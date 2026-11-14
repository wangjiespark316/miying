"""pansou-portal：觅影前置门脸（长效登录版 Sidecar）。

职责：
- 透明代理所有 /api/* 到上游 PanSou 容器（http://pansou），不动其本体；
- portal 自签长效 JWT（HS256，AUTH_USERS 校验账号密码，TOKEN_TTL_DAYS 控制有效期）；
- 搜索成功后：服务端落「历史」（按用户隔离、跨设备）、按 IP 落「事件」（用量统计）；
- 搜索时自动检测前 N 条分享链接，确认失效的不显示（结果含 verified 统计）；
- 服务端「收藏」（按用户隔离）、滑动窗口 + 单日阈值滥用检测（Bark 告警）；
- 管理员（ADMIN_USER）统计：用户用量、IP、热词、告警。

不接任何网盘账号、不做转存/播放/下载。
"""
import asyncio
import base64
import difflib
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import sqlite3
import time
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from urllib.parse import quote, urlencode, parse_qsl, urlparse
from email.utils import formatdate as rfc822_date
from xml.sax.saxutils import escape as xml_escape

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

# ---------------- 统一结构化日志（时间/级别/模块/消息，docker 直接采集）----------------
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
    force=True,
)
logger = logging.getLogger("portal")

UPSTREAM = os.environ.get("PANSOU_UPSTREAM", "http://pansou").rstrip("/")
DB_PATH = os.environ.get("DB_PATH", "/app/data/portal.db")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
APP_VERSION = os.environ.get("APP_VERSION", "0.5.2")

# SQLite 在线备份：启动一份 + 每日轮转，Connection.backup() 在 WAL 下也保证一致性
BACKUP_ENABLED = bool(int(os.environ.get("BACKUP_ENABLED", "1")))
BACKUP_DIR = os.environ.get("BACKUP_DIR", "/app/data/backups")
BACKUP_KEEP = int(os.environ.get("BACKUP_KEEP", "7"))
BACKUP_INTERVAL_SEC = int(os.environ.get("BACKUP_INTERVAL_SEC", "86400"))

# 上游熔断：连续失败 N 次打开闸门，打开期快速失败并优先 FTS 本地兜底，
# 冷却后半开试探一次，避免单 worker 被多个长超时等待叠加拖死。
CB_FAIL_THRESHOLD = int(os.environ.get("CB_FAIL_THRESHOLD", "5"))
CB_OPEN_SEC = int(os.environ.get("CB_OPEN_SEC", "30"))

# 异常链接自动重试定性：请求异常不再直接算 alive，先记 unknown，由后台每隔
# 一段时间重试，最多 N 次仍异常才放行定性，全程内存态、不引入独立服务。
VERIFY_RETRY_MAX = int(os.environ.get("VERIFY_RETRY_MAX", "3"))
VERIFY_RETRY_INTERVAL_SEC = int(
    os.environ.get("VERIFY_RETRY_INTERVAL_SEC", "180"))
VERIFY_RETRY_SCAN_SEC = int(os.environ.get("VERIFY_RETRY_SCAN_SEC", "60"))
VERIFY_RETRY_START_DELAY = int(
    os.environ.get("VERIFY_RETRY_START_DELAY", "120"))
VERIFY_RETRY_WORKERS = int(os.environ.get("VERIFY_RETRY_WORKERS", "4"))

# 长效登录
AUTH_USERS_RAW = os.environ.get("AUTH_USERS", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "")
TOKEN_TTL_DAYS = int(os.environ.get("TOKEN_TTL_DAYS", "180"))

# 安全兜底：JWT 密钥缺失或过短直接拒绝启动，避免用空密钥签发可被伪造的令牌
if not JWT_SECRET or len(JWT_SECRET) < 32:
    raise RuntimeError(
        "JWT_SECRET 未配置或长度不足 32 位，请在环境变量中设置强随机密钥"
        "（可用: python -c \"import secrets;print(secrets.token_urlsafe(48))\"）")

# Bark 滥用告警
BARK_KEY = os.environ.get("BARK_KEY", "")
BARK_DEFAULT_SERVER = os.environ.get("BARK_SERVER", "https://api.day.app")
RATE_WINDOW_SEC = int(os.environ.get("RATE_WINDOW_SEC", "600"))
RATE_WINDOW_MAX = int(os.environ.get("RATE_WINDOW_MAX", "60"))
RATE_DAY_MAX = int(os.environ.get("RATE_DAY_MAX", "500"))
ALERT_COOLDOWN_SEC = int(os.environ.get("ALERT_COOLDOWN_SEC", "900"))
EVENT_KEEP_DAYS = int(os.environ.get("EVENT_KEEP_DAYS", "30"))

# 登录防爆破：同一 IP 在窗口内失败 N 次后临时锁定
LOGIN_WINDOW_SEC = int(os.environ.get("LOGIN_WINDOW_SEC", "900"))
LOGIN_MAX_FAIL = int(os.environ.get("LOGIN_MAX_FAIL", "8"))
LOGIN_LOCK_SEC = int(os.environ.get("LOGIN_LOCK_SEC", "900"))
# 登录安全 Bark 提醒：失败达到该次数先预警一次（设 0 关闭，且应低于锁定阈值）；
# 新公网 IP 成功登录是否提醒（内网/回环自动忽略，避免 frp 回环误报）
LOGIN_WARN_FAIL = int(os.environ.get("LOGIN_WARN_FAIL", "3"))
LOGIN_IP_NOTIFY = bool(int(os.environ.get("LOGIN_IP_NOTIFY", "1")))

# 链接失效检测
# A：默认同步验证窗口由 15 提到 40，并对每个网盘类型保底各验前若干条，
# 避免百度这类被高画质夸克挤出全局前 N 窗口、后排死链无人检测。
VERIFY_N = int(os.environ.get("VERIFY_N", "40"))
VERIFY_WORKERS = int(os.environ.get("VERIFY_WORKERS", "16"))
VERIFY_CACHE_TTL = int(os.environ.get("VERIFY_CACHE_TTL", "1800"))
VERIFY_TIMEOUT = float(os.environ.get("VERIFY_TIMEOUT", "3"))
VERIFY_PER_TYPE = int(os.environ.get("VERIFY_PER_TYPE", "8"))
# B：首屏返回后，后台对该词剩余链接异步全量净化的单次安全上限（防超大词打爆）
VERIFY_BG_LIMIT = int(os.environ.get("VERIFY_BG_LIMIT", "160"))
# C：同版本标题指纹去重开关；来源健康度降权的最小样本与系数下限（样本不足不惩罚）
DEDUP_ENABLED = bool(int(os.environ.get("DEDUP_ENABLED", "1")))
SOURCE_HEALTH_MIN = int(os.environ.get("SOURCE_HEALTH_MIN", "10"))
SOURCE_HEALTH_FLOOR = float(os.environ.get("SOURCE_HEALTH_FLOOR", "0.5"))

# 查询改写 / 多路召回（方案一）：主词结果偏少或为 0 时，并发等价变体与
# 逐级退化词回源，合并后复用同一套去重/死链净化，只在供给不足时触发以控开销。
QUERY_REWRITE_ENABLED = bool(int(os.environ.get("QUERY_REWRITE_ENABLED", "1")))
# 变体上限：季等价 + 同义词（繁简/别号/中英译名）+ 逐级退化共享，强等价优先于退化
QUERY_VARIANT_MAX = int(os.environ.get("QUERY_VARIANT_MAX", "5"))
# 主词去重后唯一链接数低于该值才触发变体召回
QUERY_REWRITE_MIN_HITS = int(os.environ.get("QUERY_REWRITE_MIN_HITS", "8"))
# 变体回源整体等待硬顶（秒），超时只收已完成的部分，绝不拖垮主响应
QUERY_VARIANT_TIMEOUT = float(os.environ.get("QUERY_VARIANT_TIMEOUT", "8"))
# 同义词召回（繁简体 + 作品别号/中英译名），纯规则词典、零外部依赖，可独立关闭
SYNONYM_ENABLED = bool(int(os.environ.get("SYNONYM_ENABLED", "1")))
# 每个裸片名最多取几个别号变体，防止大别名组爆量
SYNONYM_ALIAS_MAX = int(os.environ.get("SYNONYM_ALIAS_MAX", "2"))

# 远程 MCP（Streamable HTTP，JSON-RPC 2.0）：把搜索薄封装暴露给 AI 客户端，Bearer JWT 鉴权
MCP_ENABLED = bool(int(os.environ.get("MCP_ENABLED", "1")))
MCP_RESULT_LIMIT = int(os.environ.get("MCP_RESULT_LIMIT", "30"))

# 海报图片代理：海报多为 Telegram CDN（telesco.pe，国内直连被墙），
# 由 portal 经 HTTP 代理回源后转发，浏览器只走同源，不直连图床。
# 留空=不代理；需要时经环境变量传入，例如 http://user:pass@host:port
POSTER_PROXY = os.environ.get("POSTER_PROXY", "")
POSTER_CACHE_DIR = os.environ.get("POSTER_CACHE_DIR", "/app/data/imgcache")
POSTER_CACHE_TTL = int(os.environ.get("POSTER_CACHE_TTL", str(30 * 86400)))
POSTER_MAX_BYTES = int(os.environ.get("POSTER_MAX_BYTES", str(6 * 1024 * 1024)))
# 白名单图床：仅允许这些域名，防止 /portal/img 被当作开放代理（SSRF）
POSTER_HOSTS = {
    "telesco.pe",     # Telegram CDN（含 cdn1~cdn5 等子域），走 Clash
    "doubanio.com",   # 豆瓣图（img1/img9 等子域），国内直连
    "meilinvps.com",  # 资源站豆瓣代理，国内直连
    "yzzyimg.online", # 资源站图床，国内直连
}
# 命中这些域的才走 Clash 代理（国内直连不通）
POSTER_PROXY_HOSTS = {"telesco.pe"}

# 默认过滤（只看正片）：搜索时自动排除的噪音词，前端 clean=0 可关闭
DEFAULT_EXCLUDE = ["预告", "花絮", "枪版", "抢先", "偷拍", "解说",
                   "速看", "片花", "宣传片", "抢先版", "tc版", "hdcam",
                   "cam版", "ts版", "高清预告"]
# 门户侧二次过滤补充词：上游 exclude 对衍生有声读物/短剧解说拦不住，响应前再兜一遍
EXTRA_EXCLUDE = ["有声书", "有声小说", "有声读物", "有声剧", "广播剧", "听书",
                 "评书", "电影解说", "剧集解说", "剧情解说", "几分钟看完",
                 "短剧解说", "番外解说"]


def _clean_is_noise(note: str, keyword: str) -> bool:
    """只看正片模式的标题级确定性判断（纯规则，不依赖 AI）。
    1) 命中默认/补充噪音词；2) 同名衍生短剧「<片名>之<副标题>」（如搜「庆余年」
       时的「庆余年之帝王业」），正片「庆余年2/第二季」不含「之」不会误伤。"""
    text = (note or "").lower()
    for w in DEFAULT_EXCLUDE + EXTRA_EXCLUDE:
        if w.lower() in text:
            return True
    root = (keyword or "").strip()
    if len(root) >= 2:
        pat = r"(?:^|[《【\[\s(（])" + re.escape(root) + r"\s*之[一-龥A-Za-z0-9]"
        if re.search(pat, note or ""):
            return True
    return False


def _apply_clean_filter(mbt: dict, keyword: str):
    """对 merged_by_type 就地做正片过滤，丢弃清空的网盘桶，返回 (新mbt, 剔除数)。"""
    out, dropped = {}, 0
    for drive, items in (mbt or {}).items():
        kept = [it for it in items
                if not _clean_is_noise(it.get("note", ""), keyword)]
        dropped += len(items) - len(kept)
        if kept:
            out[drive] = kept
    return out, dropped

# ---------------- 混合 FTS5 预索引 ----------------
# 平时把"全网热榜 + 高频搜索词 + 追剧词 + 固定常用词"的 PanSou 结果持久化进本地
# FTS5；搜索时先查本地（秒开），不足/miss 再回源 PanSou，回源结果异步回填。
# 全程只调 PanSou 自己的搜索接口，不直接连 Telegram，因此不需要 api_id/api_hash。
FTS_ENABLED = bool(int(os.environ.get("FTS_ENABLED", "1")))
FTS_FILL_INTERVAL = int(os.environ.get("FTS_FILL_INTERVAL", str(6 * 3600)))  # 填充周期 6h
FTS_JOB_TTL = int(os.environ.get("FTS_JOB_TTL", str(6 * 3600)))             # 单词刷新 TTL
FTS_STARTUP_DELAY = int(os.environ.get("FTS_STARTUP_DELAY", "120"))          # 启动后延迟
FTS_MIN_HITS = int(os.environ.get("FTS_MIN_HITS", "8"))                      # 本地命中足够阈值
FTS_MAX_WORDS = int(os.environ.get("FTS_MAX_WORDS", "30"))                   # 每轮最多填充词数
FTS_MAX_ARTS_PER_WORD = int(os.environ.get("FTS_MAX_ARTS_PER_WORD", "90"))   # 每词最多入库
FTS_PER_DRIVE_FLOOR = int(os.environ.get("FTS_PER_DRIVE_FLOOR", "8"))        # 每网盘保底入库条数
FTS_ART_TTL = int(os.environ.get("FTS_ART_TTL", str(45 * 86400)))            # 条目过期清理
FTS_WORD_GAP = float(os.environ.get("FTS_WORD_GAP", "1.5"))                  # 词间间隔
FTS_QUERY_LIMIT = int(os.environ.get("FTS_QUERY_LIMIT", "120"))              # 本地查询返回上限
# FTS 缓存代际：选行/配额规则变更时 +1，启动即一次性作废旧快照，令各词下次搜索
# miss 回源按新规则重建（仅清 FTS 三表，dead_links/source_health/history 不受影响）
FTS_CACHE_GEN = 2
# 热搜/热榜覆盖不到的固定常用词（热门 / 经典画质标杆，与 warm-cache 对齐）
FTS_STATIC_WORDS = ["沙丘2", "阿凡达", "让子弹飞", "奥本海默", "流浪地球2",
                    "满江红", "封神第一部", "年会不能停", "热辣滚烫",
                    "消失的她", "沙丘", "阿凡达3", "庆余年", "繁花",
                    "与凤行", "黑神话悟空", "三体", "狂飙", "我是刑警"]

# 追剧更新监控

# ---------------- 海外英文磁力源（档2：apibay + yts） ----------------
# 搜索含英文字母的词时，并行查询海盗湾官方 JSON API（直连）与 YTS API（走
# POSTER_PROXY 代理），把英文片磁力种子注入 merged_by_type.magnet。
# 纯中文词跳过（海外源命中率极低且拖慢响应）；失败静默降级不影响主流程。
MAGNET_ENABLED = bool(int(os.environ.get("MAGNET_ENABLED", "1")))
MAGNET_CACHE_TTL = int(os.environ.get("MAGNET_CACHE_TTL", "600"))
MAGNET_TIMEOUT = float(os.environ.get("MAGNET_TIMEOUT", "10"))
MAGNET_APIBAY_MAX = int(os.environ.get("MAGNET_APIBAY_MAX", "20"))
MAGNET_YTS_MAX = int(os.environ.get("MAGNET_YTS_MAX", "10"))
_MAGNET_CACHE: dict = {}
# fire-and-forget 后台任务强引用，防止任务被 GC 提前回收（asyncio 官方模式）
_background_tasks: set = set()


class CircuitBreaker:
    """搜索上游熔断器。单 worker 事件循环内运行，普通属性即可，无需加锁。

    closed 正常放行；连续失败达阈值转 open，open 期快速失败（不再等待长超时）；
    冷却时间到转 half_open 放行一次试探，成功则闭合、失败则重新打开。"""

    def __init__(self):
        self.state = "closed"
        self.fails = 0
        self.opened_at = 0.0
        self.trips = 0

    def allow(self) -> bool:
        if self.state == "closed":
            return True
        if self.state == "open":
            if time.time() - self.opened_at >= CB_OPEN_SEC:
                self.state = "half_open"
                logger.info("upstream circuit half-open, probing once")
                return True
            return False
        return True  # half_open：只放行这一次试探

    def record_success(self):
        if self.state != "closed":
            logger.info("upstream recovered, circuit %s -> closed", self.state)
        self.state, self.fails = "closed", 0

    def record_failure(self):
        self.fails += 1
        if self.state == "half_open" or self.fails >= CB_FAIL_THRESHOLD:
            if self.state != "open":
                self.trips += 1
                logger.warning(
                    "upstream circuit open (consecutive fails=%s)", self.fails)
            self.state = "open"
            self.opened_at = time.time()

    def snapshot(self) -> dict:
        return {
            "state": self.state, "fails": self.fails, "trips": self.trips,
            "threshold": CB_FAIL_THRESHOLD, "open_sec": CB_OPEN_SEC,
            "open_for_sec": round(time.time() - self.opened_at, 1)
            if self.state == "open" else 0,
        }


class Metrics:
    """进程内可观测计数（重启清零，持久化口径仍以 sqlite 为准）。"""

    def __init__(self):
        self.start_ts = time.time()
        self.search_total = 0
        self.search_local = 0
        self.search_upstream = 0
        self.search_fallback = 0
        self.variant_recalled = 0
        self.upstream_calls = 0
        self.upstream_ok = 0
        self.upstream_fail = 0
        self.upstream_short = 0       # 熔断打开期被快速拦截、未真正发请求的次数
        self.upstream_lat = deque(maxlen=300)
        self.verify_checked = 0
        self.verify_alive = 0
        self.verify_dead = 0
        self.verify_unknown = 0
        self.retry_resolved = 0
        self.retry_giveup = 0
        # 第四批：登录安全事件与 MCP 调用计数（进程期累计）
        self.login_warn = 0
        self.login_lock = 0
        self.login_new_ip = 0
        self.mcp_calls = 0
        self.mcp_errors = 0
        self.drive_checked = {}          # 网盘类型 -> [新检测数, 死链数]
        self.jobs = {}                   # 后台任务名 -> 最近心跳

    def record_latency(self, ms: float):
        self.upstream_lat.append(max(0.0, ms))

    def latency(self) -> dict:
        xs = sorted(self.upstream_lat)
        if not xs:
            return {"count": 0}
        pick = lambda p: xs[min(len(xs) - 1, int(len(xs) * p))]
        return {"count": len(xs),
                "avg_ms": round(sum(xs) / len(xs)),
                "p50_ms": round(pick(0.5)),
                "p95_ms": round(pick(0.95)),
                "last_ms": round(xs[-1])}

    def record_verify(self, drive: str, status: str):
        self.verify_checked += 1
        bucket = self.drive_checked.setdefault(drive or "unknown", [0, 0])
        bucket[0] += 1
        if status == "dead":
            self.verify_dead += 1
            bucket[1] += 1
        elif status == "unknown":
            self.verify_unknown += 1
        else:
            self.verify_alive += 1

    def job_beat(self, name: str, ok: bool = True, info: str = ""):
        self.jobs[name] = {"last": time.time(), "ok": bool(ok), "info": info}


cb = CircuitBreaker()
metrics = Metrics()
# 异常待重试链接：url -> [已失败次数, 下次可重试时间戳]，纯内存态
_retry_pending: dict = {}
_retry_inflight: set = set()


def _magnet_item(name: str, info_hash: str, source: str,
                 seeds: int = 0, size: str = "") -> dict:
    note = name
    if size:
        note = "%s %s" % (note, size)
    if seeds:
        note = "%s [%d做种]" % (note, seeds)
    return {
        "url": "magnet:?xt=urn:btih:%s&dn=%s" % (info_hash, quote(name)),
        "password": "",
        "note": note,
        "source": "plugin:" + source,
        "datetime": "",
        "size": size or "",
    }


def _human_size(num) -> str:
    """字节数转人类可读体积；无法解析返回空串。"""
    try:
        n = float(num)
    except (TypeError, ValueError):
        return ""
    if n <= 0:
        return ""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return ("%g" % n) + ("" if unit == "B" else " " + unit)
        n /= 1024
    return ""


async def _fetch_apibay(kw: str, to: httpx.Timeout) -> list:
    url = "https://apibay.org/q.php?q=" + quote(kw)
    kwarg = dict(timeout=to, headers={"User-Agent": UA})
    if POSTER_PROXY:
        kwarg["proxy"] = POSTER_PROXY
    async with httpx.AsyncClient(**kwarg) as c:
        resp = await c.get(url)
        rows = resp.json()
    out = []
    for r in rows or []:
        if str(r.get("id") or "0") == "0":
            continue  # apibay 的 "No results returned" 占位条目
        ih = (r.get("info_hash") or "").strip()
        name = (r.get("name") or "").strip()
        if not ih or not name or len(ih) != 40 or ih == "0" * 40:
            continue
        try:
            seeds = int(r.get("seeders") or 0)
        except Exception:
            seeds = 0
        out.append((seeds, _magnet_item(
            name, ih, "apibay", seeds, _human_size(r.get("size")))))
    out.sort(key=lambda x: -x[0])
    return [it for _, it in out[:MAGNET_APIBAY_MAX]]


async def _fetch_yts(kw: str, to: httpx.Timeout) -> list:
    url = "https://yts.rs/api/v2/list_movies.json?query_term=" + quote(kw)
    kwarg = dict(timeout=to, headers={"User-Agent": UA})
    if POSTER_PROXY:
        kwarg["proxy"] = POSTER_PROXY
    async with httpx.AsyncClient(**kwarg) as c:
        resp = await c.get(url)
        data = resp.json()
    out = []
    for m in (data.get("data") or {}).get("movies") or []:
        title = (m.get("title") or "").strip()
        year = m.get("year") or ""
        for t in m.get("torrents") or []:
            h = (t.get("hash") or "").strip()
            if not h:
                continue
            q = (t.get("quality") or "").strip()
            typ = (t.get("type") or "").strip()
            size = (t.get("size") or "").strip()
            try:
                seeds = int(t.get("seeds") or 0)
            except Exception:
                seeds = 0
            name = title
            if year:
                name = "%s (%s)" % (name, year)
            tags = " / ".join(x for x in (q, typ, size) if x)
            if tags:
                name = "%s [%s]" % (name, tags)
            out.append((seeds, _magnet_item(name, h, "yts", seeds, size)))
    out.sort(key=lambda x: -x[0])
    return [it for _, it in out[:MAGNET_YTS_MAX]]


async def _fetch_magnets(kw: str, soft: bool = False) -> dict:
    """并发查 apibay(直连)+yts(代理)，注入 magnet。失败静默。
    soft=True 用于本地命中(SWR)路径：更短超时，避免拖慢秒开响应。"""
    if not MAGNET_ENABLED or not re.search(r"[A-Za-z]", kw):
        return {}
    key = kw.strip().lower()
    now = time.time()
    if key in _MAGNET_CACHE and _MAGNET_CACHE[key][0] > now:
        return _MAGNET_CACHE[key][1]
    if soft:
        ato = httpx.Timeout(2.5, connect=2.0)
        yto = httpx.Timeout(3.0, connect=2.5)
        limit = 4.0
    else:
        ato = httpx.Timeout(6.0, connect=4.0)
        yto = httpx.Timeout(8.0, connect=5.0)
        limit = MAGNET_TIMEOUT
    result = {}
    try:
        r1, r2 = await asyncio.wait_for(
            asyncio.gather(_fetch_apibay(kw, ato), _fetch_yts(kw, yto),
                           return_exceptions=True), timeout=limit)
        items = []
        for r in (r1, r2):
            if isinstance(r, Exception):
                logger.warning("magnet fetch error: %s", r)
            else:
                items.extend(r)
        if items:
            result = {"magnet": items}
    except Exception as e:
        logger.warning("magnet error: %s", e)
    _MAGNET_CACHE[key] = (time.time() + MAGNET_CACHE_TTL, result)
    return result

# 追剧更新监控：后台定时检索订阅词，发现比基线新的资源即推送
WATCH_INTERVAL_SEC = int(os.environ.get("WATCH_INTERVAL_SEC", "7200"))
WATCH_STARTUP_DELAY = int(os.environ.get("WATCH_STARTUP_DELAY", "90"))
WATCH_PUSH_MAX = int(os.environ.get("WATCH_PUSH_MAX", "5"))
# 追剧三态：want 想看 / watching 在看（参与更新监控与 Bark 推送）/ watched 看过
WATCH_STATUSES = ("want", "watching", "watched")
# RSS 订阅：内存短缓存防阅读器高频回源、单 feed 条目上限、无 kw 时聚合在看关键词上限
RSS_CACHE_SEC = int(os.environ.get("RSS_CACHE_SEC", "60"))
RSS_MAX_ITEMS = int(os.environ.get("RSS_MAX_ITEMS", "30"))
RSS_FEED_KEYWORDS_MAX = int(os.environ.get("RSS_FEED_KEYWORDS_MAX", "5"))

# 密码哈希（PBKDF2-HMAC-SHA256，每用户随机盐）
PBKDF2_ITER = int(os.environ.get("PBKDF2_ITER", "600000"))
PASSWORD_MIN = int(os.environ.get("PASSWORD_MIN", "6"))

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
}

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# 明确失效的页面标志（网络异常不算，避免误杀）
DEAD_MARKERS = [
    "链接不存在", "分享文件已被删除", "分享的文件已经被取消", "分享文件已被取消",
    "分享已失效", "此链接不存在", "页面不存在", "404", "not found",
]

QUALITY_SCORE = [
    ("remux", 120), ("原盘", 120), ("蓝光原盘", 120),
    ("杜比视界", 70), ("dolby vision", 70), ("杜比全景声", 40),
    ("4k", 60), ("uhd", 60), ("2160p", 60),
    ("hdr", 45), ("hdr10", 45),
    ("蓝光", 30), ("bluray", 30),
    ("1080p", 15), ("高码", 15), ("国英", 12),
    ("双音", 8), ("特效字幕", 12), ("双语", 6),
]

app = FastAPI(title="pansou-portal")

_last_alert = {}          # ip -> 上次告警时间
_verify_cache = {}        # url -> (status, ts)，status: "alive" / "dead"
_login_fails = {}         # ip -> [fail_ts, ...]
_login_locks = {}         # ip -> lock_until_ts
_security_alert_ts = {}   # (ip, kind) -> 上次安全提醒时间，冷却去抖
_rss_cache: dict = {}     # (token, kw) -> (缓存时间戳, RSS XML)，短缓存防阅读器高频回源
# A+B+C：持久化死链与来源健康度的内存视图（启动从 sqlite 预热，读路径 O(1)）
_dead_urls: set = set()           # 已确认失效 URL，任意响应路径返回前统一过滤
_verify_inflight: set = set()     # 后台深度验证进行中的 URL，避免跨请求重复打
_src_health: dict = {}            # source -> [alive, dead] 累计计数，用于温和降权


# ---------------- 安全响应头 ----------------
@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("X-XSS-Protection", "0")
    # HSTS：强制 HTTPS 一年（仅在已通过 HTTPS 访问时生效，部署确认稳定后可保留）
    resp.headers.setdefault(
        "Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    # CSP：本前端为单文件、JS 全部内联（含内联事件），故 script-src 必须放行
    # 'unsafe-inline'，否则整站脚本会被拦截；style-src 同理。外连仅放行字体与图片。
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline' https://miaoda.feishu.cn; "
        "font-src 'self' https://sf3-scmcdn-cn.feishucdn.com; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
    return resp


def parse_users():
    out = {}
    for chunk in AUTH_USERS_RAW.split(","):
        chunk = chunk.strip()
        if not chunk or ":" not in chunk:
            continue
        u, p = chunk.split(":", 1)
        out[u.strip()] = p.strip()
    return out


ENV_USERS = parse_users()


# ---------------- 密码哈希（PBKDF2-HMAC-SHA256） ----------------
def hash_password(pwd: str, salt: str = None):
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pwd.encode("utf-8"),
                             salt.encode("utf-8"), PBKDF2_ITER)
    return salt, dk.hex()


def verify_password(pwd: str, salt: str, expected: str) -> bool:
    _, dk = hash_password(pwd, salt)
    return hmac.compare_digest(dk, expected)


# ---------------- IP 网段归并（须前置于本模块顶层 init_db() 调用，供建表迁移回填） ----------------
def _ip_net_key(ip: str) -> str:
    """动态 IP 归并键：IPv4 取 /24、IPv6 取 /64；非法地址回退精确 IP（保守不并）。
    同一最小路由广播块内的地址漂移必属同局向（同城同运营商），以此作为"新设备"
    判定口径可消除家宽动态 IP 误报，且纯标准库计算、不引入 GeoIP 或外部查询。"""
    if not ip:
        return ""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    prefix = "/24" if isinstance(addr, ipaddress.IPv4Address) else "/64"
    try:
        return str(ipaddress.ip_network(f"{ip}{prefix}", strict=False))
    except ValueError:
        return ip


# ---------------- 数据库 ----------------
def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS history(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL, keyword TEXT NOT NULL,
            total INTEGER DEFAULT 0, counts TEXT, src TEXT, ts TEXT NOT NULL)""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_hist_user ON history(username, ts DESC)")
        db.execute("""CREATE TABLE IF NOT EXISTS favorites(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL, note TEXT, drive TEXT, url TEXT,
            password TEXT, source TEXT, ts TEXT NOT NULL,
            UNIQUE(username, url))""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_fav_user ON favorites(username, ts DESC)")
        db.execute("""CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL, keyword TEXT NOT NULL,
            total INTEGER DEFAULT 0, counts TEXT, src TEXT, ts TEXT NOT NULL)""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_ev_ip ON events(ip, ts DESC)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_ev_ts ON events(ts)")
        db.execute("""CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL, reason TEXT, detail TEXT, ts TEXT NOT NULL)""")
        # 登录来源 IP 登记：按网段归并（IPv4 /24、IPv6 /64）判定新设备，
        # 动态 IP 在同一网段内漂移不重复报；具体 IP 仍逐行登记便于审计
        db.execute("""CREATE TABLE IF NOT EXISTS login_seen_ip(
            ip TEXT PRIMARY KEY, net_key TEXT NOT NULL DEFAULT '',
            first_ts TEXT NOT NULL,
            last_ts TEXT NOT NULL, hits INTEGER DEFAULT 1)""")
        # 老库补 net_key 列并回填存量网段，避免升级后把已见网段误判为新设备
        lip_cols = {r[1] for r in db.execute("PRAGMA table_info(login_seen_ip)")}
        if "net_key" not in lip_cols:
            db.execute(
                "ALTER TABLE login_seen_ip ADD COLUMN net_key TEXT NOT NULL DEFAULT ''")
        for r in db.execute(
                "SELECT ip FROM login_seen_ip WHERE net_key=''").fetchall():
            db.execute("UPDATE login_seen_ip SET net_key=? WHERE ip=?",
                       (_ip_net_key(r[0]), r[0]))
        # RSS 订阅令牌：每用户一个不可猜测 token，阅读器经 query 令牌鉴权（无法带 Bearer）
        db.execute("""CREATE TABLE IF NOT EXISTS rss_feed(
            username TEXT PRIMARY KEY, token TEXT UNIQUE NOT NULL,
            created_ts TEXT NOT NULL)""")
        # 用户级 Bark：未配置时回退站长默认 BARK_KEY；server 可指向自建 Bark 服务
        db.execute("""CREATE TABLE IF NOT EXISTS user_bark(
            username TEXT PRIMARY KEY,
            server TEXT NOT NULL DEFAULT '',
            bark_key TEXT NOT NULL DEFAULT '',
            updated_ts TEXT NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            salt TEXT NOT NULL, pwd_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_ts TEXT NOT NULL, pw_ts TEXT)""")
        db.execute("""CREATE TABLE IF NOT EXISTS watch(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL, keyword TEXT NOT NULL,
            last_ts TEXT DEFAULT '', last_total INTEGER DEFAULT 0,
            created_ts TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'watching',
            UNIQUE(username, keyword))""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_watch_user ON watch(username)")
        # 追剧三态平滑升级：旧库无 status 列时幂等补列，存量订阅默认归入"在看"
        watch_cols = {r[1] for r in db.execute("PRAGMA table_info(watch)")}
        if "status" not in watch_cols:
            db.execute(
                "ALTER TABLE watch ADD COLUMN status TEXT NOT NULL "
                "DEFAULT 'watching'")
        db.execute("""CREATE TABLE IF NOT EXISTS poster_fallback(
            tkey TEXT PRIMARY KEY,
            qtitle TEXT DEFAULT '',
            cover TEXT DEFAULT '',
            title TEXT DEFAULT '',
            year TEXT DEFAULT '',
            rating TEXT DEFAULT '',
            miss INTEGER DEFAULT 0,
            ts REAL NOT NULL)""")
        # 老库补 rating 列（第六批前缓存表不存评分，导致 meta 行评分恒空）
        fb_cols = {r[1] for r in db.execute("PRAGMA table_info(poster_fallback)")}
        if fb_cols and "rating" not in fb_cols:
            db.execute("ALTER TABLE poster_fallback ADD COLUMN rating TEXT DEFAULT ''")
            # 旧命中缓存缺评分：置过期，下次请求重拉并回写评分（封面可重建）
            db.execute("UPDATE poster_fallback SET ts=0 WHERE cover IS NOT NULL AND cover<>''")
        # ---- 混合 FTS5 预索引 ----
        # 资源条目主表：存原始 item JSON（raw），返回时直接还原，保证前端渲染一致
        db.execute("""CREATE TABLE IF NOT EXISTS idx_arts(
            url TEXT PRIMARY KEY,
            drive TEXT DEFAULT '',
            note TEXT DEFAULT '',
            datetime TEXT DEFAULT '',
            score INTEGER DEFAULT 0,
            raw TEXT DEFAULT '',
            kws TEXT DEFAULT '',
            first_seen REAL,
            last_seen REAL)""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_arts_drive ON idx_arts(drive)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_arts_seen ON idx_arts(last_seen)")
        # FTS5 全文表：trigram 分词（3 字符滑动窗口，适合中文子串/混排），仅索引标题
        db.execute("""CREATE VIRTUAL TABLE IF NOT EXISTS idx_fts USING fts5(
            note, url UNINDEXED, tokenize='trigram')""")
        # 每关键词的填充记录（TTL 判断 / 统计）
        db.execute("""CREATE TABLE IF NOT EXISTS idx_jobs(
            kw TEXT PRIMARY KEY,
            n INTEGER DEFAULT 0,
            last_run REAL,
            src TEXT DEFAULT '')""")
        # 通用键值元信息（如 FTS 缓存代际），承载一次性数据迁移闸门
        db.execute("""CREATE TABLE IF NOT EXISTS app_meta(
            key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '')""")
        # ---- A+B+C：死链持久化 + 来源健康度（平滑升级，旧库自动补建）----
        db.execute("""CREATE TABLE IF NOT EXISTS dead_links(
            url TEXT PRIMARY KEY,
            title TEXT DEFAULT '',
            ts REAL NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS source_health(
            source TEXT PRIMARY KEY,
            alive INTEGER NOT NULL DEFAULT 0,
            dead INTEGER NOT NULL DEFAULT 0,
            updated REAL)""")
        db.execute("PRAGMA journal_mode=WAL")
        # 预热内存视图：死链集合与来源计数，重启不丢、跨关键词复用
        for r in db.execute("SELECT url FROM dead_links"):
            _dead_urls.add(r[0])
        for r in db.execute("SELECT source, alive, dead FROM source_health"):
            _src_health[r[0]] = [int(r[1] or 0), int(r[2] or 0)]
        # FTS 缓存代际闸门：选行/配额规则升级后一次性作废旧截断快照，令每个词
        # 下次搜索本地 miss 并按新规则回源重建；仅清 FTS 三表，死链库/健康度/历史
        # 等保留；幂等，已处于当前代际则不再清空（重启不重复）。
        grow = db.execute(
            "SELECT value FROM app_meta WHERE key='fts_cache_gen'").fetchone()
        try:
            cur_gen = int(grow[0]) if grow and grow[0] not in (None, "") else 0
        except (TypeError, ValueError):
            cur_gen = 0
        if cur_gen < FTS_CACHE_GEN:
            dropped = db.execute("SELECT COUNT(*) FROM idx_arts").fetchone()[0]
            db.execute("DELETE FROM idx_fts")
            db.execute("DELETE FROM idx_arts")
            db.execute("DELETE FROM idx_jobs")
            db.execute(
                "INSERT INTO app_meta(key,value) VALUES('fts_cache_gen',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(FTS_CACHE_GEN),))
            logger.info(
                "fts cache gen %s->%s: dropped %s cached arts; "
                "rebuild on next search", cur_gen, FTS_CACHE_GEN, dropped)
    try:
        os.chmod(DB_PATH, 0o600)
    except OSError:
        pass


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def backup_database(tag: str = "scheduled"):
    """在线一致性备份主库并按份数轮转；同步 IO，仅在线程池内调用。"""
    if not BACKUP_ENABLED:
        return None
    if not os.path.exists(DB_PATH):
        logger.warning("backup skipped, db not found: %s", DB_PATH)
        return None
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        stamp = time.strftime("%Y%m%d%H%M%S")
        dest = os.path.join(BACKUP_DIR, "portal.db.%s-%s" % (tag, stamp))
        # sqlite3 在线热备份：读取 WAL 最新一致视图，不阻塞正在进行的写入
        with sqlite3.connect(DB_PATH) as src, sqlite3.connect(dest) as dst:
            src.backup(dst)
        os.chmod(dest, 0o600)
        snaps = [os.path.join(BACKUP_DIR, n) for n in os.listdir(BACKUP_DIR)
                 if n.startswith("portal.db.")]
        snaps.sort(key=os.path.getmtime, reverse=True)
        for old in snaps[BACKUP_KEEP:]:
            os.remove(old)
        logger.info("db backup ok tag=%s file=%s keep=%d", tag, dest, BACKUP_KEEP)
        return dest
    except Exception:
        logger.exception("db backup failed tag=%s", tag)
        return None


async def backup_loop():
    """启动先备份一份，之后每隔 BACKUP_INTERVAL_SEC 备份；失败不影响主服务。"""
    loop = asyncio.get_event_loop()
    dest = await loop.run_in_executor(None, backup_database, "startup")
    metrics.job_beat("backup", ok=bool(dest), info="startup")
    while True:
        await asyncio.sleep(BACKUP_INTERVAL_SEC)
        try:
            dest = await loop.run_in_executor(None, backup_database, "daily")
            metrics.job_beat("backup", ok=bool(dest), info="daily")
        except Exception:
            logger.exception("backup loop error")
            metrics.job_beat("backup", ok=False, info="daily error")


def seed_users():
    """首次启动从 AUTH_USERS 导入；并保证 ADMIN_USER 始终为启用管理员（锁死自救）。"""
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    with db() as conn:
        cnt = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
        if cnt == 0:
            for u, p in ENV_USERS.items():
                salt, h = hash_password(p)
                role = "admin" if u == ADMIN_USER else "user"
                conn.execute(
                    """INSERT INTO users(username,salt,pwd_hash,role,enabled,
                         created_ts,pw_ts) VALUES(?,?,?,?,1,?,?)""",
                    (u, salt, h, role, stamp, stamp))
        # 环境变量兜底：保证 ADMIN_USER 存在、启用且为管理员（不覆盖其密码）
        row = conn.execute("SELECT id FROM users WHERE username=?",
                           (ADMIN_USER,)).fetchone()
        if row is None:
            # 仅在 ADMIN_USER 未列入 AUTH_USERS 时兜底；务必在 AUTH_USERS 中显式配置强密码
            p = ENV_USERS.get(ADMIN_USER, "admin-change-me")
            salt, h = hash_password(p)
            conn.execute(
                """INSERT INTO users(username,salt,pwd_hash,role,enabled,
                     created_ts,pw_ts) VALUES(?,?,?,'admin',1,?,?)""",
                (ADMIN_USER, salt, h, stamp, stamp))
        else:
            conn.execute(
                "UPDATE users SET role='admin', enabled=1 WHERE username=?",
                (ADMIN_USER,))


init_db()
seed_users()


# ---------------- JWT（HS256，自签长效） ----------------
def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_token(username: str) -> str:
    h = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"},
                           separators=(",", ":")).encode())
    now = int(time.time())
    payload = {"username": username, "iat": now,
               "exp": now + TOKEN_TTL_DAYS * 86400}
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64url(hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(),
                           hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def verify_token(token: str):
    try:
        h, p, sig = token.split(".")
        expected = _b64url(hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(),
                                    hashlib.sha256).digest())
        if not hmac.compare_digest(expected, sig):
            return None
        payload = json.loads(_b64url_decode(p))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        if not payload.get("username"):
            return None
        return payload
    except Exception:
        return None


class _AuthError(Exception):
    def __init__(self, status, body):
        self.status = status
        self.body = body


@app.exception_handler(_AuthError)
async def auth_handler(request: Request, exc: _AuthError):
    return JSONResponse(exc.body, status_code=exc.status)


async def _json_body(request: Request) -> dict:
    """安全解析 JSON body；空 body、非法 JSON、顶层非对象统一返回 400，而非抛 500。"""
    try:
        data = await request.json()
    except Exception:
        raise _AuthError(400, {"detail": "请求体不是合法的 JSON"})
    if not isinstance(data, dict):
        raise _AuthError(400, {"detail": "请求体格式错误"})
    return data


def current_user(request: Request):
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return None
    payload = verify_token(auth[7:].strip())
    return payload.get("username") if payload else None


def require_user(request: Request) -> str:
    u = current_user(request)
    if not u:
        raise _AuthError(401, {"detail": "未登录或登录已过期"})
    return u


def get_role(username: str) -> str:
    with db() as conn:
        row = conn.execute("SELECT role, enabled FROM users WHERE username=?",
                           (username,)).fetchone()
    if not row or row["enabled"] != 1:
        raise _AuthError(401, {"detail": "未登录或登录已过期"})
    return row["role"]


def require_admin(request: Request) -> str:
    u = require_user(request)
    if get_role(u) != "admin":
        raise _AuthError(403, {"detail": "无管理员权限"})
    return u


# ---------------- 工具 ----------------
def client_ip(request: Request) -> str:
    xri = request.headers.get("x-real-ip", "").strip()
    if xri:
        return xri
    xff = request.headers.get("x-forwarded-for", "").strip()
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


# 容器以 UTC 运行，库内 TEXT 时间均为无时区标记的 UTC 墙上时间。
# 对外输出统一换算为北京时区并显式带偏移，前端可直接 new Date() 正确本地化。
BJ_TZ = timezone(timedelta(hours=8))


def _iso_bj(ts) -> str:
    """naive(按 UTC 解释) 或带偏移的时间字符串，统一转 +08:00 ISO8601；空值/异常安全。"""
    if ts is None:
        return ""
    s = str(ts).strip()
    if not s:
        return ""
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00").replace(" ", "T"))
    except Exception:
        return s
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(BJ_TZ).isoformat(timespec="seconds")


def _epoch_bj(epoch) -> str:
    """Unix 秒（可为小数）转 +08:00 ISO8601；空值/异常安全。"""
    if epoch is None:
        return ""
    try:
        return datetime.fromtimestamp(float(epoch), tz=BJ_TZ).isoformat(
            timespec="seconds")
    except Exception:
        return str(epoch)


def quality_score(item: dict) -> int:
    text = ((item.get("note") or "") + " " + (item.get("url") or "")).lower()
    return sum(w for t, w in QUALITY_SCORE if t in text)


# ---------------- C：同版本标题指纹去重 + 来源健康度降权 ----------------
# 画质/版本档位 token：指纹里单独成档，保证同名的 4K 与 1080p 等不同版本不被折叠
_FP_QUALITY_TOKENS = (
    "remux", "蓝光原盘", "原盘", "杜比视界", "dolby vision", "杜比全景声",
    "4k", "uhd", "2160p", "hdr10", "hdr", "蓝光", "bluray", "1080p",
    "高码", "60fps", "国英", "双音", "特效字幕", "双语",
)
# 连载期号/更新进度/年份日期等会变、但指向同一作品同一版本的噪音片段
_FP_NOISE_PATTERNS = (
    r"更新至[^0-9]{0,6}[0-9.]+\s*期?",
    r"更至[^0-9]{0,6}[0-9.]+\s*期?",
    r"更新[^0-9]{0,6}[0-9.]+\s*期?",
    r"更\s*[0-9.]+\s*期?",
    r"第\s*[0-9.]+\s*期", r"[0-9.]+\s*期",
    r"\d{1,2}\s*月\s*\d{1,2}\s*[日号]",
    r"(?:19|20)\d{2}\s*年?", r"(?:19|20)\d{2}",
)


def _title_fingerprint(note: str, drive: str, url: str = ""):
    """归一化出 (网盘类型, 画质档位集合, 核心片名) 指纹。
    剥离 emoji/标签/括号标点、连载期号与年份；核心片名为空时退回唯一键，绝不合并。"""
    s = (note or "").lower()
    tokens = tuple(sorted({t for t in _FP_QUALITY_TOKENS if t in s}))
    for t in tokens:
        s = s.replace(t, " ")
    for pat in _FP_NOISE_PATTERNS:
        s = re.sub(pat, " ", s)
    core = re.sub(r"[^0-9a-z一-鿿]+", "", s)
    if not core:                      # 信息不足，保守不折叠
        core = "uniq:" + (url or "")
    return drive or "", tokens, core


def _dedup_mbt(mbt: dict):
    """同网盘、同画质档位、同核心片名的雷同链接只留画质分最高的一条；
    magnet 为不同 info_hash 的独立资源，不做标题去重。返回 (新mbt, 删除条数)。"""
    if not DEDUP_ENABLED:
        return mbt, 0
    out, dropped = {}, 0
    for drive, items in (mbt or {}).items():
        if drive == "magnet":
            out[drive] = list(items)
            continue
        kept, idx_of, seen_url = [], {}, set()
        for it in items:
            u = (it.get("url") or "").strip()
            if not u:
                continue
            if u in seen_url:
                dropped += 1
                continue
            fp = _title_fingerprint(it.get("note") or "", drive, u)
            if fp in idx_of:
                dropped += 1
                k = idx_of[fp]
                if quality_score(it) > quality_score(kept[k]):
                    kept[k] = it
                continue
            seen_url.add(u)
            idx_of[fp] = len(kept)
            kept.append(it)
        if kept:
            out[drive] = kept
    return out, dropped


def _source_factor(source: str) -> float:
    """来源滚动失效率 -> 温和排序系数。样本不足不惩罚；最差也只降到下限，不隐藏。"""
    rec = _src_health.get((source or "").strip())
    if not rec:
        return 1.0
    alive, dead = int(rec[0]), int(rec[1])
    n = alive + dead
    if n < SOURCE_HEALTH_MIN:
        return 1.0
    rate = dead / n if n else 0.0
    return max(SOURCE_HEALTH_FLOOR, 1.0 - rate * (1.0 - SOURCE_HEALTH_FLOOR))


def effective_score(item: dict) -> float:
    return quality_score(item) * _source_factor(item.get("source") or "")


def _select_check_urls(mbt: dict, ranked: list) -> list:
    """A：ranked 为全局有效分降序的 url 列表。先给每个网盘类型保底取前
    VERIFY_PER_TYPE 条，再按全局顺序补足到 VERIFY_N；magnet 不做 HTTP 验证。"""
    drive_of, per_type = {}, {}
    for drive, items in (mbt or {}).items():
        for it in items:
            u = (it.get("url") or "").strip()
            if u:
                drive_of.setdefault(u, drive)
    http_ranked = [u for u in ranked
                   if u in drive_of and not u.startswith("magnet:")]
    for u in http_ranked:
        per_type.setdefault(drive_of[u], []).append(u)
    chosen, picked = [], set()
    for drive in (mbt or {}).keys():
        for u in per_type.get(drive, [])[:VERIFY_PER_TYPE]:
            if u not in picked:
                picked.add(u)
                chosen.append(u)
    for u in http_ranked:
        if len(chosen) >= VERIFY_N:
            break
        if u not in picked:
            picked.add(u)
            chosen.append(u)
    return chosen[:VERIFY_N]


def _filter_dead_mbt(mbt: dict):
    """任意响应路径返回前，用持久化死链集合统一过滤。返回 (新mbt, 剔除条数)。"""
    if not _dead_urls:
        return mbt, 0
    out, removed = {}, 0
    for drive, items in (mbt or {}).items():
        kept = [it for it in items
                if (it.get("url") or "").strip() not in _dead_urls]
        removed += len(items) - len(kept)
        if kept:
            out[drive] = kept
    return out, removed


def _url_source_map(mbt: dict) -> dict:
    mp = {}
    for items in (mbt or {}).values():
        for it in items:
            u = (it.get("url") or "").strip()
            if u:
                mp.setdefault(u, (it.get("source") or "unknown").strip()
                              or "unknown")
    return mp


def _record_verdicts(verdict: dict, url_source: dict):
    """验证结果落 dead_links/source_health，同步内存死链、来源计数与 FTS 索引。"""
    if not verdict:
        return
    now = time.time()
    dead_now = [u for u, st in verdict.items() if st == "dead"]
    # unknown 为待重试中间态，不落库、不计来源健康度，避免污染统计与误复活
    alive_now = [u for u, st in verdict.items() if st == "alive"]
    try:
        with db() as conn:
            for u in dead_now:
                conn.execute(
                    "INSERT INTO dead_links(url,title,ts) VALUES(?,?,?) "
                    "ON CONFLICT(url) DO UPDATE SET ts=excluded.ts",
                    (u, "", now))
            if alive_now:
                conn.executemany("DELETE FROM dead_links WHERE url=?",
                                 [(u,) for u in alive_now])
            for u in dead_now:
                src = url_source.get(u, "unknown")
                conn.execute(
                    "INSERT INTO source_health(source,dead,updated) VALUES(?,1,?) "
                    "ON CONFLICT(source) DO UPDATE SET dead=dead+1,"
                    "updated=excluded.updated", (src, now))
            for u in alive_now:
                src = url_source.get(u, "unknown")
                conn.execute(
                    "INSERT INTO source_health(source,alive,updated) VALUES(?,1,?) "
                    "ON CONFLICT(source) DO UPDATE SET alive=alive+1,"
                    "updated=excluded.updated", (src, now))
        for u in dead_now:
            _dead_urls.add(u)
            _src_health.setdefault(url_source.get(u, "unknown"), [0, 0])[1] += 1
        for u in alive_now:
            _dead_urls.discard(u)
            _src_health.setdefault(url_source.get(u, "unknown"), [0, 0])[0] += 1
        for u in dead_now:                     # FTS 移除放在事务连接外，避免嵌套连接
            try:
                _fts_remove_url(u)
            except Exception:
                pass
    except Exception as e:
        logger.warning("record verdicts error: %s", e)


# ---------------- 链接失效检测 ----------------
async def _check_one(url: str, client: httpx.AsyncClient):
    try:
        r = await client.get(url, headers={"User-Agent": UA},
                             follow_redirects=True)
        head = r.text[:6000]
        m = re.search(r"<title>(.*?)</title>", head, re.S | re.I)
        title = re.sub(r"\s+", " ", m.group(1)).strip() if m else ""
        dead = any(k in title.lower() for k in
                   [x.lower() for x in DEAD_MARKERS])
        return url, ("dead" if dead else "alive")
    except Exception:
        # 网络异常先记 unknown：本次照常展示（不误杀好链接），但不写活结论，
        # 交给后台 retry_loop 隔几分钟重试，连续多次异常才放行定性。
        return url, "unknown"


async def verify_urls(urls, client: httpx.AsyncClient):
    now = time.time()
    verdict = {}
    todo = []
    for u in urls:
        if u in _verify_cache and now - _verify_cache[u][1] < VERIFY_CACHE_TTL:
            verdict[u] = _verify_cache[u][0]
        else:
            todo.append(u)
    if todo:
        sem = asyncio.Semaphore(VERIFY_WORKERS)

        async def guarded(u):
            async with sem:
                return await _check_one(u, client)

        for u, status in await asyncio.gather(*[guarded(x) for x in todo]):
            verdict[u] = status
            if status == "unknown":
                # 不进长 TTL 缓存，登记后台重试（已在队列则保留既有失败计数）
                if u not in _retry_pending:
                    _retry_pending[u] = [1, now + VERIFY_RETRY_INTERVAL_SEC]
            else:
                _verify_cache[u] = (status, now)
    return verdict


def _pending(urls: list) -> list:
    """筛出验证缓存已过期/不存在、本次需要真正发起请求的 URL。
    健康度只对新检测结果计数，避免缓存命中被反复累加。"""
    now = time.time()
    return [u for u in urls
            if not (u in _verify_cache and now - _verify_cache[u][1] < VERIFY_CACHE_TTL)]


async def _bg_deep_verify(keyword: str, mbt: dict):
    """B：首屏返回后，后台把该词剩余链接全量验证（受 VERIFY_BG_LIMIT 安全阀约束、
    跨请求 in-flight 去重、信号量限流复用 VERIFY_WORKERS）。死链落库并移出 FTS，
    下次刷新/搜索即消失；alive 则允许复活。全程异常静默，绝不影响响应链路。"""
    try:
        now = time.time()
        todo, seen = [], set()
        for items in (mbt or {}).values():
            for it in items:
                u = (it.get("url") or "").strip()
                if not u or u.startswith("magnet:") or u in seen:
                    continue
                seen.add(u)
                if u in _verify_inflight:
                    continue
                if u in _verify_cache and now - _verify_cache[u][1] < VERIFY_CACHE_TTL:
                    continue
                todo.append(u)
        todo = todo[:VERIFY_BG_LIMIT]
        if not todo:
            return
        for u in todo:
            _verify_inflight.add(u)
        url_source = _url_source_map(mbt)
        try:
            async with httpx.AsyncClient(
                    timeout=httpx.Timeout(VERIFY_TIMEOUT + 2),
                    follow_redirects=True) as vclient:
                verdict = await verify_urls(todo, vclient)
            _record_verdicts(verdict, url_source)
            url_drive = {(it.get("url") or "").strip(): d
                         for d, its in (mbt or {}).items() for it in its}
            for u, st in verdict.items():
                metrics.record_verify(url_drive.get(u, "unknown"), st)
            # 历史只冻结用户当次实际收到的响应快照（record 时已剔除死链）；
            # 后台新定性的死链仅维护死链表/FTS，下次搜索自然剔除，不回溯改写当次历史
        finally:
            _verify_inflight.difference_update(todo)
    except Exception as e:
        logger.warning("bg deep verify error kw=%s: %s", keyword, e)


def _apply_retry_verdict(url: str, status: str):
    """重试定性后的最小落库：维护死链集合/FTS/验证缓存。
    重试阶段没有来源(source)上下文，故不写 source_health，避免污染来源健康度。"""
    now = time.time()
    try:
        with db() as conn:
            if status == "dead":
                conn.execute(
                    "INSERT INTO dead_links(url,title,ts) VALUES(?,?,?) "
                    "ON CONFLICT(url) DO UPDATE SET ts=excluded.ts",
                    (url, "", now))
            else:
                conn.execute("DELETE FROM dead_links WHERE url=?", (url,))
        if status == "dead":
            _dead_urls.add(url)
            try:
                _fts_remove_url(url)
            except Exception:
                pass
        else:
            _dead_urls.discard(url)
        _verify_cache[url] = (status, now)
    except Exception as e:
        logger.warning("apply retry verdict error %s: %s", url[:80], e)


async def retry_loop():
    """周期性重试验证异常(unknown)链接：限流并发、隔几分钟一次，
    连续 VERIFY_RETRY_MAX 次仍异常则容错放行 alive，全程不阻塞响应链路。"""
    await asyncio.sleep(VERIFY_RETRY_START_DELAY)
    metrics.job_beat("retry", info="loop started")
    while True:
        due = []
        try:
            now = time.time()
            due = [u for u, (_, nxt) in _retry_pending.items()
                   if nxt <= now and u not in _retry_inflight]
            if due:
                for u in due:
                    _retry_inflight.add(u)
                try:
                    async with httpx.AsyncClient(
                            timeout=httpx.Timeout(VERIFY_TIMEOUT + 2),
                            follow_redirects=True) as vclient:
                        sem = asyncio.Semaphore(VERIFY_RETRY_WORKERS)

                        async def guarded(u):
                            async with sem:
                                return await _check_one(u, vclient)

                        results = await asyncio.gather(
                            *[guarded(u) for u in due],
                            return_exceptions=True)
                    for item in results:
                        if isinstance(item, Exception):
                            continue
                        u, status = item
                        _retry_inflight.discard(u)
                        ent = _retry_pending.get(u)
                        if status in ("alive", "dead"):
                            _apply_retry_verdict(u, status)
                            _retry_pending.pop(u, None)
                            metrics.retry_resolved += 1
                            metrics.record_verify(
                                _drive_by_url(u) or "unknown", status)
                            logger.info("retry resolved -> %s %s",
                                        status, u[:80])
                        else:
                            fails = (ent[0] if ent else 0) + 1
                            if fails >= VERIFY_RETRY_MAX:
                                # 多次仍无法判定：容错放行当活，避免链接被长期挂起
                                _apply_retry_verdict(u, "alive")
                                _retry_pending.pop(u, None)
                                metrics.retry_giveup += 1
                                logger.info("retry giveup, mark alive %s",
                                            u[:80])
                            else:
                                _retry_pending[u] = [
                                    fails, now + VERIFY_RETRY_INTERVAL_SEC]
                finally:
                    _retry_inflight.difference_update(due)
            metrics.job_beat("retry",
                             info="pending=%d" % len(_retry_pending))
        except Exception as e:
            logger.warning("retry loop error: %s", e)
            metrics.job_beat("retry", ok=False, info=str(e)[:120])
        await asyncio.sleep(VERIFY_RETRY_SCAN_SEC)


# ---------------- 滥用检测 / 告警 ----------------
def check_abuse(ip: str, keyword: str, username: str = ""):
    # admin 豁免：管理员频繁测试/自用，不计入滥用告警（事件照常记录）
    try:
        if username and get_role(username) == "admin":
            return
    except Exception:
        pass
    t = time.time()
    win_cut = time.strftime("%Y-%m-%dT%H:%M:%S",
                            time.localtime(t - RATE_WINDOW_SEC))
    day_start = time.strftime("%Y-%m-%dT00:00:00")
    with db() as conn:
        win_n = conn.execute(
            "SELECT COUNT(*) c FROM events WHERE ip=? AND ts>=?",
            (ip, win_cut)).fetchone()["c"]
        day_n = conn.execute(
            "SELECT COUNT(*) c FROM events WHERE ip=? AND ts>=?",
            (ip, day_start)).fetchone()["c"]
    reasons = []
    if win_n > RATE_WINDOW_MAX:
        reasons.append(f"近{RATE_WINDOW_SEC // 60}分钟{win_n}次（阈值{RATE_WINDOW_MAX}）")
    if day_n > RATE_DAY_MAX:
        reasons.append(f"今日{day_n}次（阈值{RATE_DAY_MAX}）")
    if reasons:
        maybe_alert(ip, "；".join(reasons))


def maybe_alert(ip: str, reason: str):
    t = time.time()
    if t - _last_alert.get(ip, 0) < ALERT_COOLDOWN_SEC:
        return
    _last_alert[ip] = t
    detail = f"IP {ip} 觅影用量异常：{reason}"
    with db() as conn:
        conn.execute("INSERT INTO alerts(ip,reason,detail,ts) VALUES(?,?,?,?)",
                     (ip, reason, detail, now_ts()))
    if BARK_KEY:
        try:
            title = "觅影·用量异常"
            url = f"https://api.day.app/{BARK_KEY}/{quote(title)}/{quote(detail)}"
            with httpx.Client(timeout=10.0) as c:
                c.get(url)
        except Exception as e:
            logger.warning("bark failed: %s", e)


_BARK_HOST_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$"
)


def _bark_norm_server(server: str) -> str:
    """规范化 Bark 服务器地址：补协议、去尾斜杠，非法时回退官方域名。"""
    s = (server or "").strip()
    if s and not s.lower().startswith(("http://", "https://")):
        s = "https://" + s
    try:
        # 只承认单个 ://，拦掉补协议后畸形的 https://ftp://x.com 这类
        p = urlparse(s)
        if p.scheme in ("http", "https") and p.netloc and len(s) <= 200 \
                and s.count("://") == 1:
            host = p.hostname or ""
            ok_host = bool(_BARK_HOST_RE.match(host)) or (
                ":" in host and all(c in "0123456789abcdefABCDEF:" for c in host))
            if ok_host:
                p.port  # 非法端口会抛 ValueError，落到下方回退
                return s.rstrip("/")
    except Exception:
        pass
    return BARK_DEFAULT_SERVER


def _bark_send(server: str, key: str, title: str, body: str,
               group: str = "觅影", url: str = "") -> bool:
    """向指定 Bark 服务器/密钥发一条推送，成功返回 True；网络异常返回 False。"""
    key = (key or "").strip()
    if not key:
        return False
    base = _bark_norm_server(server)
    try:
        q = (f"{base}/{quote(key)}/{quote(title)}/{quote(body)}"
             f"?group={quote(group)}")
        if url:
            q += f"&url={quote(url, safe='')}"
        with httpx.Client(timeout=10.0) as c:
            resp = c.get(q)
        return 200 <= resp.status_code < 300
    except Exception as e:
        logger.warning("bark send failed: %s", e)
        return False


def push_bark(title: str, body: str, group: str = "觅影", url: str = ""):
    """通用 Bark 推送（追剧更新等），走站长默认通道。失败不影响主流程。
    url 非空时，点击通知可直接打开对应网盘链接。"""
    if not BARK_KEY:
        return
    _bark_send(BARK_DEFAULT_SERVER, BARK_KEY, title, body, group, url)


def _user_bark_get(username: str):
    """返回用户自定义 Bark 配置 {server,key}，未配置返回 None。"""
    try:
        with db() as conn:
            r = conn.execute(
                "SELECT server,bark_key FROM user_bark WHERE username=?",
                (username,)).fetchone()
        if r and (r["bark_key"] or "").strip():
            return {"server": r["server"] or BARK_DEFAULT_SERVER,
                    "key": r["bark_key"].strip()}
    except Exception as e:
        logger.warning("user bark get failed: %s", e)
    return None


def _is_private_ip(ip: str) -> bool:
    """回环/内网地址不参与"新 IP 登录"提醒，避免 frp 回环与局域网误报。"""
    if not ip or ip in ("unknown", "::1"):
        return True
    if ip.startswith(("127.", "10.", "192.168.", "169.254.")):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            return 16 <= second <= 31
        except (IndexError, ValueError):
            return False
    return False


def _security_notify(ip: str, kind: str, title: str, detail: str):
    """安全事件提醒：冷却去抖 + 落审计 alerts + Bark，任何异常都不影响登录主流程。"""
    try:
        key = (ip, kind)
        t = time.time()
        if t - _security_alert_ts.get(key, 0) < ALERT_COOLDOWN_SEC:
            return
        _security_alert_ts[key] = t
        with db() as conn:
            conn.execute("INSERT INTO alerts(ip,reason,detail,ts) VALUES(?,?,?,?)",
                         (ip, kind, detail, now_ts()))
        push_bark(title, detail, group="觅影安全")
    except Exception as e:
        logger.warning("security notify failed: %s", e)


def _note_login_seen_ip(username: str, ip: str, role: str):
    """成功登录后登记来源 IP，按网段（IPv4 /24、IPv6 /64）判定是否新设备。

    新网段：管理员即时 Bark 并落审计；普通账号只写审计 alerts 与日志、不推送，
    管理面板仍可见。同网段内动态 IP 漂移视为已知，静默累计具体 IP，不重复报。"""
    if not LOGIN_IP_NOTIFY or _is_private_ip(ip):
        return
    try:
        net = _ip_net_key(ip)
        with db() as conn:
            net_seen = conn.execute(
                "SELECT 1 FROM login_seen_ip WHERE net_key=? LIMIT 1",
                (net,)).fetchone()
            row = conn.execute(
                "SELECT hits FROM login_seen_ip WHERE ip=?", (ip,)).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO login_seen_ip(ip,net_key,first_ts,last_ts,hits) "
                    "VALUES(?,?,?,?,1)", (ip, net, now_ts(), now_ts()))
            else:
                conn.execute(
                    "UPDATE login_seen_ip SET net_key=?,last_ts=?,hits=? WHERE ip=?",
                    (net, now_ts(), row["hits"] + 1, ip))
            is_new_net = net_seen is None
        if not is_new_net:
            return
        metrics.login_new_ip += 1
        if role == "admin":
            _security_notify(
                ip, "login_new_ip", "觅影·新设备登录",
                f"管理员 {username} 自新网段 {net}（IP {ip}）登录成功，"
                "如非本人请立即改密")
            return
        # 普通账号：仅审计 + 日志，不发 Bark；管理面板"最近滥用告警"可见
        detail = (f"普通账号 {username} 自新网段 {net}（IP {ip}）登录成功，"
                  "按分级策略仅记录、不推送")
        logger.warning(
            "login new net (user, no push) user=%s ip=%s net=%s",
            username, ip, net)
        with db() as conn:
            conn.execute(
                "INSERT INTO alerts(ip,reason,detail,ts) VALUES(?,?,?,?)",
                (ip, "login_new_ip", detail, now_ts()))
    except Exception as e:
        logger.warning("login seen ip failed: %s", e)


# ---------------- 透明代理（非搜索） ----------------
def _fwd_headers(request: Request):
    return {k: v for k, v in request.headers.items()
            if k.lower() not in HOP_BY_HOP}


def _upstream_url(path: str, request: Request) -> str:
    qs = str(request.url.query)
    url = f"{UPSTREAM}/{path}"
    return f"{url}?{qs}" if qs else url


async def _stream_proxy(request: Request, path: str):
    url = _upstream_url(path, request)
    body = await request.body()
    client = httpx.AsyncClient(timeout=httpx.Timeout(180.0, connect=15.0))
    try:
        req = client.build_request(
            request.method, url, headers=_fwd_headers(request), content=body)
        upstream = await client.send(req, stream=True)

        async def gen():
            try:
                async for chunk in upstream.aiter_raw():
                    yield chunk
            finally:
                await upstream.aclose()
                await client.aclose()

        resp_headers = {k: v for k, v in upstream.headers.items()
                        if k.lower() not in HOP_BY_HOP}
        return StreamingResponse(gen(), status_code=upstream.status_code,
                                 headers=resp_headers)
    except Exception as e:
        await client.aclose()
        logger.warning("upstream error: %s", e)  # 内部日志保留细节，不回传给客户端
        return JSONResponse({"detail": "上游服务暂时不可用，请稍后重试"}, status_code=502)


# 历史分项计数认可的标准网盘（与前端 DRIVE_ORDER 对齐）；其余任意上游新类型
# 统一并入 other，保证 last_counts 分项之和恒等于 total，前端不会漏掉未知桶
_HISTORY_CANONICAL = ("baidu", "quark", "aliyun", "tianyi", "uc", "115",
                      "xunlei", "123", "pikpak", "guangya", "magnet")


def _counts(mbt: dict):
    out = {}
    other = 0
    for k, v in (mbt or {}).items():
        if not isinstance(v, list):
            continue
        n = len(v)
        if k in _HISTORY_CANONICAL:
            out[k] = n
        else:
            other += n
    ordered = {d: out[d] for d in _HISTORY_CANONICAL if d in out}
    if other:
        ordered["other"] = other
    return json.dumps(ordered, ensure_ascii=False)


def _record_history(username, keyword, src, data):
    try:
        total = int(data.get("total") or 0)
        counts = _counts(data.get("merged_by_type") or {})
        with db() as conn:
            conn.execute(
                "INSERT INTO history(username,keyword,total,counts,src,ts) "
                "VALUES(?,?,?,?,?,?)",
                (username, keyword, total, counts, src, now_ts()))
    except Exception as e:
        logger.warning("record history failed: %s", e)


def _record_event(ip, keyword, src, data):
    try:
        total = int(data.get("total") or 0)
        counts = _counts(data.get("merged_by_type") or {})
        with db() as conn:
            conn.execute(
                "INSERT INTO events(ip,keyword,total,counts,src,ts) "
                "VALUES(?,?,?,?,?,?)",
                (ip, keyword, total, counts, src, now_ts()))
            if EVENT_KEEP_DAYS > 0:
                cut = time.strftime(
                    "%Y-%m-%dT%H:%M:%S",
                    time.localtime(time.time() - EVENT_KEEP_DAYS * 86400))
                conn.execute("DELETE FROM events WHERE ts<?", (cut,))
    except Exception as e:
        logger.warning("record event failed: %s", e)


# ---------------- 分桶域名复核：插件自报类型与 URL 域名冲突时以域名为准 ----------------
# 只收录能确定归属的分享页域名（域名/子域后缀匹配）；未知域名保留原桶，保守不误迁
DRIVE_DOMAIN_RULES = [
    ("quark", ("pan.quark.cn",)),
    ("baidu", ("pan.baidu.com", "yun.baidu.com", "pan.bdimg.com")),
    ("aliyun", ("alipan.com", "aliyundrive.com")),
    ("uc", ("drive.uc.cn", "fast.uc.cn", "pan.uc.cn")),
    ("115", ("115cdn.com", "115.com")),
    ("xunlei", ("pan.xunlei.com",)),
    ("mobile", ("yun.139.com", "caiyun.139.com", "clouds.139.com")),
    ("123", ("123pan.com", "123912.com", "123684.com", "123865.com")),
    ("tianyi", ("cloud.189.cn",)),
    # 真实分享页可见 toapp.mypikpak.com 跳转域，一并纳入
    ("pikpak", ("pikpak.com", "pikpak.cloud", "mypikpak.com")),
    ("guangya", ("guangyapan.com",)),
]


def _drive_by_url(url: str):
    """按分享页 URL 域名推断网盘类型；magnet 链归 magnet；无法判定返回 None。"""
    u = (url or "").strip()
    if u.startswith("magnet:"):
        return "magnet"
    try:
        host = (urlparse(u).hostname or "").lower()
    except Exception:
        return None
    if not host:
        return None
    for drive, suffixes in DRIVE_DOMAIN_RULES:
        if host in suffixes or any(host.endswith("." + s) for s in suffixes):
            return drive
    return None


def _rebucket_by_domain(mbt: dict) -> dict:
    """按 URL 域名复核 merged_by_type 分桶。
    域名可判定且与插件自报类型冲突时以域名为准；未知域名/异常 URL 保留原桶；空桶移除。"""
    out = {}
    for typ, items in (mbt or {}).items():
        for it in items:
            target = _drive_by_url(it.get("url") or "") or typ
            out.setdefault(target, []).append(it)
    return out


def _inject_clean_filter(request: Request, body: bytes):
    """默认只看正片：未显式传 filter 且 clean!=0 时，注入默认排除词。"""
    qs = dict(request.query_params)
    target = f"{UPSTREAM}/api/search"
    if qs.get("clean", "1") == "0" or qs.get("filter"):
        return _upstream_url("api/search", request), body
    filt = json.dumps({"exclude": DEFAULT_EXCLUDE}, ensure_ascii=False)
    if request.method == "GET":
        pairs = parse_qsl(str(request.url.query), keep_blank_values=True)
        pairs.append(("filter", filt))
        return target + "?" + urlencode(pairs), body
    try:
        payload = json.loads(body.decode("utf-8") or "{}")
        if isinstance(payload, dict) and "filter" not in payload:
            payload["filter"] = {"exclude": DEFAULT_EXCLUDE}
            body = json.dumps(payload, ensure_ascii=False).encode()
    except Exception:
        return _upstream_url("api/search", request), body
    return target, body


# ---------------- 查询改写 / 多路召回（方案一） ----------------
# 季数等价（第四季/第4季/4/S4）+ 长查询逐级退化（去年份/类型/演员等限定词），
# 仅在主词供给不足时并发回源；变体新增结果统一过片名/季/年相关性过滤，防串片串季。
_CN_DIGIT = {"零": 0, "一": 1, "二": 2, "两": 2, "三": 3, "四": 4, "五": 5,
             "六": 6, "七": 7, "八": 8, "九": 9}
_TYPE_WORDS = ("电视剧", "连续剧", "综艺", "电影", "纪录片", "动漫", "动画",
               "国剧", "美剧", "韩剧", "日剧", "港剧", "台剧", "网剧")
_SEASON_RE = re.compile(r"第\s*(\d+|[一二三四五六七八九十]{1,3})\s*季")
_SEASON_EN_RE = re.compile(
    r"(?<![A-Za-z])[Ss]eason\s*(\d{1,2})|(?<![A-Za-z])S(\d{1,2})(?![\d])")
_YEAR_RE = re.compile(r"(?:19|20)\d{2}")
_BARE_SEASON_RE = re.compile(r"^(?P<base>.+?)\s*(?P<num>\d{1,2})$")


def _cn_num(s: str):
    """『四/十/十二』等中文小数字转 int，失败返回 None，覆盖季号常见范围。"""
    if not s:
        return None
    if s.isdigit():
        return int(s)
    if s == "十":
        return 10
    if "十" in s:
        a, _, b = s.partition("十")
        tens = _CN_DIGIT.get(a, 1) if a else 1
        ones = _CN_DIGIT.get(b, 0) if b else 0
        return tens * 10 + ones
    if len(s) == 1:
        return _CN_DIGIT.get(s)
    val = 0
    for ch in s:
        if ch not in _CN_DIGIT:
            return None
        val = val * 10 + _CN_DIGIT[ch]
    return val


def _num_to_cn(n: int) -> str:
    cn = {1: "一", 2: "二", 3: "三", 4: "四", 5: "五", 6: "六",
          7: "七", 8: "八", 9: "九", 10: "十"}
    if n in cn:
        return cn[n]
    if 10 < n < 20:
        return "十" + cn.get(n - 10, str(n - 10))
    return str(n)


def _norm_space(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").replace("　", " ")).strip()


def _parse_season(keyword: str):
    """识别查询中的季号，返回 (去季标记后的 base, season_int|None)。"""
    kw = _norm_space(keyword)
    m = _SEASON_RE.search(kw)
    if m:
        n = _cn_num(m.group(1))
        return _norm_space(kw[:m.start()] + " " + kw[m.end():]), n
    m = _SEASON_EN_RE.search(kw)
    if m:
        return _norm_space(kw[:m.start()] + " " + kw[m.end():]), \
            int(m.group(1) or m.group(2))
    return kw, None


def _root_core(keyword: str) -> str:
    """核心根片名：取首段并去年份/季标记/类型词，丢弃演员等后置限定。"""
    head = re.split(r"[\s/|｜]+", _norm_space(keyword), 1)[0]
    head = _YEAR_RE.sub(" ", head)
    head = _SEASON_RE.sub(" ", head)
    head = _SEASON_EN_RE.sub(" ", head)
    for w in _TYPE_WORDS:
        head = head.replace(w, " ")
    return _norm_space(head)


# ---------------- 同义词召回（#233，纯规则、零外部依赖） ----------------
# 高频简体→繁体单字表（影视片名/资源标题常用字，一对多歧义取最通用繁体）。
# 仅用于多召回一路变体；表外字原样保留，转不出差异就不产生繁体变体，安全降级。
_S2T_MAP = {
    "个": "個", "们": "們", "这": "這", "里": "裡", "后": "後", "为": "為",
    "于": "於", "么": "麼", "无": "無", "来": "來", "时": "時", "间": "間",
    "对": "對", "过": "過", "还": "還", "关": "關", "开": "開", "观": "觀",
    "见": "見", "听": "聽", "说": "說", "话": "話", "语": "語", "请": "請",
    "问": "問", "电": "電", "视": "視", "剧": "劇", "综": "綜", "艺": "藝",
    "纪": "紀", "录": "錄", "节": "節", "国": "國", "乡": "鄉", "边": "邊",
    "际": "際", "云": "雲", "风": "風", "雾": "霧", "爱": "愛", "怀": "懷",
    "欢": "歡", "乐": "樂", "声": "聲", "梦": "夢", "华": "華", "丽": "麗",
    "坚": "堅", "强": "強", "伟": "偉", "学": "學", "庆": "慶", "余": "餘",
    "丰": "豐", "现": "現", "发": "發", "游": "遊", "戏": "戲", "战": "戰",
    "争": "爭", "斗": "鬥", "阴": "陰", "阳": "陽", "险": "險", "红": "紅",
    "绿": "綠", "蓝": "藍", "黄": "黃", "银": "銀", "铜": "銅", "铁": "鐵",
    "钱": "錢", "饭": "飯", "汤": "湯", "妈": "媽", "儿": "兒", "孙": "孫",
    "师": "師", "医": "醫", "护": "護", "贼": "賊", "兴": "興", "伤": "傷",
    "难": "難", "优": "優", "胜": "勝", "败": "敗", "进": "進", "达": "達",
    "运": "運", "动": "動", "远": "遠", "长": "長", "浅": "淺", "旧": "舊",
    "坏": "壞", "实": "實", "虚": "虛", "异": "異", "别": "別", "称": "稱",
    "号": "號", "寻": "尋", "获": "獲", "给": "給", "网": "網", "盘": "盤",
    "链": "鏈", "资": "資", "讯": "訊", "线": "線", "点": "點", "络": "絡",
    "数": "數", "据": "據", "体": "體", "会": "會", "议": "議", "团": "團",
    "队": "隊", "组": "組", "员": "員", "业": "業", "厂": "廠", "场": "場",
    "铺": "鋪", "经": "經", "济": "濟", "价": "價", "币": "幣", "万": "萬",
    "亿": "億", "块": "塊", "计": "計", "划": "劃", "帮": "幫", "协": "協",
    "题": "題", "头": "頭", "脑": "腦", "脸": "臉", "脚": "腳", "裤": "褲",
    "楼": "樓", "桥": "橋", "岛": "島", "叶": "葉", "树": "樹", "鸟": "鳥",
    "兽": "獸", "鱼": "魚", "虫": "蟲", "热": "熱", "温": "溫", "干": "乾",
    "湿": "濕", "灯": "燈", "烟": "煙", "买": "買", "卖": "賣", "货": "貨",
    "赚": "賺", "赔": "賠", "选": "選", "择": "擇", "决": "決", "愿": "願",
    "记": "記", "忆": "憶", "惊": "驚", "讶": "訝", "极": "極", "敌": "敵",
    "杀": "殺", "枪": "槍", "剑": "劍", "钥": "鑰", "灵": "靈", "圣": "聖",
    "侠": "俠", "隐": "隱", "维": "維", "镇": "鎮", "县": "縣", "台": "臺",
    "湾": "灣", "军": "軍", "谍": "諜", "悬": "懸", "侦": "偵", "闹": "鬧",
    "灾": "災", "历": "歷", "怖": "怖", "卧": "臥", "传": "傳", "访": "訪",
    "谈": "談", "画": "畫", "摄": "攝", "导": "導", "编": "編", "质": "質",
    "轨": "軌", "双": "雙", "标": "標", "筛": "篩", "滤": "濾", "键": "鍵",
    "词": "詞", "门": "門", "单": "單", "状": "狀", "态": "態", "补": "補",
    "验": "驗", "删": "刪", "试": "試", "断": "斷", "级": "級", "备": "備",
    "监": "監", "仪": "儀", "报": "報", "觉": "覺", "参": "參", "环": "環",
    "变": "變", "权": "權", "账": "賬", "凭": "憑", "证": "證", "简": "簡",
    "义": "義", "扩": "擴", "护": "護", "从": "從", "虽": "雖", "没": "沒",
    "系": "係", "将": "將", "总": "總", "尔": "爾", "钟": "鐘", "类": "類",
    "响": "響", "顾": "顧",
}

# 作品别号/中英译名：同一作品的等价裸片名（不含季号/年份/副标题），只收高确定性条目。
# 组内任意写法互为别名；匹配按小写精确相等，避免子串误伤。可按需自行增补。
_TITLE_ALIAS_GROUPS = [
    ["盗梦空间", "Inception"],
    ["肖申克的救赎", "刺激1995", "The Shawshank Redemption"],
    ["这个杀手不太冷", "杀手里昂", "Léon: The Professional", "Leon"],
    ["星际穿越", "Interstellar"],
    ["阿凡达", "Avatar"],
    ["沙丘", "Dune"],
    ["奥本海默", "Oppenheimer"],
    ["流浪地球", "The Wandering Earth"],
    ["鱿鱼游戏", "Squid Game"],
    ["复仇者联盟", "复联", "Avengers"],
    ["哈利波特", "哈利·波特", "Harry Potter"],
    ["指环王", "魔戒", "The Lord of the Rings"],
    ["黑客帝国", "骇客任务", "The Matrix"],
    ["速度与激情", "玩命关头", "Fast & Furious"],
    ["生化危机", "恶灵古堡", "Resident Evil"],
    ["加勒比海盗", "Pirates of the Caribbean"],
    ["蝙蝠侠", "Batman"],
    ["蜘蛛侠", "Spider-Man"],
    ["星球大战", "星际大战", "Star Wars"],
    ["冰雪奇缘", "Frozen"],
    ["疯狂动物城", "Zootopia"],
]
_ALIAS_INDEX = {}
for _g in _TITLE_ALIAS_GROUPS:
    _names = [n.strip() for n in _g if n.strip()]
    for _n in _names:
        _ALIAS_INDEX[_n.lower()] = [x for x in _names if x != _n]


def _s2t(s: str) -> str:
    """简体→繁体（内联高频单字表）；表外字原样保留，仅供多一路召回。"""
    if not s:
        return ""
    return "".join(_S2T_MAP.get(ch, ch) for ch in s)


def _alias_names(root: str):
    """裸根片名命中别名词典时返回同作品其他写法（保留原大小写），否则空列表。"""
    if not root:
        return []
    return list(_ALIAS_INDEX.get(root.strip().lower(), []))


def _equivalent_roots(keyword: str):
    """变体相关性过滤用的等价根词集合（小写）：原根 + 繁体根 + 别号根。
    纯字母根去空格短于 3 不收，防止单/双字母英文子串误命中；中文根不受此限。"""
    root = _root_core(keyword)
    roots = set()

    def keep(r):
        r = (r or "").strip()
        if not r:
            return
        low = r.lower()
        compact = re.sub(r"\s+", "", low)
        if re.fullmatch(r"[a-z0-9.&':\-]+", compact) and len(compact) < 3:
            return
        roots.add(low)

    keep(root)
    if SYNONYM_ENABLED:
        keep(_s2t(root))
        for _a in _alias_names(root):
            keep(_root_core(_a))
    return roots


def _query_variants(keyword: str, limit: int):
    """生成有序、去重、不含原词的召回变体：先季等价，再长查询逐级退化。"""
    kw = _norm_space(keyword)
    if not kw or limit <= 0:
        return []
    out, seen = [], set()

    def add(v):
        v = _norm_space(v)
        if v and v != kw and v not in seen:
            seen.add(v)
            out.append(v)

    base, season = _parse_season(kw)
    if season is not None and base:
        add(f"{base} 第{_num_to_cn(season)}季")
        add(f"{base} 第{season}季")
        add(f"{base}{season}")
        add(f"{base} {season}")
        add(f"{base} S{season}")
    else:
        # 无显式季标记时，尝试把结尾裸数字当季号（如『现在就出发4』），4 位年份除外
        m = _BARE_SEASON_RE.match(base)
        if m:
            b, n = _norm_space(m.group("base")), int(m.group("num"))
            if b and 1 <= n <= 30:
                add(f"{b} 第{_num_to_cn(n)}季")
                add(f"{b} 第{n}季")
                add(f"{b} S{n}")

    # 同义词（强等价，优先于后面的逐级退化）：繁简体 + 作品别号/中英译名。
    # 仅对「裸根名（可带季/年/类型词）、无实义副标题」生效：既避免给长尾查询造
    # 等长繁体变体挤占退化名额，也防止别号带着副标题泛化串片。
    if SYNONYM_ENABLED:
        sbase, sseason = _parse_season(kw)
        extra = []
        for t in [t for t in re.split(r"[\s,，、]+", kw) if t][1:]:
            if _YEAR_RE.fullmatch(t):
                continue
            if _SEASON_RE.search(t) or _SEASON_EN_RE.search(t):
                continue
            if t in _TYPE_WORDS:
                continue
            extra.append(t)
        if not extra and sbase:
            tw = _s2t(sbase)
            if tw and tw != sbase:
                suffix = (" 第%d季" % sseason) if sseason is not None else ""
                add(tw + suffix)
            for al in _alias_names(_root_core(kw))[:SYNONYM_ALIAS_MAX]:
                al_root = _root_core(al)
                if sseason is not None and re.search(r"[A-Za-z]", al_root):
                    add("%s S%d" % (al_root, sseason))
                elif sseason is not None:
                    add("%s 第%d季" % (al_root, sseason))
                else:
                    add(al_root)

    # 长查询逐级退化：从尾部逐档去限定词直到首段根片名；遇到季 token 立即停止防串季
    tokens = [t for t in re.split(r"[\s,，、]+", kw) if t]
    if len(tokens) >= 2 and len(_root_core(kw)) >= 2:
        work = list(tokens)
        while len(work) > 1:
            if _SEASON_RE.search(work[-1]) or _SEASON_EN_RE.search(work[-1]):
                break
            work = work[:-1]
            add(" ".join(work))
    return out[:limit]


def _title_season(note: str):
    """从资源标题提取明确季号；识别不到返回 None（不视为冲突，避免误杀）。"""
    m = _SEASON_RE.search(note or "")
    if m:
        return _cn_num(m.group(1))
    m = _SEASON_EN_RE.search(note or "")
    if m:
        return int(m.group(1) or m.group(2))
    return None


_KANA_RE = re.compile(r"[぀-ヿ]")


def _root_hits(root: str, low: str) -> bool:
    """根片名是否在标题中形成一次『干净命中』。
    中文根词若紧贴日文假名（如『天道まさえ』『お天道様』）视为日文词的一部分，不算命中。"""
    if not root:
        return False
    rl = root.lower()
    if re.search(r"[A-Za-z]", root):
        return rl in low
    for mt in re.finditer(re.escape(rl), low):
        before = low[mt.start() - 1] if mt.start() > 0 else ""
        after = low[mt.end()] if mt.end() < len(low) else ""
        if not _KANA_RE.match(before) and not _KANA_RE.match(after):
            return True
    return False


def _variant_relevant(orig_kw: str, item: dict) -> bool:
    """变体『新增』结果相关性把关：原根或其等价写法（繁简/别号/中英译名）须干净命中；
    明确异季/年代冲突则剔除。"""
    note = item.get("note") or ""
    low = note.lower()
    root = _root_core(orig_kw)
    if len(root) >= 2:
        roots = _equivalent_roots(orig_kw)
        if not any(_root_hits(r, low) for r in roots):
            return False
    _, season = _parse_season(orig_kw)
    ts = _title_season(note)
    if season is not None and ts is not None and ts != season:
        return False
    # 年份宽松：容忍 ±2 年（拍摄/首播跨年、合集区间），仅同名作品年代明显不同才拦
    qy = [int(y) for y in _YEAR_RE.findall(orig_kw)]
    ty = [int(y) for y in _YEAR_RE.findall(note)]
    if qy and ty and all(abs(y - b) > 2 for y in ty for b in qy):
        return False
    return True


def _mbt_url_count(mbt: dict) -> int:
    urls = set()
    for items in (mbt or {}).values():
        for it in items:
            u = (it.get("url") or "").strip()
            if u:
                urls.add(u)
    return len(urls)


def _merge_variant_mbt(extra_list: list):
    """变体结果经相关性过滤、按 URL 去重（同链只留一条）并按域名定桶。"""
    out, picked = {}, set()
    for embt in extra_list:
        for drive, items in (embt or {}).items():
            for it in items:
                u = (it.get("url") or "").strip()
                if not u or u in picked:
                    continue
                picked.add(u)
                d = _drive_by_url(u) or drive
                out.setdefault(d, []).append(it)
    return out


async def _multi_recall(orig_kw: str):
    """主词供给不足时并发跑变体回源，返回 (增量mbt, 变体数, 相关性过滤后新增数)。
    自建独立 httpx client，不依赖主请求 client 的生命周期。"""
    variants = _query_variants(orig_kw, QUERY_VARIANT_MAX)
    if not variants:
        return None, 0, 0

    async def one(v, c):
        try:
            return await _internal_search(v, c)
        except Exception:
            return {}

    results = []
    try:
        async with httpx.AsyncClient(
                timeout=httpx.Timeout(QUERY_VARIANT_TIMEOUT + 10.0,
                                      connect=10.0)) as vclient:
            tasks = [asyncio.create_task(one(v, vclient)) for v in variants]
            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*tasks), timeout=QUERY_VARIANT_TIMEOUT)
            except asyncio.TimeoutError:
                # 硬顶到达：只收已完成的部分，未完成任务随 client 关闭而取消
                for t in tasks:
                    if t.done() and not t.cancelled() and not t.exception():
                        results.append(t.result())
    except Exception:
        results = []
    filtered = [{d: [it for it in items if _variant_relevant(orig_kw, it)]
                 for d, items in (m or {}).items()} for m in results]
    merged = _merge_variant_mbt(filtered)
    return merged, len(variants), _mbt_url_count(merged)


class _CircuitOpen(Exception):
    """熔断打开期间的内部快速失败信号。"""


def _local_fallback_response(local_mbt, username, keyword, src, ip, reason,
                             clean_on=True):
    """回源不可用（熔断打开/网络失败）时用本地 FTS 存量兜底，有多少给多少。
    无任何本地存量则返回 None，由调用方回 5xx。"""
    if not local_mbt:
        return None
    mbt, deduped = _dedup_mbt(local_mbt)
    mbt, dead_hidden = _filter_dead_mbt(mbt)
    clean_hidden = 0
    if clean_on:
        mbt, clean_hidden = _apply_clean_filter(mbt, keyword)
    total = sum(len(v) for v in mbt.values())
    if not total:
        return None
    data = {"merged_by_type": mbt, "total": total,
            "verified": {"checked": 0, "removed": dead_hidden,
                         "deduped": deduped, "source": "local-fallback",
                         "clean_hidden": clean_hidden, "degraded": reason}}
    _record_history(username, keyword, src, data)
    _record_event(ip, keyword, src, data)
    check_abuse(ip, keyword, username)
    metrics.search_total += 1
    metrics.search_fallback += 1
    logger.warning("serve local fallback (%s) kw=%s total=%d",
                   reason, keyword, total)
    return Response(
        content=json.dumps({"code": 0, "data": data},
                           ensure_ascii=False).encode(),
        status_code=200,
        headers={"content-type": "application/json",
                 "X-Source": "local-fallback"})


async def _search_proxy(request: Request, username: str):
    qs = dict(request.query_params)
    keyword = qs.get("kw", "")
    src = qs.get("src", "all")
    clean_on = qs.get("clean", "1") != "0"
    ip = client_ip(request)
    body = await request.body()
    target_url, body = _inject_clean_filter(request, body)

    # ===== 混合检索：先查本地 FTS5，命中足够则立即返回（SWR），后台异步保鲜 =====
    local_mbt: dict = {}
    if FTS_ENABLED and keyword and request.method == "GET":
        local_total = 0
        try:
            local_mbt = _fts_local_search(keyword)
            local_total = sum(len(v) for v in local_mbt.values())
        except Exception as e:
            logger.warning("local search error: %s", e)
        if local_total >= FTS_MIN_HITS:
            # 档2：英文词本地命中也注入海外磁力（短超时，失败静默）
            try:
                ext = await _fetch_magnets(keyword, soft=True)
                ext_m = ext.get("magnet") or []
                if ext_m:
                    seen = {u.get("url") for u in (local_mbt.get("magnet") or [])}
                    ext_m = [it for it in ext_m if it.get("url") not in seen]
                    if ext_m:
                        local_mbt["magnet"] = ext_m + (local_mbt.get("magnet") or [])
                        local_total = sum(len(v) for v in local_mbt.values())
            except Exception as e:
                logger.warning("magnet swr error: %s", e)
            # C：本地结果同样做同版本去重；A+B：先剔除已确认死链，再后台全量净化
            local_mbt, local_deduped = _dedup_mbt(local_mbt)
            local_mbt, local_dead_hidden = _filter_dead_mbt(local_mbt)
            local_clean_hidden = 0
            if clean_on:
                local_mbt, local_clean_hidden = _apply_clean_filter(
                    local_mbt, keyword)
            local_total = sum(len(v) for v in local_mbt.values())
            # 后台刷新（TTL 过期回源 + 验证剔除失效），本次响应不等待
            bg = asyncio.create_task(_fts_bg_refresh(keyword))
            _background_tasks.add(bg)
            bg.add_done_callback(_background_tasks.discard)
            deep = asyncio.create_task(_bg_deep_verify(keyword, local_mbt))
            _background_tasks.add(deep)
            deep.add_done_callback(_background_tasks.discard)
            data = {"merged_by_type": local_mbt, "total": local_total,
                    "verified": {"checked": 0, "removed": local_dead_hidden,
                                 "deduped": local_deduped,
                                 "clean_hidden": local_clean_hidden,
                                 "source": "local"}}
            if local_total:
                _record_history(username, keyword, src, data)
            _record_event(ip, keyword, src, data)
            check_abuse(ip, keyword, username)
            metrics.search_total += 1
            metrics.search_local += 1
            payload = {"code": 0, "data": data}
            return Response(
                content=json.dumps(payload, ensure_ascii=False).encode(),
                status_code=200,
                headers={"content-type": "application/json",
                         "X-Source": "local-cache"})

    # ===== 本地不足 / miss：回源 PanSou（原完整流程） =====
    # 方案A：海外磁力查询与核心回源并发（原为核心返回后串行 await）。
    # _fetch_magnets 内部已全量 try/except 并带 10s 硬顶，失败返 {}，
    # 磁力路任何超时/报错都不会阻塞或拖垮核心主响应。
    mag_task = None
    if keyword:
        mag_task = asyncio.create_task(_fetch_magnets(keyword))
        _background_tasks.add(mag_task)
        mag_task.add_done_callback(_background_tasks.discard)
    # 熔断打开：不发起长等待请求，直接尝试本地 FTS 兜底，避免单 worker 被超时拖垮
    if not cb.allow():
        metrics.upstream_short += 1
        fb = _local_fallback_response(local_mbt, username, keyword, src, ip,
                                      "circuit-open", clean_on)
        if fb is not None:
            return fb
        return JSONResponse(
            {"detail": "上游暂时不可用，已启用本地保护，请稍后重试"},
            status_code=503, headers={"Retry-After": str(CB_OPEN_SEC)})
    try:
        async with httpx.AsyncClient(
                timeout=httpx.Timeout(180.0, connect=15.0)) as client:
            _t0 = time.time()
            upstream = await client.request(
                request.method, target_url,
                headers=_fwd_headers(request), content=body)
        metrics.upstream_calls += 1
        metrics.record_latency((time.time() - _t0) * 1000)
        if upstream.status_code >= 500:
            cb.record_failure()
            metrics.upstream_fail += 1
        else:
            cb.record_success()
            metrics.upstream_ok += 1
        content = upstream.content
        if upstream.status_code == 200 and keyword:
            payload = json.loads(content.decode("utf-8"))
            if payload.get("code") == 0:
                data = payload.setdefault("data", {})
                mbt = data.get("merged_by_type") or {}

                # 档2：海外英文磁力源（apibay/yts），失败不影响主流程
                # 方案A：任务在核心回源发出时已并发启动，此处取其结果（已完成则立即返回）
                try:
                    ext = await mag_task if mag_task is not None else {}
                    ext_m = ext.get("magnet") or []
                    if ext_m:
                        seen = {u.get("url") for u in (mbt.get("magnet") or [])}
                        ext_m = [it for it in ext_m if it.get("url") not in seen]
                        if ext_m:
                            mbt["magnet"] = ext_m + (mbt.get("magnet") or [])
                            # PanSou 0 结果时 data 无 merged_by_type 键，需写回
                            data.setdefault("merged_by_type", mbt)
                except Exception as e:
                    logger.warning("magnet inject error: %s", e)
                # 域名复核：插件自报类型与链接域名冲突时以域名为准
                mbt = _rebucket_by_domain(mbt)
                # 方案一：主词供给不足时按需多路变体召回（仅 GET + 全源），合并后统一净化
                v_count = v_added = 0
                if (QUERY_REWRITE_ENABLED and request.method == "GET"
                        and src in ("", "all")
                        and _mbt_url_count(mbt) < QUERY_REWRITE_MIN_HITS):
                    try:
                        extra_mbt, v_count, v_added = await _multi_recall(
                            keyword)
                        if extra_mbt and v_added:
                            for d, its in extra_mbt.items():
                                mbt[d] = list(mbt.get(d, [])) + list(its)
                    except Exception as e:
                        logger.warning("multi recall error: %s", e)
                        v_count = v_added = 0
                # C：同版本标题指纹去重，削减模板化批量堆量的雷同链接
                mbt, deduped = _dedup_mbt(mbt)
                data["merged_by_type"] = mbt
                # 展平按 URL 去重；排序键 = 画质分 × 来源健康度系数（C 只调序不删除）
                best = {}
                for items in mbt.values():
                    for it in items:
                        u = (it.get("url") or "").strip()
                        if not u:
                            continue
                        s = effective_score(it)
                        if u not in best or s > best[u][1]:
                            best[u] = (u, s)
                ranked = sorted(best.values(), key=lambda x: x[1],
                                reverse=True)
                # A：每个网盘类型保底、再全局补足的首屏同步验证窗口
                check_urls = _select_check_urls(mbt, [u for u, _ in ranked])
                url_source = _url_source_map(mbt)
                if check_urls:
                    fresh_pending = _pending(check_urls)
                    async with httpx.AsyncClient(
                            timeout=httpx.Timeout(VERIFY_TIMEOUT + 2),
                            follow_redirects=True) as vclient:
                        verdict = await verify_urls(check_urls, vclient)
                    # 仅对本次新检测结果落库/累计健康度，缓存命中项不重复计数
                    fresh_verdict = {u: verdict[u] for u in fresh_pending
                                     if u in verdict}
                    _record_verdicts(fresh_verdict, url_source)
                    url_drive = {(it.get("url") or "").strip(): d
                                 for d, its in mbt.items() for it in its}
                    for u, st in fresh_verdict.items():
                        metrics.record_verify(url_drive.get(u, "unknown"), st)
                # A+B：本次新判死链 + 历史已确认死链统一剔除（含持久化结果）
                mbt, removed = _filter_dead_mbt(mbt)
                clean_hidden = 0
                if clean_on:
                    mbt, clean_hidden = _apply_clean_filter(mbt, keyword)
                data["merged_by_type"] = mbt
                data["total"] = sum(
                    len(v) for v in data.get("merged_by_type", {}).values())
                data["verified"] = {
                    "checked": len(check_urls), "removed": removed,
                    "deduped": deduped, "source": "upstream",
                    "clean_hidden": clean_hidden,
                    "variants": v_count, "recalled": v_added}
                metrics.search_total += 1
                metrics.search_upstream += 1
                if v_added:
                    metrics.variant_recalled += v_added
                # B：首屏不等待，后台把该词剩余链接全量验证，死链下次刷新自动消失
                deep = asyncio.create_task(
                    _bg_deep_verify(keyword, data["merged_by_type"]))
                _background_tasks.add(deep)
                deep.add_done_callback(_background_tasks.discard)
                # 0 结果不写入用户个人历史（避免污染历史列表）；
                # 但 events 仍记录（匿名用量/限流/统计需要完整搜索行为）。
                if data.get("total"):
                    _record_history(username, keyword, src, data)
                _record_event(ip, keyword, src, data)
                check_abuse(ip, keyword, username)
                # 回源结果异步回填索引（下次该词本地命中、秒开）
                if FTS_ENABLED and data.get("total"):
                    asyncio.create_task(
                        _fts_backfill(keyword, data["merged_by_type"]))
                content = json.dumps(payload, ensure_ascii=False).encode()
        ctype = upstream.headers.get("content-type", "application/json")
        return Response(content=content, status_code=upstream.status_code,
                        headers={"content-type": ctype})
    except httpx.RequestError as e:
        logger.warning("search upstream error: %s", e)
        cb.record_failure()
        metrics.upstream_fail += 1
        fb = _local_fallback_response(local_mbt, username, keyword, src, ip,
                                      "upstream-error", clean_on)
        if fb is not None:
            return fb
        return JSONResponse({"detail": "搜索服务暂时不可用，请稍后重试"},
                            status_code=502)


# ---------------- 路由：/api/* ----------------
@app.api_route("/api/{path:path}",
               methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy_api(path: str, request: Request):
    username = require_user(request)
    if path == "search" and request.method == "GET":
        return await _search_proxy(request, username)
    return await _stream_proxy(request, "api/" + path)


@app.get("/portal/health")
async def health():
    return {"ok": True, "service": "pansou-portal", "mode": "longtoken",
            "version": APP_VERSION,
            "circuit": cb.snapshot()["state"],
            "mcp": MCP_ENABLED,
            "upstream": UPSTREAM}


# ---------------- 海报图片代理（墙内回源 + 磁盘缓存） ----------------
def _poster_base_host(host):
    host = (host or "").lower().split(":")[0]
    return host


def _poster_allowed(host):
    host = _poster_base_host(host)
    return any(host == b or host.endswith("." + b) for b in POSTER_HOSTS)


def _poster_use_proxy(host):
    host = _poster_base_host(host)
    return any(host == b or host.endswith("." + b) for b in POSTER_PROXY_HOSTS)


def _poster_referer(host):
    # doubanio 有防盗链：无 Referer 返回 418，需带豆瓣来源
    host = _poster_base_host(host)
    if host.endswith("doubanio.com"):
        return "https://movie.douban.com/"
    return ""


@app.get("/portal/img")
async def poster_img(u: str):
    # 不做登录校验：海报由 <img src> 加载，浏览器图片请求不会携带 JWT，
    # 强制鉴权会导致全部海报 401 裂图。已用 POSTER_HOSTS 域名白名单 + scheme
    # 校验防 SSRF（不能访问内网），未授权者最多只能代理白名单图床的公开图片。
    if not u:
        return Response(status_code=400)
    try:
        parsed = urlparse(u)
    except Exception:
        return Response(status_code=400)
    if parsed.scheme not in ("http", "https") or not _poster_allowed(parsed.netloc):
        return Response(status_code=403)

    key = hashlib.sha256(u.encode("utf-8")).hexdigest()
    cpath = os.path.join(POSTER_CACHE_DIR, key)
    mpath = cpath + ".meta"
    # 命中磁盘缓存
    if os.path.exists(cpath) and os.path.exists(mpath):
        try:
            age = time.time() - os.path.getmtime(cpath)
            if age < POSTER_CACHE_TTL:
                blob = open(cpath, "rb").read()
                ctype = open(mpath, "r", encoding="utf-8").read().strip() or "image/jpeg"
                return Response(content=blob, media_type=ctype, headers={
                    "Cache-Control": "public, max-age=86400",
                    "X-Poster-Cache": "HIT"})
        except Exception:
            pass

    proxy = POSTER_PROXY if _poster_use_proxy(parsed.netloc) else None
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(12.0, connect=6.0),
                                     follow_redirects=True,
                                     proxy=proxy) as client:
            resp = await client.get(
                u, headers={"User-Agent": UA,
                            "Referer": _poster_referer(parsed.netloc),
                            "Accept": "image/avif,image/webp,image/*,*/*;q=0.8"})
            if resp.status_code != 200 or not resp.content:
                return Response(status_code=502)
            if len(resp.content) > POSTER_MAX_BYTES:
                return Response(status_code=502)
            ctype = resp.headers.get("content-type", "image/jpeg").split(";")[0].strip()
            if not ctype.startswith("image/"):
                ctype = "image/jpeg"
            blob = resp.content
    except Exception:
        return Response(status_code=504)

    # 写磁盘缓存（失败不影响本次响应）
    try:
        os.makedirs(POSTER_CACHE_DIR, exist_ok=True)
        with open(cpath + ".tmp", "wb") as f:
            f.write(blob)
        with open(mpath + ".tmp", "w", encoding="utf-8") as f:
            f.write(ctype)
        os.replace(cpath + ".tmp", cpath)
        os.replace(mpath + ".tmp", mpath)
    except Exception:
        pass

    return Response(content=blob, media_type=ctype, headers={
        "Cache-Control": "public, max-age=86400",
        "X-Poster-Cache": "MISS"})


# ---------------- 公开热搜（无需登录，仅返回词+次数） ----------------
@app.get("/portal/api/public/hot")
async def public_hot():
    week_cut = time.strftime(
        "%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - 7 * 86400))
    with db() as conn:
        hot = conn.execute(
            """SELECT keyword, COUNT(*) n FROM history
               WHERE ts>=? GROUP BY keyword ORDER BY n DESC, MAX(ts) DESC
               LIMIT 10""", (week_cut,)).fetchall()
    return {"hot": [{"keyword": r["keyword"], "c": r["n"]} for r in hot]}


# ---------------- 全网热榜（豆瓣移动端 rexxar，直连，服务端缓存） ----------------
# movie.douban.com 的 j/search_subjects 已被边缘风控：DNS/TCP/TLS 均正常，却在 TLS
# 握手后静默丢弃应用层响应（HTTP 000 读取超时），首页等同域接口一并不可用。改用仍
# 开放的移动端 m.douban.com/rexxar/api/v2：电影热门取 /movie/hot_gaia，剧集热门取
# /subject_collection/tv_hot/items。rexxar 强制校验 iOS UA + m 站 Referer，裸请求被拒。
TRENDING_CACHE = {"ts": 0.0, "data": None}
TRENDING_TTL = 6 * 3600
DOUBAN_UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) "
             "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1")
REXXAR_BASE = "https://m.douban.com/rexxar/api/v2"
REXXAR_HEADERS = {
    "User-Agent": DOUBAN_UA,
    "Referer": "https://m.douban.com/",
    "Accept": "application/json, text/plain, */*",
}


def _map_rexxar_subject(it: dict) -> dict:
    """把 rexxar 条目归一化成前端热搜契约（title/rate/ep/cover/url），缺字段安全降级。"""
    rating = it.get("rating") or {}
    value = rating.get("value")
    pic = it.get("pic") or {}
    sid = str(it.get("id") or "").strip()
    return {
        "title": it.get("title", "") or "",
        "rate": (str(value) if value else ""),
        "ep": it.get("episodes_info", "") or "",
        "cover": pic.get("large") or pic.get("normal") or "",
        # 豆瓣电影与剧集网页统一走 /subject/{id}/ 详情页
        "url": ("https://movie.douban.com/subject/%s/" % sid) if sid else "",
    }


async def _douban_subjects(typ: str, client: httpx.AsyncClient, limit: int = 10):
    if typ == "tv":
        path = REXXAR_BASE + "/subject_collection/tv_hot/items"
        list_key = "subject_collection_items"
    else:
        path = REXXAR_BASE + "/movie/hot_gaia"
        list_key = "items"
    r = await client.get(path, params={"count": limit}, headers=REXXAR_HEADERS)
    r.raise_for_status()
    rows = r.json().get(list_key) or []
    return [_map_rexxar_subject(it) for it in rows[:limit] if isinstance(it, dict)]


@app.get("/portal/api/public/trending")
async def public_trending():
    now = time.time()
    c = TRENDING_CACHE
    if c["data"] and now - c["ts"] < TRENDING_TTL:
        return dict(c["data"], cached=True)
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(8.0, connect=5.0)) as client:
            movies, tv = await asyncio.gather(
                _douban_subjects("movie", client),
                _douban_subjects("tv", client),
                return_exceptions=True)
        movies = movies if isinstance(movies, list) else []
        tv = tv if isinstance(tv, list) else []
        data = {"movies": movies, "tv": tv}
        if movies or tv:
            c["ts"], c["data"] = now, data
        return dict(data, cached=False)
    except Exception:
        if c["data"]:
            return dict(c["data"], cached=True, stale=True)
        return {"movies": [], "tv": [], "cached": False}


# ---------------- 失效海报豆瓣补全（按片名查封面，持久缓存） ----------------
# 上游 Telegram CDN 海报（telesco.pe）大量源文件 404 失效，前端按片名兜底查豆瓣封面。
# doubanio 封面已在 POSTER_HOSTS 白名单，前端会经 /portal/img 代理（带 Referer 防盗链）。
_FB_MEM = {}
_FB_HIT_TTL = 90 * 86400     # 命中封面缓存 90 天
_FB_MISS_TTL = 10 * 60       # 普通 miss 缓存 10 分钟（复杂查询真无片）
_FB_SOFT_TTL = 90            # 疑似限流的"软 miss"仅缓存 90 秒，窗口过后快速重试
_FB_MAX_BATCH = 24           # 单次最多处理片名数
_FB_REQ_GAP = 0.8            # 豆瓣请求间隔（suggest 限流敏感）
_FB_BACKOFF_GAP = 2.2        # 一次调用内连续空结果（疑似限流）时的退避间隔
_FB_HTTP_BUDGET = 14         # 单次调用最多发起的豆瓣 HTTP 请求数（按 root 分组后通常远低于此）

# 出现即截断的"技术参数"词（这些词之后基本是画质/集数/编码，不再是片名）
_FB_CUT_PATTERNS = [
    r"4\s*[Kk]", r"2160\s*[pP]", r"1080\s*[pP]", r"720\s*[pP]", r"\bHD\b",
    r"蓝光", r"原盘", r"[Rr]emux", r"WEB[- ]?DL", r"\bWEB\b", r"DSNP", r"\bNF\b",
    r"杜比视界", r"杜比", r"[Dd]olby", r"[Dd]TS", r"[Tt]rueHD", r"[Aa]tmos",
    r"HDR", r"[XxHh]26[45]", r"HEVC", r"10\s*bit", r"[Aa]ac",
    r"国粤双语", r"国英双语", r"双语", r"国语", r"粤语", r"中文字幕", r"简中", r"繁中",
    r"中字", r"内封", r"外挂", r"纯净版", r"完整版", r"收藏版", r"修复版",
    r"加长版", r"导演剪辑", r"未删减", r"未删", r"补档", r"补全", r"补齐",
    r"缺集", r"臻彩", r"全集", r"全\s*[一二三四五六七八九十两\d]+\s*季",
    r"全\s*\d+\s*集", r"共\s*\d+\s*集", r"\d+\s*集全", r"更新至",
    r"第\s*[\d一二三四五六七八九十]+\s*[集期]", r"(?<![\d])\d{1,3}\s*集",
    r"[Ee]\d{2,3}", r"\d+\s*[Gg][Bb]", r"[\d.]+\s*[Mm][Bb]",
    r"百度网盘", r"夸克", r"阿里云盘", r"迅雷", r"天翼云盘", r"115网盘",
]
_FB_DROP_WORDS = ["两季全", "两季", "全季", "合集", "高清", "超清",
                  "已完结", "完结", "网盘", "资源", "国剧", "美剧", "韩剧",
                  "日剧", "港剧", "台剧", "动漫", "综艺", "电影", "电视剧"]


def _season_cn(sm):
    n = int(sm.group(1))
    cn = {1: "一", 2: "二", 3: "三", 4: "四", 5: "五", 6: "六",
          7: "七", 8: "八", 9: "九", 10: "十"}
    return "第" + (cn.get(n, str(n)) if n <= 10 else str(n)) + "季"


def clean_title(note: str):
    """网盘资源标题 → (豆瓣查询词, 年份)。只做清洗，不做补全。"""
    s = (note or "").strip()
    if not s:
        return "", ""
    # 先剥 URL/域名残留（磁力发布标题常带 dygod.org 等站点域名，污染 root 与豆瓣查询）；
    # 主体限定 ASCII、TLD 走常见后缀白名单（避免误删 4K.HDR 这类点号画质词），遇中文即停
    s = re.sub(
        r"https?://[A-Za-z0-9.\-]+(?:/[^\s]*)?|"
        r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\."
        r"(?:com|cn|net|org|me|app|xyz|top|cc|io|tv|info|club|site|live|pro|vip)"
        r"(?:/[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]*)?",
        " ", s, flags=re.IGNORECASE)
    s = re.sub(r"^\s*(资源名称|文件名称|文件名|名称|资源名)\s*[:：]\s*", "", s)
    # 去掉开头的【】/[] 标签（可能多个）
    for _ in range(4):
        s = re.sub(r"^\s*[【\[][^】\]]*[】\]]\s*", "", s)
    # 去掉开头的分类前缀："短剧：""国剧 "等
    s = re.sub(r"^\s*(短剧|电影|电视剧|国剧|美剧|韩剧|日剧|港剧|台剧|动漫|综艺)\s*[:：.\-\s]+",
               "", s)
    # 斜杠/竖线分隔的多个别名（"庆余年 第二季 / 庆余年2"），取第一个
    s = re.split(r"\s*[\/｜|]\s*", s, 1)[0]
    # 年份：合集区间取较早年份；否则取最后一个年份
    year = ""
    if re.search(r"(19\d{2}|20\d{2})\s*[-—~至]\s*(?:19\d{2}|20\d{2})", s):
        year = re.search(r"(19\d{2}|20\d{2})", s).group(1)
    else:
        ys = re.findall(r"(?:19\d{2}|20\d{2})", s)
        if ys:
            year = ys[-1]
    # Season 2 / S2 → 第二季（保留季信息，避免"庆余年2"误匹配到第一季）
    s = re.sub(r"[Ss]eason\s*(\d{1,2})", _season_cn, s)
    s = re.sub(r"(?<![\d])S(\d{1,2})(?![\d])", _season_cn, s)
    # 在最早出现的技术参数词处截断
    cut = len(s)
    for pat in _FB_CUT_PATTERNS:
        m = re.search(pat, s)
        if m and m.start() < cut:
            cut = m.start()
    s = s[:cut]
    # 删除残留括号块、方括号块、年份
    s = re.sub(r"[（(][^）)]*[）)]", " ", s)
    s = re.sub(r"[【\[][^】\]]*[】\]]", " ", s)
    s = re.sub(r"(?:19\d{2}|20\d{2})", " ", s)
    for w in _FB_DROP_WORDS:
        s = s.replace(w, " ")
    # 仅保留中日韩文字、字母、数字、空格、间隔号、连字符
    s = re.sub(r"[^\u4e00-\u9fffA-Za-z0-9\s·\-]", " ", s)
    s = re.sub(r"\s+", " ", s).strip(" -_/|·")
    return s, year


def _fb_root(q: str):
    """从清洗后的查询词提取"根片名"：首个空格/连字符分段（丢弃演员名、类型词、
    版本后缀如'真彩'），但保留'第X季'。用于豆瓣兜底查询与缓存键归一——
    同一部剧的不同资源标题都归到同一 root，一次搜索只查一次豆瓣。"""
    s = (q or "").strip()
    if not s:
        return ""
    head = re.split(r"[\s\-]+", s, 1)[0]
    m = re.search(r"第[一二三四五六七八九十百\d]{1,3}季", s)
    if m and m.group(0) not in head:
        head = head + " " + m.group(0)
    return head or s


def _fb_root_is_short(root: str):
    """去掉季信息后的根片名长度 2~8：干净短片名 suggest 通常有结果，
    这种查询空了更可能是限流，走软 miss 快速重试。"""
    core = re.sub(r"第[一二三四五六七八九十百\d]{1,3}季", "", root).strip()
    return 2 <= len(core) <= 8


def _fb_norm_title(t: str):
    """归一化标题用于相似度比较：去空格、去'第X季/季'。"""
    t = (t or "").replace(" ", "")
    t = re.sub(r"第[一二三四五六七八九十百\d]+季", "", t)
    t = t.replace("季", "")
    return t


def _fb_pick(arr, q: str, year: str):
    """从豆瓣 suggest 结果里挑最匹配的一条。"""
    qn = _fb_norm_title(q)
    best, best_score = None, -1.0
    for it in arr:
        img = it.get("img") or ""
        if not img:
            continue
        tn = _fb_norm_title(it.get("title", ""))
        score = difflib.SequenceMatcher(None, qn, tn).ratio() * 4
        if qn and (qn in tn or tn in qn):
            score += 10
        iy = (it.get("year") or "").strip()
        if year and iy:
            try:
                if int(iy) == int(year):
                    score += 3
                elif abs(int(iy) - int(year)) <= 1:
                    score += 1
            except ValueError:
                pass
        if score > best_score:
            best, best_score = it, score
    return best


def _normalize_douban_cover_url(u: str) -> str:
    """rexxar 词条返回的是带时效签名的 qnmob3-sign 压缩小图（query 含 sa_cv/sa_ct，
    过期即失效且分辨率低）。提取其 /view/photo/ 对象路径，改写为 img3 无签名大图，
    与热榜封面同一稳定图床（门脸 /portal/img 会自动补豆瓣 Referer 绕防盗链），
    便于持久缓存而不会因签名过期裂图。"""
    try:
        p = urlparse(u)
        if p.netloc.endswith("doubanio.com") and p.path.startswith("/view/photo/"):
            return "https://img3.doubanio.com" + p.path
    except Exception:
        pass
    return u


async def _douban_suggest_cover(q: str, client: httpx.AsyncClient, year: str = ""):
    # movie.douban.com/j/subject_suggest 与热榜接口同域，已被边缘风控（HTTP 000）。
    # 改用移动端 rexxar 词条搜索 type=subject，取 subjects.items[].target 归一化后，
    # 仍交给原有 _fb_pick 做片名/年份相关性打分，缓存与软 miss 行为保持不变。
    try:
        r = await client.get(REXXAR_BASE + "/search",
                             params={"type": "subject", "q": q, "count": 10},
                             headers=REXXAR_HEADERS)
        if r.status_code != 200:
            return None
        data = r.json()
    except Exception:
        return None
    cells = ((data.get("subjects") or {}).get("items")) or []
    arr = []
    for cell in cells:
        if not isinstance(cell, dict):
            continue
        t = cell.get("target") or {}
        if not isinstance(t, dict) or not t.get("title"):
            continue
        cover = t.get("cover_url") or ""
        rv = t.get("rating")
        rate = ""
        if isinstance(rv, dict):
            v = rv.get("value")
            if isinstance(v, (int, float)):
                rate = "%g" % v
            elif v:
                rate = str(v)
        elif rv:
            rate = str(rv)
        arr.append({
            "title": t.get("title", "") or "",
            "year": str(t.get("year") or "").strip(),
            "rating": rate,
            "img": _normalize_douban_cover_url(cover) if cover else "",
            "id": str(t.get("id") or "").strip(),
        })
    if not arr:
        return None
    best = _fb_pick(arr, q, year)
    if best is None:
        # 相似度都很低时，只要第一条有图也可接受（rexxar 本身已按相关性排序）
        best = next((x for x in arr if x.get("img")), None)
    if not best or not best.get("img"):
        return None
    # search 摘要在风控降级时可能只给封面/年份而缺评分：用条目 id 补一次 subject 详情，
    # 详情接口稳定返回 rating/year（失败则静默保留摘要结果，不影响封面）。
    sid = (best.get("id") or "").strip()
    if sid and not best.get("rating"):
        try:
            dr = await client.get(REXXAR_BASE + "/subject/" + sid, headers=REXXAR_HEADERS)
            if dr.status_code == 200:
                det = dr.json()
                drv = det.get("rating")
                if isinstance(drv, dict) and drv.get("value"):
                    best["rating"] = ("%g" % drv["value"]) if isinstance(
                        drv["value"], (int, float)) else str(drv["value"])
                if not best.get("year") and det.get("year"):
                    best["year"] = str(det.get("year") or "").strip()
                dcover = det.get("cover_url") or ""
                if dcover and not best.get("img"):
                    best["img"] = _normalize_douban_cover_url(dcover)
        except Exception:
            pass
    return {"cover": best.get("img", ""),
            "title": best.get("title", ""),
            "year": best.get("year", ""),
            "rating": best.get("rating", "")}


def _fb_key(q: str):
    return hashlib.md5(re.sub(r"[\s·\-]", "", q.lower()).encode("utf-8")).hexdigest()


def _fb_ttl_of(e):
    if e.get("cover"):
        return _FB_HIT_TTL
    if e.get("soft"):
        return _FB_SOFT_TTL
    return _FB_MISS_TTL


def _fb_cache_get(tkey: str):
    """命中且未过期返回 dict（cover 可能为空=miss）；无缓存或过期返回 None。"""
    now = time.time()
    e = _FB_MEM.get(tkey)
    if e:
        return e if now - e["ts"] < _fb_ttl_of(e) else None
    with db() as conn:
        r = conn.execute(
            "SELECT cover,title,year,rating,miss,ts FROM poster_fallback WHERE tkey=?",
            (tkey,)).fetchone()
    if r:
        e = {"cover": r["cover"], "title": r["title"], "year": r["year"],
             "rating": r["rating"] or "",
             "miss": r["miss"], "ts": r["ts"], "soft": 0}
        if now - r["ts"] < _fb_ttl_of(e):
            _FB_MEM[tkey] = e
            return e
    return None


def _fb_cache_set(tkey: str, q: str, info, soft=False):
    """soft=True 为疑似限流的软 miss：只写内存短缓存（90s），不污染持久库。"""
    now = time.time()
    e = {"cover": (info or {}).get("cover", ""),
         "title": (info or {}).get("title", ""),
         "year": (info or {}).get("year", ""),
         "rating": (info or {}).get("rating", ""),
         "miss": 0 if info and info.get("cover") else 1,
         "soft": 1 if (soft and not (info and info.get("cover"))) else 0,
         "ts": now}
    _FB_MEM[tkey] = e
    if e["soft"]:
        return
    try:
        with db() as conn:
            conn.execute(
                """INSERT INTO poster_fallback(tkey,qtitle,cover,title,year,rating,miss,ts)
                   VALUES(?,?,?,?,?,?,?,?)
                   ON CONFLICT(tkey) DO UPDATE SET qtitle=excluded.qtitle,
                     cover=excluded.cover,title=excluded.title,year=excluded.year,
                     rating=excluded.rating,miss=excluded.miss,ts=excluded.ts""",
                (tkey, q, e["cover"], e["title"], e["year"], e["rating"],
                 e["miss"], now))
    except Exception:
        pass


@app.post("/portal/api/poster-fallback")
async def poster_fallback(request: Request):
    """批量按片名补全豆瓣封面。入参 {"titles":[资源标题,...]}，出参 {"covers":{原标题:封面URL}}。"""
    require_user(request)
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    raw_titles = payload.get("titles") if isinstance(payload, dict) else None
    if not isinstance(raw_titles, list):
        return {"covers": {}, "meta": {}}
    seen, uniq = set(), []
    for t in raw_titles:
        t = str(t).strip()
        if not t or t in seen:
            continue
        seen.add(t)
        uniq.append(t)
    uniq = uniq[:_FB_MAX_BATCH]

    # 按根片名分组：同一部剧的多种资源标题（带画质/演员/版本后缀）归到一个 root，
    # 一次搜索对每部剧只查一次豆瓣，封面回填给组内所有原始标题。
    groups = {}          # tkey -> {root,q,year,raws[]}
    order = []
    for raw in uniq:
        q, year = clean_title(raw)
        if not q or len(q) > 40:
            continue
        root = _fb_root(q)
        if not root:
            continue
        tkey = _fb_key(root)
        g = groups.get(tkey)
        if g is None:
            g = {"root": root, "q": q, "year": year, "raws": []}
            groups[tkey] = g
            order.append(tkey)
        g["raws"].append(raw)
        # 保留最长的清洗词作为完整查询（信息最全，利于精准命中副标题）
        if len(q) > len(g["q"]):
            g["q"], g["year"] = q, year

    covers = {}
    meta = {}            # 原标题 -> {cover,year,rating}，与封面同一次补全、共用缓存
    http_used = 0          # 本次已发起的豆瓣 HTTP 请求数
    short_empty = 0        # 连续"干净短片名也空"的 root 数（疑似限流信号）
    async with httpx.AsyncClient(timeout=httpx.Timeout(8.0, connect=5.0)) as client:
        async def ask(kw, yy):
            nonlocal http_used
            if http_used >= _FB_HTTP_BUDGET:
                return None
            # 连续多个短片名查空 → 已触发限流，退避后再发，避免继续被限流
            if short_empty >= 2:
                await asyncio.sleep(_FB_BACKOFF_GAP)
            else:
                await asyncio.sleep(_FB_REQ_GAP)
            try:
                info = await _douban_suggest_cover(kw, client, yy)
            except Exception:
                info = None
            http_used += 1
            return info

        for tkey in order:
            g = groups[tkey]
            root, q, year = g["root"], g["q"], g["year"]
            cached = _fb_cache_get(tkey)
            if cached is None:
                info = None
                # 1) 完整清洗词（含副标题，如"蜘蛛侠 纵横宇宙"），精准优先
                if q.strip() != root.strip():
                    info = await ask(q, year)
                # 2) 完整词无果或本就等于 root → 查根片名（去掉演员名/类型噪声）
                if not info:
                    info = await ask(root, year)
                # 3) rexxar 对带空格的中文季查询（如"庆余年 第二季"）会间歇 403：
                #    去掉" 第X季"后缀用纯片名再查一次，由 _fb_pick 按年份选中正确季。
                bare = re.sub(r"第[一二三四五六七八九十百\d]{1,3}季", "", root).strip()
                if not info and bare and bare != root.strip():
                    info = await ask(bare, year)
                if info:
                    _fb_cache_set(tkey, root, info)
                    short_empty = 0
                else:
                    # 干净短片名查空大概率是限流（空数组与真无无法区分）→ 软 miss 90s；
                    # 复杂长查询查空更可能是真无 → 普通 miss 10 分钟
                    soft = _fb_root_is_short(root)
                    if soft:
                        short_empty += 1
                    _fb_cache_set(tkey, root, None, soft=soft)
                cached = _fb_cache_get(tkey)
            if cached and cached.get("cover"):
                for raw in g["raws"]:
                    covers[raw] = cached["cover"]
                    meta[raw] = {
                        "cover": cached.get("cover", ""),
                        "year": cached.get("year", ""),
                        "rating": cached.get("rating", ""),
                    }
    return {"covers": covers, "meta": meta}


# ---------------- 登录 / 当前用户 ----------------
def _login_gate(ip: str):
    """登录防爆破：窗口内失败超限则锁定，锁定期间直接拒绝。"""
    t = time.time()
    until = _login_locks.get(ip, 0)
    if until > t:
        wait = int(until - t)
        raise _AuthError(429, {"detail": f"失败次数过多，请 {wait} 秒后再试"})
    if until:
        _login_locks.pop(ip, None)
    cut = t - LOGIN_WINDOW_SEC
    fails = [x for x in _login_fails.get(ip, []) if x > cut]
    _login_fails[ip] = fails
    if len(fails) >= LOGIN_MAX_FAIL:
        _login_locks[ip] = t + LOGIN_LOCK_SEC
        _login_fails.pop(ip, None)
        # 复用告警通道，记录爆破尝试（不影响主流程）
        try:
            maybe_alert(ip, f"登录连续失败 {LOGIN_MAX_FAIL} 次，已临时锁定")
        except Exception:
            pass
        metrics.login_lock += 1
        raise _AuthError(429, {"detail": f"失败次数过多，请 {LOGIN_LOCK_SEC} 秒后再试"})


def _login_failed(ip: str, username: str = ""):
    _login_fails.setdefault(ip, []).append(time.time())
    cut = time.time() - LOGIN_WINDOW_SEC
    n = len([x for x in _login_fails.get(ip, []) if x > cut])
    # 达到预警阈值（且尚未到锁定阈值）先 Bark 提醒一次；锁定由 _login_gate 另行告警
    if 0 < LOGIN_WARN_FAIL < LOGIN_MAX_FAIL and n == LOGIN_WARN_FAIL:
        metrics.login_warn += 1
        who = f"账号 {username} " if username else ""
        _security_notify(
            ip, "login_warn", "觅影·登录失败预警",
            f"{who}连续 {n} 次密码错误（IP {ip}），达 {LOGIN_MAX_FAIL} 次将临时锁定")


@app.post("/portal/api/auth/login")
async def login(request: Request):
    ip = client_ip(request)
    _login_gate(ip)  # 先过防爆破闸门
    payload = await _json_body(request)
    u = (payload.get("username") or "").strip()
    p = payload.get("password") or ""
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username=?",
                           (u,)).fetchone()
    if (row and row["enabled"] == 1
            and verify_password(p, row["salt"], row["pwd_hash"])):
        _login_fails.pop(ip, None)  # 登录成功，清除失败计数
        _login_locks.pop(ip, None)
        _note_login_seen_ip(u, ip, row["role"])  # 新网段登录：管理员推送/普通账号仅记录
        return {"token": make_token(u), "username": u,
                "is_admin": row["role"] == "admin",
                "ttl_days": TOKEN_TTL_DAYS}
    _login_failed(ip, u)
    raise _AuthError(401, {"detail": "账号或密码错误"})


@app.get("/portal/api/me")
async def me(request: Request):
    u = require_user(request)
    return {"username": u, "is_admin": get_role(u) == "admin"}


# ---------------- 历史 ----------------
@app.get("/portal/api/history")
async def list_history(request: Request):
    u = require_user(request)
    with db() as conn:
        rows = conn.execute(
            """SELECT keyword, COUNT(*) cnt, MAX(ts) last_ts,
                      (SELECT total FROM history h2 WHERE h2.username=h1.username
                        AND h2.keyword=h1.keyword ORDER BY h2.id DESC LIMIT 1)
                        AS last_total,
                      (SELECT counts FROM history h2 WHERE h2.username=h1.username
                        AND h2.keyword=h1.keyword ORDER BY h2.id DESC LIMIT 1)
                        AS last_counts,
                      (SELECT src FROM history h2 WHERE h2.username=h1.username
                        AND h2.keyword=h1.keyword ORDER BY h2.id DESC LIMIT 1)
                        AS last_src
               FROM history h1 WHERE username=?
               GROUP BY keyword ORDER BY last_ts DESC LIMIT 200""",
            (u,)).fetchall()
    items = []
    for r in rows:
        row = dict(r)
        # 库内为 UTC naive，统一带 +08:00 输出，前端显示「刚刚/X 分钟前」不再差 8 小时
        row["last_ts"] = _iso_bj(row.get("last_ts"))
        items.append(row)
    return {"items": items}


@app.delete("/portal/api/history/{kw}")
async def delete_history_kw(kw: str, request: Request):
    u = require_user(request)
    with db() as conn:
        conn.execute("DELETE FROM history WHERE username=? AND keyword=?",
                     (u, kw))
    return {"ok": True}


@app.delete("/portal/api/history")
async def clear_history(request: Request):
    u = require_user(request)
    with db() as conn:
        conn.execute("DELETE FROM history WHERE username=?", (u,))
    return {"ok": True}


# ---------------- 收藏 ----------------
@app.get("/portal/api/favorites")
async def list_favorites(request: Request):
    u = require_user(request)
    with db() as conn:
        rows = conn.execute(
            "SELECT id,note,drive,url,password,source,ts FROM favorites "
            "WHERE username=? ORDER BY id DESC LIMIT 1000", (u,)).fetchall()
    return {"items": [dict(r) for r in rows]}


@app.post("/portal/api/favorites")
async def add_favorite(request: Request):
    u = require_user(request)
    payload = await _json_body(request)
    url = (payload.get("url") or "").strip()
    if not url:
        raise _AuthError(400, {"detail": "缺少 url"})
    if urlparse(url).scheme.lower() not in ("http", "https"):
        raise _AuthError(400, {"detail": "链接不合法，仅支持网盘分享链接"})
    with db() as conn:
        cur = conn.execute(
            """INSERT INTO favorites(username,note,drive,url,password,source,ts)
               VALUES(?,?,?,?,?,?,?)
               ON CONFLICT(username,url) DO UPDATE SET
                 note=excluded.note,drive=excluded.drive,
                 password=excluded.password,source=excluded.source""",
            (u, payload.get("note", ""), payload.get("drive", ""), url,
             payload.get("password", ""), payload.get("source", ""),
             now_ts()))
        fid = cur.lastrowid
    return {"ok": True, "id": fid}


@app.delete("/portal/api/favorites/{fid}")
async def delete_favorite(fid: int, request: Request):
    u = require_user(request)
    with db() as conn:
        conn.execute("DELETE FROM favorites WHERE id=? AND username=?",
                     (fid, u))
    return {"ok": True}


# ---------------- 管理员统计 ----------------
@app.get("/portal/api/admin/stats")
async def admin_stats(request: Request):
    u = require_admin(request)
    day_start = time.strftime("%Y-%m-%dT00:00:00")
    week_cut = time.strftime(
        "%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - 7 * 86400))
    with db() as conn:
        total = conn.execute("SELECT COUNT(*) c FROM history").fetchone()["c"]
        today = conn.execute(
            "SELECT COUNT(*) c FROM history WHERE ts>=?",
            (day_start,)).fetchone()["c"]
        u_rows = conn.execute(
            """SELECT u.username, u.role, u.enabled,
                      (SELECT COUNT(*) FROM history h WHERE h.username=u.username)
                        AS searches,
                      (SELECT MAX(ts) FROM history h WHERE h.username=u.username)
                        AS last_active
               FROM users u ORDER BY u.id"""
        ).fetchall()
        f_rows = conn.execute(
            "SELECT username,COUNT(*) c FROM favorites GROUP BY username"
        ).fetchall()
        ips = conn.execute(
            """SELECT ip, COUNT(*) n, MAX(ts) last FROM events
               WHERE ts>=? GROUP BY ip ORDER BY n DESC LIMIT 30""",
            (week_cut,)).fetchall()
        hot = conn.execute(
            """SELECT keyword, COUNT(*) n FROM history
               WHERE ts>=? GROUP BY keyword ORDER BY n DESC, MAX(ts) DESC
               LIMIT 20""", (week_cut,)).fetchall()
        alerts = conn.execute(
            "SELECT ip,reason,detail,ts FROM alerts ORDER BY id DESC LIMIT 30"
        ).fetchall()
        fts_arts = conn.execute(
            "SELECT COUNT(*) c FROM idx_arts").fetchone()["c"]
        fts_jobs = conn.execute(
            "SELECT COUNT(*) c FROM idx_jobs").fetchone()["c"]
        dead_n = conn.execute(
            "SELECT COUNT(*) c FROM dead_links").fetchone()["c"]
        src_rows = conn.execute(
            "SELECT source,alive,dead,updated FROM source_health "
            "ORDER BY (alive+dead) DESC LIMIT 30").fetchall()
        watch_rows = conn.execute(
            "SELECT status,COUNT(*) c FROM watch GROUP BY status"
        ).fetchall()
        rss_n = conn.execute("SELECT COUNT(*) c FROM rss_feed").fetchone()["c"]
        seen_ip_n = conn.execute(
            "SELECT COUNT(*) c FROM login_seen_ip").fetchone()["c"]
    ws_map = {r["status"]: r["c"] for r in watch_rows}
    f_map = {r["username"]: r["c"] for r in f_rows}
    users_out = [{
        "username": r["username"], "role": r["role"],
        "is_admin": r["role"] == "admin", "enabled": r["enabled"],
        "search_count": r["searches"], "fav_count": f_map.get(r["username"], 0),
        "last_active": r["last_active"],
    } for r in u_rows]
    def _dir_size(path):
        total = 0
        try:
            for root, _, files in os.walk(path):
                for fn in files:
                    try:
                        total += os.path.getsize(os.path.join(root, fn))
                    except OSError:
                        pass
        except OSError:
            pass
        return total

    db_bytes = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0
    drive_health = sorted((
        {"drive": d, "checked": c, "dead": de,
         "dead_rate": round(de / c, 3) if c else 0.0}
        for d, (c, de) in metrics.drive_checked.items()),
        key=lambda x: x["checked"], reverse=True)
    meta = {
        "version": APP_VERSION,
        "uptime_sec": round(time.time() - metrics.start_ts),
        "circuit": cb.snapshot(),
        "search": {"total": metrics.search_total,
                   "local": metrics.search_local,
                   "upstream": metrics.search_upstream,
                   "fallback": metrics.search_fallback,
                   "variant_recalled": metrics.variant_recalled},
        "upstream": {"calls": metrics.upstream_calls,
                     "ok": metrics.upstream_ok,
                     "fail": metrics.upstream_fail,
                     "short_circuited": metrics.upstream_short,
                     "latency": metrics.latency()},
        "verify": {"checked": metrics.verify_checked,
                   "alive": metrics.verify_alive,
                   "dead": metrics.verify_dead,
                   "unknown": metrics.verify_unknown,
                   "retry_pending": len(_retry_pending),
                   "retry_resolved": metrics.retry_resolved,
                   "retry_giveup": metrics.retry_giveup},
        "drive_health": drive_health,
        "source_health": [
            {**dict(r), "updated_text": _epoch_bj(r["updated"])}
            for r in src_rows],
        "storage": {"db_bytes": db_bytes,
                    "imgcache_bytes": _dir_size(POSTER_CACHE_DIR),
                    "fts_arts": fts_arts, "fts_jobs": fts_jobs,
                    "dead_links": dead_n,
                    "verify_cache": len(_verify_cache)},
        "security": {"login_warn": metrics.login_warn,
                     "login_lock": metrics.login_lock,
                     "login_new_ip": metrics.login_new_ip,
                     "known_ips": seen_ip_n},
        "mcp": {"enabled": MCP_ENABLED,
                "calls": metrics.mcp_calls,
                "errors": metrics.mcp_errors},
        "watch": {"total": sum(ws_map.values()),
                  "by_status": {s: ws_map.get(s, 0) for s in WATCH_STATUSES},
                  "rss_feeds": rss_n},
        "jobs": {name: {"last": jb["last"], "ok": jb["ok"], "info": jb["info"]}
                 for name, jb in metrics.jobs.items()},
    }
    return {
        "version": APP_VERSION,
        "meta": meta,
        "total_searches": total,
        "today_searches": today,
        "users": users_out,
        "by_ip": [dict(r) for r in ips],
        "hot": [{"keyword": r["keyword"], "c": r["n"]} for r in hot],
        "alerts": [dict(r) for r in alerts],
        "thresholds": {"window_sec": RATE_WINDOW_SEC,
                       "window_max": RATE_WINDOW_MAX,
                       "day_max": RATE_DAY_MAX},
        "note": "不展示任何用户的收藏明细",
    }


# ---------------- 用户管理（管理员） ----------------
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")


def _admin_count(conn) -> int:
    return conn.execute(
        "SELECT COUNT(*) c FROM users WHERE role='admin' AND enabled=1"
    ).fetchone()["c"]


@app.get("/portal/api/admin/users")
async def admin_list_users(request: Request):
    require_admin(request)
    with db() as conn:
        rows = conn.execute(
            "SELECT id,username,role,enabled,created_ts,pw_ts FROM users "
            "ORDER BY id").fetchall()
        h = conn.execute(
            "SELECT username, COUNT(*) c FROM history GROUP BY username"
        ).fetchall()
        f = conn.execute(
            "SELECT username, COUNT(*) c FROM favorites GROUP BY username"
        ).fetchall()
    hm = {r["username"]: r["c"] for r in h}
    fm = {r["username"]: r["c"] for r in f}
    out = []
    for r in rows:
        d = dict(r)
        d["search_count"] = hm.get(r["username"], 0)
        d["fav_count"] = fm.get(r["username"], 0)
        d["boot"] = (r["username"] == ADMIN_USER)  # 环境变量兜底管理员，禁止停用/删除/降级
        out.append(d)
    return {"items": out}


@app.post("/portal/api/admin/users")
async def admin_create_user(request: Request):
    require_admin(request)
    p = await _json_body(request)
    username = (p.get("username") or "").strip()
    password = p.get("password") or ""
    role = "admin" if p.get("role") == "admin" else "user"
    if not USERNAME_RE.match(username):
        raise _AuthError(400, {"detail": "用户名需 3-20 位字母/数字/下划线"})
    if len(password) < PASSWORD_MIN:
        raise _AuthError(400, {"detail": f"密码至少 {PASSWORD_MIN} 位"})
    with db() as conn:
        if conn.execute("SELECT id FROM users WHERE username=?",
                        (username,)).fetchone():
            raise _AuthError(400, {"detail": "用户名已存在"})
        salt, hsh = hash_password(password)
        uid = conn.execute(
            """INSERT INTO users(username,salt,pwd_hash,role,enabled,
                 created_ts,pw_ts) VALUES(?,?,?,?,1,?,?)""",
            (username, salt, hsh, role, now_ts(), now_ts())).lastrowid
    return {"ok": True, "id": uid}


@app.post("/portal/api/admin/users/{uid}")
async def admin_update_user(uid: int, request: Request):
    require_admin(request)
    p = await _json_body(request)
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?",
                           (uid,)).fetchone()
        if not row:
            raise _AuthError(404, {"detail": "用户不存在"})
        if "role" in p:
            new_role = "admin" if p["role"] == "admin" else "user"
            if new_role != row["role"] and row["role"] == "admin" \
                    and new_role == "user" and row["enabled"] == 1 \
                    and _admin_count(conn) <= 1:
                raise _AuthError(400, {"detail": "至少保留一个启用的管理员"})
            conn.execute("UPDATE users SET role=? WHERE id=?", (new_role, uid))
        if "enabled" in p:
            new_en = 1 if p["enabled"] else 0
            if new_en != row["enabled"] and row["role"] == "admin" \
                    and new_en == 0 and _admin_count(conn) <= 1:
                raise _AuthError(400, {"detail": "至少保留一个启用的管理员"})
            conn.execute("UPDATE users SET enabled=? WHERE id=?", (new_en, uid))
    return {"ok": True}


@app.post("/portal/api/admin/users/{uid}/password")
async def admin_reset_password(uid: int, request: Request):
    require_admin(request)
    p = await _json_body(request)
    password = p.get("password") or ""
    if len(password) < PASSWORD_MIN:
        raise _AuthError(400, {"detail": f"密码至少 {PASSWORD_MIN} 位"})
    with db() as conn:
        if not conn.execute("SELECT id FROM users WHERE id=?",
                            (uid,)).fetchone():
            raise _AuthError(404, {"detail": "用户不存在"})
        salt, hsh = hash_password(password)
        conn.execute("UPDATE users SET salt=?, pwd_hash=?, pw_ts=? WHERE id=?",
                     (salt, hsh, now_ts(), uid))
    return {"ok": True}


@app.delete("/portal/api/admin/users/{uid}")
async def admin_delete_user(uid: int, request: Request):
    me = require_admin(request)
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?",
                           (uid,)).fetchone()
        if not row:
            raise _AuthError(404, {"detail": "用户不存在"})
        if row["username"] == me:
            raise _AuthError(400, {"detail": "不能删除当前登录账号"})
        if row["username"] == ADMIN_USER:
            raise _AuthError(
                400, {"detail": "环境变量兜底管理员不可删除（重启会自动恢复）"})
        if row["role"] == "admin" and row["enabled"] == 1 \
                and _admin_count(conn) <= 1:
            raise _AuthError(400, {"detail": "至少保留一个启用的管理员"})
        # 级联清理该用户私有数据，避免同名重建账号继承历史/收藏/追剧
        uname = row["username"]
        conn.execute("DELETE FROM favorites WHERE username=?", (uname,))
        conn.execute("DELETE FROM watch WHERE username=?", (uname,))
        conn.execute("DELETE FROM history WHERE username=?", (uname,))
        conn.execute("DELETE FROM users WHERE id=?", (uid,))
    return {"ok": True}


# ---------------- 修改自己的密码 ----------------
@app.post("/portal/api/change-password")
async def change_password(request: Request):
    u = require_user(request)
    p = await _json_body(request)
    old_p = p.get("old_password") or ""
    new_p = p.get("new_password") or ""
    if len(new_p) < PASSWORD_MIN:
        raise _AuthError(400, {"detail": f"新密码至少 {PASSWORD_MIN} 位"})
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username=?",
                           (u,)).fetchone()
        if not row or not verify_password(old_p, row["salt"],
                                          row["pwd_hash"]):
            raise _AuthError(400, {"detail": "原密码不正确"})
        salt, hsh = hash_password(new_p)
        conn.execute("UPDATE users SET salt=?, pwd_hash=?, pw_ts=? "
                     "WHERE username=?", (salt, hsh, now_ts(), u))
    return {"ok": True}


# ---------------- 混合 FTS5 预索引：写入 / 查询 / 清理 ----------------
def _fts_quota_rows(best: dict, cap: int, floor: int):
    """分网盘配额选行，修复"拍平后按上游顺序整体截断"导致靠后网盘被整桶饿死。
    best: {url: (drive, item, score)}（已按 url 去重、同 url 取高分）。
    规则：①每个网盘先保底 min(floor, 该桶条数) 条，round-robin 均匀选取且受 cap
    约束，桶内按画质分降序（稳定，平分保持上游顺序）；②剩余名额再按画质分全局
    降序补满至 cap。返回 [(drive, item, score), ...]，url 唯一。"""
    per_drive, drive_order = {}, []
    for url, (drive, it, sc) in best.items():
        if drive not in per_drive:
            per_drive[drive] = []
            drive_order.append(drive)
        per_drive[drive].append((drive, it, sc))
    for drive in drive_order:
        per_drive[drive].sort(key=lambda x: x[2], reverse=True)
    selected = {}

    def _take(row):
        u = (row[1].get("url") or "").strip()
        if u and u not in selected:
            selected[u] = row

    # ① 每网盘保底：逐轮从每个桶各取 1 条，直到各桶取够 floor 或达到 cap
    for k in range(max(0, floor)):
        for drive in drive_order:
            if len(selected) >= cap:
                break
            lst = per_drive[drive]
            if k < len(lst):
                _take(lst[k])
        if len(selected) >= cap:
            break
    # ② 余量按画质分全局降序补满（sorted 稳定，平分保持桶/上游顺序）
    if len(selected) < cap:
        all_rows = [row for lst in per_drive.values() for row in lst]
        for row in sorted(all_rows, key=lambda x: x[2], reverse=True):
            if len(selected) >= cap:
                break
            _take(row)
    return list(selected.values())


def _fts_upsert(kw: str, mbt: dict):
    """把一次 PanSou 搜索结果（merged_by_type）幂等写入 idx_arts + idx_fts。
    按 url 去重，同 url 保留画质分高的；kw 关联进 kws（一条资源可被多个词命中）。
    选行走 _fts_quota_rows 分网盘保底，避免靠后/大桶网盘被整体截断。"""
    if not FTS_ENABLED:
        return 0
    best = {}
    for drive, items in (mbt or {}).items():
        for it in items:
            url = (it.get("url") or "").strip()
            if not url:
                continue
            sc = quality_score(it)
            if url not in best or sc > best[url][2]:
                best[url] = (drive, it, sc)
    if not best:
        return 0
    rows = _fts_quota_rows(best, FTS_MAX_ARTS_PER_WORD, FTS_PER_DRIVE_FLOOR)
    n = 0
    now = time.time()
    with db() as conn:
        for drive, it, sc in rows:
            url = (it.get("url") or "").strip()
            note = (it.get("note") or "").strip()
            dt = it.get("datetime") or ""
            old = conn.execute(
                "SELECT kws,first_seen FROM idx_arts WHERE url=?",
                (url,)).fetchone()
            kws = []
            if old:
                try:
                    kws = json.loads(old["kws"] or "[]")
                except Exception:
                    kws = []
            if kw not in kws:
                kws.append(kw)
            kws_json = json.dumps(kws, ensure_ascii=False)
            raw = json.dumps(it, ensure_ascii=False)
            if old:
                first_seen = old["first_seen"] or now
                conn.execute(
                    """UPDATE idx_arts SET drive=?,note=?,datetime=?,score=?,
                       raw=?,kws=?,first_seen=?,last_seen=? WHERE url=?""",
                    (drive, note, dt, sc, raw, kws_json, first_seen, now, url))
            else:
                conn.execute(
                    """INSERT INTO idx_arts(url,drive,note,datetime,score,raw,
                       kws,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?)""",
                    (url, drive, note, dt, sc, raw, kws_json, now, now))
            # FTS 幂等：按 url 删旧再插（已验证 UNINDEXED 列可删除）。
            # 索引文本 = 标题 + 关联词（kws）：英文/变体标题也能被中文词命中。
            fts_text = note + " " + " ".join(kws)
            conn.execute("DELETE FROM idx_fts WHERE url=?", (url,))
            conn.execute("INSERT INTO idx_fts(note,url) VALUES(?,?)",
                         (fts_text, url))
            n += 1
    return n


def _fts_remove_url(url: str):
    """资源确认失效时，从索引中移除。"""
    with db() as conn:
        conn.execute("DELETE FROM idx_fts WHERE url=?", (url,))
        conn.execute("DELETE FROM idx_arts WHERE url=?", (url,))


def _fts_local_search(kw: str):
    """本地检索 -> merged_by_type（dict）。
    FTS5 trigram 处理 ≥3 字（rank 相关性），LIKE 兜底短词/子串；结果按前端
    渲染所需的原始 item 还原并按 drive 分组。"""
    kw = (kw or "").strip()
    if not FTS_ENABLED or not kw:
        return {}
    ordered, seen = [], set()
    with db() as conn:
        # 1) FTS5 trigram（≥3 字），按 rank
        if len(kw) >= 3:
            try:
                phrase = '"' + kw.replace('"', '""') + '"'
                for r in conn.execute(
                        "SELECT url FROM idx_fts WHERE idx_fts MATCH ? "
                        "ORDER BY rank LIMIT ?",
                        (phrase, FTS_QUERY_LIMIT)):
                    if r["url"] not in seen:
                        seen.add(r["url"])
                        ordered.append(r["url"])
            except Exception as e:
                logger.warning("fts match error kw=%s: %s", kw, e)
        # 2) LIKE 兜底/补充（短词、子串），转义 % _ \，按画质分；
        #    同时匹配 note 与 kws（JSON），让 2 字短词也能命中关联的英文标题。
        like = kw.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pat = "%" + like + "%"
        for r in conn.execute(
                "SELECT url FROM idx_arts WHERE note LIKE ? ESCAPE '\\' "
                "OR kws LIKE ? ESCAPE '\\' "
                "ORDER BY score DESC, last_seen DESC LIMIT ?",
                (pat, pat, FTS_QUERY_LIMIT)):
            if r["url"] not in seen:
                seen.add(r["url"])
                ordered.append(r["url"])
        # 3) 还原原始 item，按 drive 分组（保持顺序）
        mbt = {}
        for i in range(0, len(ordered), 200):
            chunk = ordered[i:i + 200]
            ph = ",".join("?" * len(chunk))
            rows = conn.execute(
                f"SELECT url,drive,raw FROM idx_arts WHERE url IN ({ph})",
                chunk).fetchall()
            mp = {r["url"]: (r["drive"], r["raw"]) for r in rows}
            for u in chunk:
                if u not in mp:
                    continue
                drive, raw = mp[u]
                try:
                    item = json.loads(raw)
                except Exception:
                    continue
                mbt.setdefault(drive, []).append(item)
    # 读路径统一做域名复核，覆盖历史索引中插件自报类型错误的存量数据
    return _rebucket_by_domain(mbt)


def _fts_purge_stale():
    """清理长期未被刷新的过期条目；返回清理条数。"""
    cut = time.time() - FTS_ART_TTL
    with db() as conn:
        dead = [r["url"] for r in conn.execute(
            "SELECT url FROM idx_arts WHERE last_seen<?", (cut,)).fetchall()]
        for u in dead:
            conn.execute("DELETE FROM idx_fts WHERE url=?", (u,))
            conn.execute("DELETE FROM idx_arts WHERE url=?", (u,))
    return len(dead)


# ---------------- 追剧更新监控 ----------------
async def _internal_search(keyword: str, client: httpx.AsyncClient):
    """后台监控用：直连上游 PanSou 搜索，返回 merged_by_type。"""
    q = urlencode({
        "kw": keyword, "res": "merge", "src": "all",
        "filter": json.dumps({"exclude": DEFAULT_EXCLUDE}, ensure_ascii=False),
    })
    try:
        if not cb.allow():
            raise _CircuitOpen("circuit open")
        _t0 = time.time()
        r = await client.get(f"{UPSTREAM}/api/search?{q}")
        metrics.upstream_calls += 1
        metrics.record_latency((time.time() - _t0) * 1000)
        if r.status_code >= 500:
            cb.record_failure()
            metrics.upstream_fail += 1
            return {}
        cb.record_success()
        metrics.upstream_ok += 1
        payload = r.json()
        if payload.get("code") != 0:
            return {}
        return _rebucket_by_domain(
            payload.get("data", {}).get("merged_by_type") or {})
    except _CircuitOpen:
        # 熔断打开：快速返回空，不发起请求、不占长超时（变体/追剧均容忍空结果）
        metrics.upstream_short += 1
        return {}
    except Exception as e:
        cb.record_failure()
        metrics.upstream_fail += 1
        logger.warning("internal search failed kw=%s: %s", keyword, e)
        return {}


def _flatten_arts(mbt: dict):
    """展平结果 -> [(datetime, note, url, password, drive)]。"""
    out = []
    for drive, items in mbt.items():
        for it in items:
            out.append((
                it.get("datetime") or "",
                it.get("note") or "",
                it.get("url") or "",
                it.get("password") or "",
                drive,
            ))
    return out


def _parse_dt(s):
    """把上游各种 datetime 文本归一化为 epoch；naive 时间按本地时区，无法解析返回 None。
    兼容 "YYYY-MM-DD HH:MM:SS"、ISO(含 T)、Z(UTC)、纯日期，避免跨格式字符串比较错乱。"""
    if not s:
        return None
    s = str(s).strip()
    iso = s.replace("Z", "+00:00").replace(" ", "T")
    dt = None
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        try:
            dt = datetime.strptime(s[:10], "%Y-%m-%d")
        except ValueError:
            return None
    try:
        if dt.tzinfo is None:
            dt = dt.astimezone()
        return dt.timestamp()
    except Exception:
        return None


def _newest_dt(arts):
    """在展平结果里按 epoch 选最新，返回其原始 datetime 字符串（无有效时间返回空串）。"""
    best, best_key = "", None
    for a in arts:
        k = _parse_dt(a[0])
        if k is not None and (best_key is None or k > best_key):
            best, best_key = a[0], k
    return best


async def _watch_baseline(kw: str):
    """立即回源一次建立更新基线，返回 (最新资源时间, 资源总数)。失败不阻断登记。"""
    try:
        async with httpx.AsyncClient(
                timeout=httpx.Timeout(60.0, connect=15.0)) as client:
            arts = _flatten_arts(await _internal_search(kw, client))
            if arts:
                return _newest_dt(arts), len(arts)
    except Exception as e:
        logger.warning("watch baseline failed for %s: %s", kw, e)
    return "", 0


@app.get("/portal/api/bark/config")
async def bark_config(request: Request):
    """读取当前用户 Bark 配置；密钥不回传明文，仅给掩码与是否已配置。"""
    u = require_user(request)
    cfg = _user_bark_get(u)
    base = {"has_default": bool(BARK_KEY)}
    if not cfg:
        return {**base, "configured": False,
                "server": BARK_DEFAULT_SERVER, "key_hint": ""}
    k = cfg["key"]
    hint = (k[:4] + "****") if len(k) > 4 else "****"
    return {**base, "configured": True, "server": cfg["server"],
            "key_hint": hint}


@app.post("/portal/api/bark/config")
async def bark_config_save(request: Request):
    """保存用户 Bark 服务器/密钥。key 留空表示保持原密钥；clear=true 清除自定义，
    回退站长默认通道。"""
    u = require_user(request)
    payload = await _json_body(request)
    clear = bool(payload.get("clear"))
    server = _bark_norm_server(payload.get("server") or BARK_DEFAULT_SERVER)
    key = str(payload.get("key") or "").strip()[:120]
    with db() as conn:
        if clear:
            conn.execute("DELETE FROM user_bark WHERE username=?", (u,))
            return {"configured": False, "server": BARK_DEFAULT_SERVER,
                    "has_default": bool(BARK_KEY), "key_hint": ""}
        row = conn.execute(
            "SELECT bark_key FROM user_bark WHERE username=?",
            (u,)).fetchone()
        if not key and not (row and row["bark_key"]):
            raise _AuthError(400, {"detail": "请填写 Bark 密钥"})
        conn.execute(
            "INSERT INTO user_bark(username,server,bark_key,updated_ts) "
            "VALUES(?,?,?,?) ON CONFLICT(username) DO UPDATE SET "
            "server=excluded.server, "
            "bark_key=COALESCE(NULLIF(excluded.bark_key,''),user_bark.bark_key), "
            "updated_ts=excluded.updated_ts",
            (u, server, key, now_ts()))
    cfg = _user_bark_get(u)
    k = cfg["key"] if cfg else ""
    hint = (k[:4] + "****") if len(k) > 4 else "****"
    return {"configured": True, "server": cfg["server"] if cfg else server,
            "has_default": bool(BARK_KEY), "key_hint": hint}


@app.post("/portal/api/bark/test")
async def bark_test(request: Request):
    """发送一条测试推送：优先用户自定义通道，未配置则沿用站长默认。"""
    u = require_user(request)
    cfg = _user_bark_get(u)
    if cfg:
        server, key, channel = cfg["server"], cfg["key"], "user"
    elif BARK_KEY:
        server, key, channel = BARK_DEFAULT_SERVER, BARK_KEY, "default"
    else:
        raise _AuthError(400, {
            "detail": "尚未配置 Bark 密钥，且站长未启用默认通道"})
    ok = await asyncio.to_thread(
        _bark_send, server, key, "觅影·测试推送",
        "这是一条测试消息，收到即说明 Bark 配置正确。", "觅影")
    if not ok:
        raise _AuthError(502, {"detail": "推送失败，请检查服务器地址与密钥"})
    return {"ok": True, "channel": channel}


@app.get("/portal/api/watch")
async def list_watch(request: Request):
    u = require_user(request)
    with db() as conn:
        rows = conn.execute(
            "SELECT id,keyword,last_ts,last_total,created_ts,status FROM watch "
            "WHERE username=? ORDER BY id DESC", (u,)).fetchall()
    items = []
    for r in rows:
        row = dict(r)
        row["last_ts"] = _iso_bj(row.get("last_ts"))
        row["created_ts"] = _iso_bj(row.get("created_ts"))
        items.append(row)
    return {"items": items}


@app.post("/portal/api/watch")
async def add_watch(request: Request):
    u = require_user(request)
    p = await _json_body(request)
    kw = (p.get("keyword") or "").strip()
    if not kw:
        raise _AuthError(400, {"detail": "请填写要追的剧名"})
    if len(kw) > 40:
        raise _AuthError(400, {"detail": "剧名过长"})
    status = (p.get("status") or "watching").strip()
    if status not in WATCH_STATUSES:
        raise _AuthError(400, {"detail": "未知追剧状态"})
    with db() as conn:
        existing = conn.execute(
            "SELECT id,last_ts FROM watch WHERE username=? AND keyword=?",
            (u, kw)).fetchone()
    baseline = 0
    if existing is None:
        # 新建：仅"在看"立即回源建基线（避免推送旧资源）；想看/看过先登记不回源
        newest = ""
        if status == "watching":
            newest, baseline = await _watch_baseline(kw)
        with db() as conn:
            conn.execute(
                "INSERT INTO watch(username,keyword,last_ts,last_total,"
                "created_ts,status) VALUES(?,?,?,?,?,?)",
                (u, kw, newest, baseline, now_ts(), status))
    else:
        # 已存在则切换状态；切到"在看"且此前无基线时补建一次
        if status == "watching" and not existing["last_ts"]:
            newest, baseline = await _watch_baseline(kw)
            with db() as conn:
                conn.execute(
                    "UPDATE watch SET status=?,last_ts=?,last_total=? WHERE id=?",
                    (status, newest, baseline, existing["id"]))
        else:
            with db() as conn:
                conn.execute("UPDATE watch SET status=? WHERE id=?",
                             (status, existing["id"]))
    return {"ok": True, "baseline": baseline, "status": status}


@app.delete("/portal/api/watch/{wid}")
async def del_watch(wid: int, request: Request):
    u = require_user(request)
    with db() as conn:
        conn.execute("DELETE FROM watch WHERE id=? AND username=?", (wid, u))
    return {"ok": True}


# ---------------- 关键词 RSS 订阅（#244，标准库手拼 RSS 2.0，零新增依赖） ----------------
def _build_rss_xml(channel_title: str, site_link: str, arts: list) -> str:
    """把展平资源 [(dt,note,url,pwd,drive)] 拼成 RSS 2.0 XML，全部文本经 XML 转义。"""
    items, seen = [], set()
    for dt, note, url, pwd, drive in arts:
        if not url or url in seen:
            continue
        seen.add(url)
        if len(items) >= RSS_MAX_ITEMS:
            break
        ep = _parse_dt(dt)
        pub = rfc822_date(ep) if ep is not None else rfc822_date()
        desc = f"网盘类型：{drive or '未知'}"
        if pwd:
            desc += f"；提取码：{pwd}"
        items.append(
            "<item>"
            f"<title>{xml_escape(note or '(无标题)')}</title>"
            f"<link>{xml_escape(url)}</link>"
            f"<guid isPermaLink=\"true\">{xml_escape(url)}</guid>"
            f"<pubDate>{pub}</pubDate>"
            f"<category>{xml_escape(drive or '')}</category>"
            f"<description>{xml_escape(desc)}</description>"
            "</item>")
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<rss version=\"2.0\"><channel>"
        f"<title>{xml_escape(channel_title)}</title>"
        f"<link>{xml_escape(site_link)}</link>"
        "<description>觅影网盘资源订阅</description>"
        f"<lastBuildDate>{rfc822_date()}</lastBuildDate>"
        + "".join(items) +
        "</channel></rss>")


@app.get("/portal/api/rss-token")
async def get_rss_token(request: Request):
    """登录态获取（首次自动生成）本用户不可猜测的 RSS 订阅令牌与 feed 基址。"""
    u = require_user(request)
    with db() as conn:
        row = conn.execute(
            "SELECT token FROM rss_feed WHERE username=?", (u,)).fetchone()
        if row:
            token = row["token"]
        else:
            token = secrets.token_urlsafe(24)
            conn.execute(
                "INSERT INTO rss_feed(username,token,created_ts) "
                "VALUES(?,?,?)", (u, token, now_ts()))
    return {"token": token, "feed_base": f"{str(request.base_url)}portal/rss/{token}"}


@app.get("/portal/rss/{token}")
async def rss_feed(token: str, request: Request):
    """阅读器端点，query token 鉴权；带 kw 订阅单关键词，不带 kw 聚合该用户在看剧单。"""
    with db() as conn:
        row = conn.execute(
            "SELECT username FROM rss_feed WHERE token=?", (token,)).fetchone()
    if not row:
        return Response("invalid rss token", status_code=401,
                        media_type="text/plain; charset=utf-8")
    u = row["username"]
    kw = (request.query_params.get("kw") or "").strip()[:40]
    cache_key = (token, kw)
    hit = _rss_cache.get(cache_key)
    if hit and time.time() - hit[0] < RSS_CACHE_SEC:
        return Response(hit[1],
                        media_type="application/rss+xml; charset=utf-8")
    site_link = str(request.base_url)
    arts, title = [], ("觅影·" + kw if kw else "觅影·追剧更新聚合")
    try:
        async with httpx.AsyncClient(
                timeout=httpx.Timeout(60.0, connect=15.0)) as client:
            if kw:
                arts = _flatten_arts(await _internal_search(kw, client))
            else:
                with db() as conn:
                    kws = [r["keyword"] for r in conn.execute(
                        "SELECT keyword FROM watch WHERE username=? "
                        "AND status='watching' ORDER BY id DESC LIMIT ?",
                        (u, RSS_FEED_KEYWORDS_MAX))]
                merged = []
                for wkw in kws:
                    try:
                        merged.extend(
                            _flatten_arts(await _internal_search(wkw, client))[:5])
                    except Exception:
                        continue
                merged.sort(key=lambda a: (_parse_dt(a[0]) or 0.0), reverse=True)
                arts = merged
    except Exception as e:
        logger.warning("rss fetch failed (%s): %s", title, e)
    xml = _build_rss_xml(title, site_link, arts)
    _rss_cache[cache_key] = (time.time(), xml)
    if len(_rss_cache) > 128:  # 简单封顶，防止长尾令牌缓存无限增长
        _rss_cache.clear()
    return Response(xml, media_type="application/rss+xml; charset=utf-8")


# ---------------- 远程 MCP（Streamable HTTP / JSON-RPC 2.0，#232） ----------------
# 不引第三方 MCP SDK，单文件手写最小协议面，把内部搜索薄封装暴露给支持 Streamable
# HTTP 的 AI 客户端（Claude Desktop / Cursor 等）；POST 单 JSON 响应，Bearer JWT 鉴权。
MCP_PROTOCOL_VERSION = "2025-03-26"
_MCP_JSONRPC = "2.0"


def _jsonrpc_error(req_id, code: int, message: str):
    return {"jsonrpc": _MCP_JSONRPC, "id": req_id,
            "error": {"code": code, "message": message}}


_MCP_YEAR_RE = re.compile(r"(?:19|20)\d{2}")


def _mcp_year_in_text(text: str) -> str:
    m = _MCP_YEAR_RE.search(text or "")
    return m.group(0) if m else ""


def _mcp_safe_drive(drive) -> str:
    d = str(drive or "").strip().lower()
    return d if re.fullmatch(r"[a-z0-9]{1,16}", d) else ""


def _split_quality_query(keyword: str):
    """把『沙丘2 4K原盘』拆成干净片名('沙丘2')与命中的画质 token 列表。
    画质词按提示处理而非片名死匹配；剥离后为空则整体回退原词，防空结果。"""
    raw = (keyword or "").strip()
    low = raw.lower()
    hits = []
    for tok in _FP_QUALITY_TOKENS:
        if tok in low and tok not in hits:
            hits.append(tok)
    if not hits:
        return raw, []
    base = low
    for tok in hits:
        base = base.replace(tok, " ")
    base = re.sub(r"[\s\[\]【】()（）_\-/·,，.。]+", " ", base)
    base = re.sub(r"\s+", " ", base).strip()
    if not base:
        return raw, []
    return base, hits


def _mcp_filter_by_quality(mbt: dict, qtokens: list):
    """按画质 token 保留命中条目；无任何命中时回退原集合（避免画质过严返空）。"""
    if not qtokens:
        return mbt
    out = {}
    for drive, items in (mbt or {}).items():
        kept = [it for it in items
                if any(t in (it.get("note") or "").lower() for t in qtokens)]
        if kept:
            out[drive] = kept
    return out or mbt


def _shape_mcp_results(mbt: dict, limit: int, meta: dict = None):
    """merged_by_type 展平为 AI 客户端易读的精简列表，跳过空链接并按上限截断。
    meta 为作品级豆瓣 {year, rating}；每条优先取标题内年份，缺省回退作品 meta。"""
    meta = meta or {}
    rows, n = [], 0
    for drive, items in (mbt or {}).items():
        for it in items:
            if n >= limit:
                return rows
            url = (it.get("url") or "").strip()
            if not url:
                continue
            note = it.get("note") or ""
            rows.append({
                "title": note,
                "drive": drive,
                "url": url,
                "password": it.get("password") or "",
                "source": it.get("source") or "",
                "datetime": it.get("datetime") or "",
                "size": it.get("size") or "",
                "year": _mcp_year_in_text(note) or meta.get("year", ""),
                "rating": meta.get("rating", ""),
            })
            n += 1
    return rows


_MCP_TOOLS = [{
    "name": "search_resources",
    "description": (
        "搜索全网网盘影视资源（电影/电视剧/动漫/纪录片/综艺），按网盘类型返回资源标题、"
        "可直接打开的分享链接与提取码，不登录网盘、不做转存。keyword 为影视名，"
        "可带画质要求，如『沙丘2 4K原盘』；limit 可选，控制返回条数。"),
    "inputSchema": {
        "type": "object",
        "properties": {
            "keyword": {"type": "string", "description": "影视名称或资源关键词"},
            "drive": {"type": "string",
                      "description": "可选，限定网盘类型，如 quark/aliyun/baidu/uc/"
                                     "tianyi/115/xunlei/magnet；不传或未知值返回全部网盘"},
            "limit": {"type": "integer", "minimum": 1,
                      "maximum": MCP_RESULT_LIMIT, "default": MCP_RESULT_LIMIT},
        },
        "required": ["keyword"],
    },
}]


async def _mcp_handle(payload):
    """处理单个 JSON-RPC 消息，返回 (http_status, body|None)；
    通知（无 id）无需响应时 body 为 None，由路由回 204。"""
    if not isinstance(payload, dict) or payload.get("jsonrpc") != _MCP_JSONRPC:
        return 400, _jsonrpc_error(
            payload.get("id") if isinstance(payload, dict) else None,
            -32600, "无效的 JSON-RPC 请求")
    req_id = payload.get("id")
    method = payload.get("method")
    params = payload.get("params") or {}
    is_notification = "id" not in payload

    if method == "initialize":
        return 200, {"jsonrpc": _MCP_JSONRPC, "id": req_id, "result": {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "miying-pansou-portal",
                           "version": APP_VERSION}}}
    if method == "ping":
        return 200, {"jsonrpc": _MCP_JSONRPC, "id": req_id, "result": {}}
    if is_notification:
        # notifications/initialized 等通知：确认收下即可，不回 JSON-RPC 体
        return 204, None
    if method == "tools/list":
        return 200, {"jsonrpc": _MCP_JSONRPC, "id": req_id,
                     "result": {"tools": _MCP_TOOLS}}
    if method == "tools/call":
        if not isinstance(params, dict):
            return 200, _jsonrpc_error(req_id, -32602, "params 必须是对象")
        if params.get("name") != "search_resources":
            return 200, _jsonrpc_error(req_id, -32602,
                                       "未知工具: %s" % params.get("name"))
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            return 200, _jsonrpc_error(req_id, -32602, "arguments 必须是对象")
        keyword = (args.get("keyword") or "").strip()
        if not keyword:
            return 200, _jsonrpc_error(req_id, -32602,
                                       "参数 keyword 不能为空")
        try:
            limit = int(args.get("limit", MCP_RESULT_LIMIT))
        except (TypeError, ValueError):
            limit = MCP_RESULT_LIMIT
        limit = max(1, min(limit, MCP_RESULT_LIMIT))
        drive = _mcp_safe_drive(args.get("drive"))
        # 画质词（原盘/REMUX/4K/杜比视界…）按提示处理：剥离后用干净片名回源，
        # 不再把画质词当片名死匹配，修复『沙丘2 原盘』返 0。
        base, qtokens = _split_quality_query(keyword)
        try:
            async with httpx.AsyncClient(
                    timeout=httpx.Timeout(60.0, connect=15.0)) as client:
                mbt = await _internal_search(base, client)
                meta = {}
                try:
                    info = await _douban_suggest_cover(base, client)
                    if info:
                        meta = {"year": info.get("year", ""),
                                "rating": info.get("rating", "")}
                except Exception:
                    meta = {}
            # 与网页端同源：先剔除已确认死链，再按网盘/画质收敛
            mbt, _ = _filter_dead_mbt(mbt)
            if drive:
                mbt = {drive: mbt[drive]} if mbt.get(drive) else {}
            mbt = _mcp_filter_by_quality(mbt, qtokens)
            rows = _shape_mcp_results(mbt, limit, meta)
            metrics.mcp_calls += 1
            result = {
                "content": [{"type": "text", "text": json.dumps(
                    {"keyword": keyword, "query": base,
                     "drive": drive or "all",
                     "count": len(rows), "results": rows},
                    ensure_ascii=False)}],
                "isError": False}
        except Exception as e:
            logger.warning("mcp search failed kw=%s: %s", keyword, e)
            metrics.mcp_errors += 1
            result = {"content": [{"type": "text",
                                   "text": "搜索失败，请稍后重试"}],
                      "isError": True}
        return 200, {"jsonrpc": _MCP_JSONRPC, "id": req_id, "result": result}
    return 200, _jsonrpc_error(req_id, -32601,
                               "方法不支持: %s" % method)


@app.api_route("/portal/mcp", methods=["POST"])
async def mcp_entry(request: Request):
    if not MCP_ENABLED:
        return JSONResponse({"detail": "MCP 未启用"}, status_code=404)
    require_user(request)  # 未授权直接由全局 _AuthError 处理器回 401
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(
            _jsonrpc_error(None, -32600, "请求体不是合法 JSON"), status_code=400)
    if isinstance(payload, list):  # JSON-RPC 批处理（可选能力）
        if not payload:
            return JSONResponse(
                _jsonrpc_error(None, -32600, "空批处理请求"), status_code=400)
        out = []
        for piece in payload:
            _, body = await _mcp_handle(piece)
            if body is not None:
                out.append(body)
        if not out:
            return Response(status_code=204)
        return JSONResponse(out, status_code=200)
    status, body = await _mcp_handle(payload)
    if body is None:
        return Response(status_code=status)
    return JSONResponse(body, status_code=status)


@app.api_route("/portal/mcp", methods=["GET"])
async def mcp_get_entry(request: Request):
    # Streamable HTTP 允许服务器只提供 POST 单响应、不提供 GET SSE 长流
    if not MCP_ENABLED:
        return JSONResponse({"detail": "MCP 未启用"}, status_code=404)
    return JSONResponse(
        {"detail": "本端点仅支持 POST JSON-RPC，请用 MCP 客户端以 POST 接入"},
        status_code=405)


async def check_watches():
    with db() as conn:
        # 仅"在看"参与更新监控与 Bark 推送；想看/看过不打扰
        rows = conn.execute(
            "SELECT * FROM watch WHERE status='watching'").fetchall()
    if not rows:
        return
    async with httpx.AsyncClient(
            timeout=httpx.Timeout(60.0, connect=15.0)) as client:
        for row in rows:
            try:
                arts = _flatten_arts(
                    await _internal_search(row["keyword"], client))
                if not arts:
                    continue
                newest = _newest_dt(arts)
                baseline = row["last_ts"] or ""
                if baseline:
                    base_ep = _parse_dt(baseline)

                    def _art_key(a):
                        k = _parse_dt(a[0])
                        return k if k is not None else -1.0

                    if base_ep is not None:
                        fresh = [a for a in arts if _art_key(a) > base_ep]
                    else:
                        # 基线时间无法解析时，退回字符串比较，避免误推全部
                        fresh = [a for a in arts if a[0] and a[0] > baseline]
                    if fresh:
                        fresh.sort(key=_art_key, reverse=True)
                        for dt, note, url, pwd, drive in fresh[:WATCH_PUSH_MAX]:
                            body = (note[:90] or "有新资源")
                            if pwd:
                                body += f"（提取码 {pwd}）"
                            push_bark(f"觅影更新·{row['keyword']}", body,
                                      url=url or "")
                with db() as conn:
                    conn.execute(
                        "UPDATE watch SET last_ts=?, last_total=? WHERE id=?",
                        (newest, len(arts), row["id"]))
                await asyncio.sleep(3)
            except Exception as e:
                logger.warning("watch check failed for %s: %s",
                               row["keyword"], e)


async def watch_loop():
    await asyncio.sleep(WATCH_STARTUP_DELAY)
    while True:
        try:
            await check_watches()
            metrics.job_beat("watch", info="ok")
        except Exception as e:
            logger.warning("watch_loop error: %s", e)
            metrics.job_beat("watch", ok=False, info=str(e)[:120])
        await asyncio.sleep(WATCH_INTERVAL_SEC)


# ---------------- 混合 FTS5：填充词收集 / 定时填充 / 回填 / 后台保鲜 ----------------
async def _fts_collect_words(client: httpx.AsyncClient):
    """收集填充词，返回 [(kw, src)]，去重并按来源优先级排序。"""
    words, seen = [], set()

    def add(kw, src):
        kw = (kw or "").strip()
        if kw and kw not in seen and len(kw) <= 40:
            seen.add(kw)
            words.append((kw, src))

    # 1) 豆瓣全网热榜（movies + tv）
    try:
        movies, tv = await asyncio.gather(
            _douban_subjects("movie", client, 10),
            _douban_subjects("tv", client, 10),
            return_exceptions=True)
        for it in (movies if isinstance(movies, list) else []):
            add(it.get("title"), "trending")
        for it in (tv if isinstance(tv, list) else []):
            add(it.get("title"), "trending")
    except Exception as e:
        logger.warning("fts collect trending failed: %s", e)
    # 2) 用户高频搜索词 + 3) 追剧词（直接查 DB）
    week_cut = time.strftime("%Y-%m-%dT%H:%M:%S",
                             time.localtime(time.time() - 7 * 86400))
    with db() as conn:
        for r in conn.execute(
                """SELECT keyword FROM history WHERE ts>=?
                   GROUP BY keyword ORDER BY COUNT(*) DESC LIMIT 10""",
                (week_cut,)):
            add(r["keyword"], "hot")
        for r in conn.execute("SELECT DISTINCT keyword FROM watch"):
            add(r["keyword"], "watch")
    # 4) 固定常用词
    for w in FTS_STATIC_WORDS:
        add(w, "static")
    return words


def _fts_mark_job(kw, n, src):
    with db() as conn:
        conn.execute(
            """INSERT INTO idx_jobs(kw,n,last_run,src) VALUES(?,?,?,?)
               ON CONFLICT(kw) DO UPDATE SET n=?,last_run=?,src=?""",
            (kw, n, time.time(), src, n, time.time(), src))


async def _fts_fill(force: bool = False):
    """定时填充：对收集到的词逐个走 PanSou 搜索并持久化；词间限流。"""
    if not FTS_ENABLED:
        return
    async with httpx.AsyncClient(
            timeout=httpx.Timeout(60.0, connect=15.0)) as client:
        words = await _fts_collect_words(client)
        done = 0
        for kw, src in words[:FTS_MAX_WORDS]:
            if not force:
                with db() as conn:
                    job = conn.execute(
                        "SELECT last_run FROM idx_jobs WHERE kw=?",
                        (kw,)).fetchone()
                if job and job["last_run"] and \
                        time.time() - job["last_run"] < FTS_JOB_TTL:
                    continue
            t0 = time.time()
            mbt = await _internal_search(kw, client)
            n = _fts_upsert(kw, mbt)
            _fts_mark_job(kw, n, src)
            done += 1
            logger.info("fts fill %s -> %d (%.1fs)",
                        kw, n, time.time() - t0)
            await asyncio.sleep(FTS_WORD_GAP)
    purged = _fts_purge_stale()
    logger.info("fts fill done: %d words, purged %d", done, purged)


async def _fts_backfill(kw: str, mbt: dict):
    """搜索回源结果异步回填（fire-and-forget，异常不影响主流程）。"""
    try:
        n = _fts_upsert(kw, mbt)
        _fts_mark_job(kw, n, "search")
    except Exception as e:
        logger.warning("fts backfill error: %s", e)


async def _fts_bg_refresh(kw: str):
    """本地命中后异步保鲜（SWR）：TTL 过期则回源刷新并回填；并轻量验证
    本地前 N 条、剔除失效，保证下次打开更准。"""
    try:
        now = time.time()
        need = True
        with db() as conn:
            job = conn.execute("SELECT last_run FROM idx_jobs WHERE kw=?",
                               (kw,)).fetchone()
        if job and job["last_run"] and now - job["last_run"] < FTS_JOB_TTL:
            need = False
        async with httpx.AsyncClient(
                timeout=httpx.Timeout(60.0, connect=15.0)) as client:
            if need:
                mbt = await _internal_search(kw, client)
                if mbt:
                    n = _fts_upsert(kw, mbt)
                    _fts_mark_job(kw, n, "refresh")
            # 轻量验证本地前 N 条，剔除失效
            local = _fts_local_search(kw)
            urls = []
            for items in local.values():
                for it in items:
                    u = (it.get("url") or "").strip()
                    if u:
                        urls.append(u)
            if urls:
                # A：后台保鲜也按每类型保底选链，结果统一落持久化死链/健康度
                ranked_urls = []
                for items in local.values():
                    for it in items:
                        u = (it.get("url") or "").strip()
                        if u and u not in ranked_urls:
                            ranked_urls.append(u)
                check_urls = _select_check_urls(local, ranked_urls)
                if check_urls:
                    pending = _pending(check_urls)
                    url_source = _url_source_map(local)
                    async with httpx.AsyncClient(
                            timeout=httpx.Timeout(VERIFY_TIMEOUT + 2),
                            follow_redirects=True) as vclient:
                        verdict = await verify_urls(check_urls, vclient)
                    _record_verdicts(
                        {u: verdict[u] for u in pending if u in verdict},
                        url_source)
    except Exception as e:
        logger.warning("fts bg refresh error: %s", e)


async def fts_loop():
    await asyncio.sleep(FTS_STARTUP_DELAY)
    while True:
        try:
            await _fts_fill()
            metrics.job_beat("fts", info="fill")
        except Exception as e:
            logger.warning("fts_loop error: %s", e)
            metrics.job_beat("fts", ok=False, info=str(e)[:120])
        await asyncio.sleep(FTS_FILL_INTERVAL)


@app.on_event("startup")
async def _start_watch():
    asyncio.create_task(backup_loop())
    asyncio.create_task(watch_loop())
    asyncio.create_task(retry_loop())
    if FTS_ENABLED:
        asyncio.create_task(fts_loop())
