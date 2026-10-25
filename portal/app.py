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
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime
from urllib.parse import quote, urlencode, parse_qsl, urlparse

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

UPSTREAM = os.environ.get("PANSOU_UPSTREAM", "http://pansou").rstrip("/")
DB_PATH = os.environ.get("DB_PATH", "/app/data/portal.db")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")

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
RATE_WINDOW_SEC = int(os.environ.get("RATE_WINDOW_SEC", "600"))
RATE_WINDOW_MAX = int(os.environ.get("RATE_WINDOW_MAX", "60"))
RATE_DAY_MAX = int(os.environ.get("RATE_DAY_MAX", "500"))
ALERT_COOLDOWN_SEC = int(os.environ.get("ALERT_COOLDOWN_SEC", "900"))
EVENT_KEEP_DAYS = int(os.environ.get("EVENT_KEEP_DAYS", "30"))

# 登录防爆破：同一 IP 在窗口内失败 N 次后临时锁定
LOGIN_WINDOW_SEC = int(os.environ.get("LOGIN_WINDOW_SEC", "900"))
LOGIN_MAX_FAIL = int(os.environ.get("LOGIN_MAX_FAIL", "8"))
LOGIN_LOCK_SEC = int(os.environ.get("LOGIN_LOCK_SEC", "900"))

# 链接失效检测
VERIFY_N = int(os.environ.get("VERIFY_N", "15"))
VERIFY_WORKERS = int(os.environ.get("VERIFY_WORKERS", "12"))
VERIFY_CACHE_TTL = int(os.environ.get("VERIFY_CACHE_TTL", "1800"))
VERIFY_TIMEOUT = float(os.environ.get("VERIFY_TIMEOUT", "3"))

# 海报图片代理：海报多为 Telegram CDN（telesco.pe，国内直连被墙），
# 由 portal 经 HTTP 代理回源后转发，浏览器只走同源站点。
# 留空 = 不使用代理直连回源；需要时通过环境变量 POSTER_PROXY 传入，
# 形如 http://user:pass@host:port，切勿把真实代理凭证写进代码。
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

# 追剧更新监控：后台定时检索订阅词，发现比基线新的资源即推送
WATCH_INTERVAL_SEC = int(os.environ.get("WATCH_INTERVAL_SEC", "7200"))
WATCH_STARTUP_DELAY = int(os.environ.get("WATCH_STARTUP_DELAY", "90"))
WATCH_PUSH_MAX = int(os.environ.get("WATCH_PUSH_MAX", "5"))

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
            UNIQUE(username, keyword))""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_watch_user ON watch(username)")
        db.execute("""CREATE TABLE IF NOT EXISTS poster_fallback(
            tkey TEXT PRIMARY KEY,
            qtitle TEXT DEFAULT '',
            cover TEXT DEFAULT '',
            title TEXT DEFAULT '',
            year TEXT DEFAULT '',
            miss INTEGER DEFAULT 0,
            ts REAL NOT NULL)""")
        db.execute("PRAGMA journal_mode=WAL")
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
            # 不再使用硬编码默认口令：AUTH_USERS 未配置管理员密码时，
            # 随机生成一个临时密码并打印到容器日志（首次启动可见），避免固定弱口令。
            p = ENV_USERS.get(ADMIN_USER)
            if not p:
                p = secrets.token_urlsafe(18)
                print(f"[init] 未在 AUTH_USERS 配置管理员 {ADMIN_USER} 的密码，"
                      f"已为其生成随机临时密码（请尽快修改或在环境变量中配置）：{p}")
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


def quality_score(item: dict) -> int:
    text = ((item.get("note") or "") + " " + (item.get("url") or "")).lower()
    return sum(w for t, w in QUALITY_SCORE if t in text)


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
        # 网络异常视为未知，不隐藏（避免误杀好链接）
        return url, "alive"


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
            _verify_cache[u] = (status, now)
    return verdict


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
            print("[portal] bark failed:", e)


def push_bark(title: str, body: str, group: str = "觅影", url: str = ""):
    """通用 Bark 推送（追剧更新等）。失败不影响主流程。
    url 非空时，点击通知可直接打开对应网盘链接。"""
    if not BARK_KEY:
        return
    try:
        q = (f"https://api.day.app/{BARK_KEY}/{quote(title)}/{quote(body)}"
             f"?group={quote(group)}")
        if url:
            q += f"&url={quote(url, safe='')}"
        with httpx.Client(timeout=10.0) as c:
            c.get(q)
    except Exception as e:
        print("[portal] push_bark failed:", e)


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
        print("[portal] upstream error:", e)  # 内部日志保留细节，不回传给客户端
        return JSONResponse({"detail": "上游服务暂时不可用，请稍后重试"}, status_code=502)


def _counts(mbt: dict):
    return json.dumps({k: len(v) for k, v in mbt.items()
                       if isinstance(v, list)}, ensure_ascii=False)


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
        print("[portal] record history failed:", e)


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
        print("[portal] record event failed:", e)


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


async def _search_proxy(request: Request, username: str):
    qs = dict(request.query_params)
    keyword = qs.get("kw", "")
    src = qs.get("src", "all")
    ip = client_ip(request)
    body = await request.body()
    target_url, body = _inject_clean_filter(request, body)
    try:
        async with httpx.AsyncClient(
                timeout=httpx.Timeout(180.0, connect=15.0)) as client:
            upstream = await client.request(
                request.method, target_url,
                headers=_fwd_headers(request), content=body)
        content = upstream.content
        if upstream.status_code == 200 and keyword:
            payload = json.loads(content.decode("utf-8"))
            if payload.get("code") == 0:
                data = payload.setdefault("data", {})
                mbt = data.get("merged_by_type") or {}
                # 展平去重，按画质排序，决定检测前 N 条
                best = {}
                for items in mbt.values():
                    for it in items:
                        u = (it.get("url") or "").strip()
                        if not u:
                            continue
                        s = quality_score(it)
                        if u not in best or s > best[u][1]:
                            best[u] = (u, s)
                ranked = sorted(best.values(), key=lambda x: x[1],
                                reverse=True)
                check_urls = [u for u, _ in ranked[:VERIFY_N]]
                removed = 0
                if check_urls:
                    async with httpx.AsyncClient(
                            timeout=httpx.Timeout(VERIFY_TIMEOUT + 2),
                            follow_redirects=True) as vclient:
                        verdict = await verify_urls(check_urls, vclient)
                    dead = {u for u, st in verdict.items() if st == "dead"}
                    new_mbt = {}
                    for typ, items in mbt.items():
                        kept = [it for it in items
                                if (it.get("url") or "").strip() not in dead]
                        removed += len(items) - len(kept)
                        if kept:
                            new_mbt[typ] = kept
                    data["merged_by_type"] = new_mbt
                data["total"] = sum(
                    len(v) for v in data.get("merged_by_type", {}).values())
                data["verified"] = {
                    "checked": len(check_urls), "removed": removed}
                # 0 结果不写入用户个人历史（避免污染历史列表）；
                # 但 events 仍记录（匿名用量/限流/统计需要完整搜索行为）。
                if data.get("total"):
                    _record_history(username, keyword, src, data)
                _record_event(ip, keyword, src, data)
                check_abuse(ip, keyword, username)
                content = json.dumps(payload, ensure_ascii=False).encode()
        ctype = upstream.headers.get("content-type", "application/json")
        return Response(content=content, status_code=upstream.status_code,
                        headers={"content-type": ctype})
    except httpx.RequestError as e:
        print("[portal] search upstream error:", e)
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


# ---------------- 全网热榜（豆瓣 j/search_subjects，直连，服务端缓存） ----------------
TRENDING_CACHE = {"ts": 0.0, "data": None}
TRENDING_TTL = 6 * 3600
DOUBAN_UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) "
             "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1")


async def _douban_subjects(typ: str, client: httpx.AsyncClient, limit: int = 10):
    url = ("https://movie.douban.com/j/search_subjects?type=%s&tag=%s&page_limit=%d&page_start=0"
           % (typ, quote("热门"), limit))
    headers = {"User-Agent": DOUBAN_UA,
               "Referer": "https://movie.douban.com/",
               "Accept": "application/json, text/plain, */*"}
    r = await client.get(url, headers=headers)
    r.raise_for_status()
    d = r.json()
    out = []
    for it in d.get("subjects", [])[:limit]:
        out.append({
            "title": it.get("title", ""),
            "rate": (it.get("rate") or ""),
            "ep": it.get("episodes_info", "") or "",
            "cover": it.get("cover", "") or "",
            "url": it.get("url", "") or "",
        })
    return out


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


async def _douban_suggest_cover(q: str, client: httpx.AsyncClient, year: str = ""):
    url = "https://movie.douban.com/j/subject_suggest?q=" + quote(q)
    headers = {"User-Agent": DOUBAN_UA,
               "Referer": "https://movie.douban.com/",
               "Accept": "application/json, text/plain, */*"}
    r = await client.get(url, headers=headers)
    if r.status_code != 200:
        return None
    try:
        arr = r.json()
    except Exception:
        return None
    if not isinstance(arr, list) or not arr:
        return None
    best = _fb_pick(arr, q, year)
    if best is None:
        # 相似度都很低时，只要第一条有图也可接受（suggest 本身已按相关性排序）
        best = next((x for x in arr if x.get("img")), None)
    if not best or not best.get("img"):
        return None
    return {"cover": best.get("img", ""),
            "title": best.get("title", ""),
            "year": best.get("year", "")}


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
            "SELECT cover,title,year,miss,ts FROM poster_fallback WHERE tkey=?",
            (tkey,)).fetchone()
    if r:
        e = {"cover": r["cover"], "title": r["title"], "year": r["year"],
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
         "miss": 0 if info and info.get("cover") else 1,
         "soft": 1 if (soft and not (info and info.get("cover"))) else 0,
         "ts": now}
    _FB_MEM[tkey] = e
    if e["soft"]:
        return
    try:
        with db() as conn:
            conn.execute(
                """INSERT INTO poster_fallback(tkey,qtitle,cover,title,year,miss,ts)
                   VALUES(?,?,?,?,?,?,?)
                   ON CONFLICT(tkey) DO UPDATE SET qtitle=excluded.qtitle,
                     cover=excluded.cover,title=excluded.title,year=excluded.year,
                     miss=excluded.miss,ts=excluded.ts""",
                (tkey, q, e["cover"], e["title"], e["year"], e["miss"], now))
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
        return {"covers": {}}
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
    return {"covers": covers}


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
        raise _AuthError(429, {"detail": f"失败次数过多，请 {LOGIN_LOCK_SEC} 秒后再试"})


def _login_failed(ip: str):
    _login_fails.setdefault(ip, []).append(time.time())


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
        return {"token": make_token(u), "username": u,
                "is_admin": row["role"] == "admin",
                "ttl_days": TOKEN_TTL_DAYS}
    _login_failed(ip)
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
    return {"items": [dict(r) for r in rows]}


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
    f_map = {r["username"]: r["c"] for r in f_rows}
    users_out = [{
        "username": r["username"], "role": r["role"],
        "is_admin": r["role"] == "admin", "enabled": r["enabled"],
        "search_count": r["searches"], "fav_count": f_map.get(r["username"], 0),
        "last_active": r["last_active"],
    } for r in u_rows]
    return {
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
        # 兜底管理员（由 ADMIN_USER 指定）不可删除/停用/降级，前端据此锁定
        d["protected"] = (r["username"] == ADMIN_USER)
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


# ---------------- 追剧更新监控 ----------------
async def _internal_search(keyword: str, client: httpx.AsyncClient):
    """后台监控用：直连上游 PanSou 搜索，返回 merged_by_type。"""
    q = urlencode({
        "kw": keyword, "res": "merge", "src": "all",
        "filter": json.dumps({"exclude": DEFAULT_EXCLUDE}, ensure_ascii=False),
    })
    try:
        r = await client.get(f"{UPSTREAM}/api/search?{q}")
        payload = r.json()
        if payload.get("code") != 0:
            return {}
        return payload.get("data", {}).get("merged_by_type") or {}
    except Exception as e:
        print("[portal] internal search failed:", keyword, e)
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


@app.get("/portal/api/watch")
async def list_watch(request: Request):
    u = require_user(request)
    with db() as conn:
        rows = conn.execute(
            "SELECT id,keyword,last_ts,last_total,created_ts FROM watch "
            "WHERE username=? ORDER BY id DESC", (u,)).fetchall()
    return {"items": [dict(r) for r in rows]}


@app.post("/portal/api/watch")
async def add_watch(request: Request):
    u = require_user(request)
    p = await _json_body(request)
    kw = (p.get("keyword") or "").strip()
    if not kw:
        raise _AuthError(400, {"detail": "请填写要追的剧名"})
    if len(kw) > 40:
        raise _AuthError(400, {"detail": "剧名过长"})
    with db() as conn:
        if conn.execute("SELECT id FROM watch WHERE username=? AND keyword=?",
                        (u, kw)).fetchone():
            raise _AuthError(400, {"detail": "已经订阅过这个剧名"})
    # 立即搜索一次建立基线（last_ts=当前最新资源时间），避免推送旧资源
    newest, total = "", 0
    async with httpx.AsyncClient(
            timeout=httpx.Timeout(60.0, connect=15.0)) as client:
        arts = _flatten_arts(await _internal_search(kw, client))
        if arts:
            newest = _newest_dt(arts)
            total = len(arts)
    with db() as conn:
        conn.execute(
            "INSERT INTO watch(username,keyword,last_ts,last_total,created_ts) "
            "VALUES(?,?,?,?,?)",
            (u, kw, newest, total, now_ts()))
    return {"ok": True, "baseline": total}


@app.delete("/portal/api/watch/{wid}")
async def del_watch(wid: int, request: Request):
    u = require_user(request)
    with db() as conn:
        conn.execute("DELETE FROM watch WHERE id=? AND username=?", (wid, u))
    return {"ok": True}


async def check_watches():
    with db() as conn:
        rows = conn.execute("SELECT * FROM watch").fetchall()
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
                print("[portal] watch check failed for",
                      row["keyword"], e)


async def watch_loop():
    await asyncio.sleep(WATCH_STARTUP_DELAY)
    while True:
        try:
            await check_watches()
        except Exception as e:
            print("[portal] watch_loop error:", e)
        await asyncio.sleep(WATCH_INTERVAL_SEC)


@app.on_event("startup")
async def _start_watch():
    asyncio.create_task(watch_loop())
