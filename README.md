# 觅影 · MiYing — 网盘影视聚合检索

一个自托管的影视网盘资源检索站：聚合上游 [PanSou](https://github.com/fish2018/PanSou) 抓取的 Telegram 频道与第三方资源站，
按画质（4K 原盘 / REMUX / 杜比视界…）排序，只给能直接打开的网盘链接。外层再包一层 **portal 门脸**
提供长效登录、跨设备历史/收藏/追剧、失效链接过滤、海报代理与豆瓣补全、用量限流与告警。

> 仅索引公开的网盘分享链接，不存储、不转码、不传播任何视频文件；请在当地法律允许范围内自用，遵守各网盘服务条款。

## 功能

- **聚合搜索**：百度 / 夸克 / 阿里 / UC / 天翼 / 115 / 迅雷 / 123 云盘 / PikPak / 磁力等多来源，自动按画质分排序、按 URL 去重。
- **长效登录**：portal 自签 HS256 令牌，默认 180 天有效；账号密码走环境变量，多用户 + 管理员。
- **跨设备同步**：搜索历史、收藏、追剧订阅全部存服务端 SQLite（不再依赖单浏览器）。
- **追剧更新**：订阅剧目后，后端定时（默认 2 小时）轮询，发现新资源可经 Bark 推送到手机。
- **失效链接过滤**：搜索后并发校验排序前列的分享页，自动隐藏确认失效的链接。
- **海报体验**：Telegram 图床经同源代理回源（可挂代理绕过墙）；失败/缺图自动走豆瓣补全。
- **热门榜**：豆瓣实时热门电影/剧集，点击即搜；首页画质快捷入口。
- **安全与风控**：登录防爆破、按 IP 限流、Bark 滥用告警；完整 CSP/HSTS/X-Frame-Options 等安全头，敏感路径显式 404。
- **响应式**：单文件原生前端，桌面与手机（含 375px 窄屏）均可用。

## 目录结构

```
miying/
├── portal/
│   ├── app.py             # FastAPI 门脸：登录/历史/收藏/追剧/校验/限流/海报代理
│   ├── Dockerfile         # portal 镜像（python:3.12-slim + uvicorn）
│   └── requirements.txt
├── web/
│   └── index.html         # 单文件前端（原生 HTML/CSS/JS，nginx 静态托管）
├── deploy/
│   ├── nginx.conf         # 公网 nginx 站点示例（含安全头、反代、敏感路径 404）
│   └── 部署说明.md         # 完整部署/加固/QA 记录（IP 已占位）
├── docker-compose.example.yml   # 两容器编排示例（复制为 docker-compose.yml 后填值）
├── .env.example           # 环境变量集中说明
└── .gitignore
```

## 快速开始

需要：一台常开主机（Docker / Docker Compose）、（可选）用于回源 Telegram 图床的 HTTP/SOCKS 代理。

```bash
# 1. 克隆并准备配置
git clone <your-repo-url> miying && cd miying
cp docker-compose.example.yml docker-compose.yml
#   编辑 docker-compose.yml：填入 AUTH_USERS、JWT_SECRET（openssl rand -hex 32）、
#   BARK_KEY、POSTER_PROXY、上游频道/插件、代理等。

# 2. 启动（pansou 上游 + portal 门脸）
docker compose up -d --build

# 3. 验证
curl http://localhost:8981/portal/health
#   {"ok":true,"service":"pansou-portal",...}
```

- portal 监听 `8981`（容器内 80），上游 pansou 监听 `8980`。
- 前端 `web/index.html` 用任意静态服务器托管；把其中的 API 同源前缀 `/portal`、`/api` 反代到 portal（见 `deploy/nginx.conf`）。
- 公网暴露建议放在 nginx/TLS 之后；内网服务可经 frp 等隧道回源，详见 `deploy/部署说明.md`。

## 安全须知（自托管）

- **绝不要**把真实的 `docker-compose.yml`、`.env`、`*.db`、代理凭证提交到仓库——它们已在 `.gitignore` 中。
- `JWT_SECRET` 用 `openssl rand -hex 32` 生成且长度 ≥ 32，否则 portal 拒绝启动。
- `AUTH_USERS` 用强密码；管理员账号对限流豁免。
- 海报代理 `/portal/img` 有意不鉴权（`<img>` 不带令牌），靠域名白名单 + 协议白名单防 SSRF，不要放开任意 URL。

## 技术栈

- 上游：[fish2018/pansou-web](https://github.com/fish2018/pansou-web)（镜像 `ghcr.io/fish2018/pansou-web:latest`）
- 门脸：FastAPI + Uvicorn + httpx + SQLite
- 前端：原生 HTML/CSS/JS（无构建、无框架），豆瓣公开接口补全海报
- 部署：Docker Compose + nginx + （可选）frp

## 免责声明

本项目仅用于学习与个人自托管的检索索引，不托管任何受版权保护的内容；所有链接均来自第三方公开页面，
版权归原作者所有。请于合规前提下使用，因不当使用产生的后果由使用者自行承担。
