#!/usr/bin/env bash
# =====================================================================
# 觅影 MiYing · 一键部署脚本
# 自动：检查依赖 -> 生成 docker-compose.yml -> 生成 JWT -> 设置管理员
#       -> 构建启动 -> 健康检查
# 用法：
#   bash scripts/install.sh                     # 交互式设置管理员
#   MIYING_ADMIN=admin MIYING_PASS=xxx bash scripts/install.sh   # 非交互
# =====================================================================
set -euo pipefail

cd "$(dirname "$0")/.."

G() { printf "\033[32m%s\033[0m\n" "$*"; }
W() { printf "\033[33m%s\033[0m\n" "$*"; }
D() { printf "\033[31m%s\033[0m\n" "$*"; }

# 1. 依赖检查
command -v docker >/dev/null 2>&1 || { D "未找到 docker，请先安装 Docker"; exit 1; }
docker compose version >/dev/null 2>&1 || { D "需要 Docker Compose v2（docker compose）"; exit 1; }
G "[1/5] 依赖检查通过（docker $(docker --version | awk '{print $3}' | tr -d ,)）"

# 2. 生成 compose
if [ -f docker-compose.yml ]; then
  W "[2/5] docker-compose.yml 已存在，保留不动"
else
  cp docker-compose.example.yml docker-compose.yml
  G "[2/5] 已从示例生成 docker-compose.yml"
fi

# 3. 管理员账号（环境变量优先，否则交互）
ADMIN="${MIYING_ADMIN:-}"
PASS="${MIYING_PASS:-}"
if [ -z "$ADMIN" ]; then
  read -r -p "  管理员用户名 [admin]: " ADMIN; ADMIN="${ADMIN:-admin}"
fi
if [ -z "$PASS" ]; then
  read -r -s -p "  管理员密码（输入不显示）: " PASS; echo
  if [ "${#PASS}" -lt 8 ]; then D "密码至少 8 位"; exit 1; fi
fi

# 4. 用 python 安全替换（避免特殊字符问题）
GEN="$(openssl rand -hex 32 2>/dev/null || true)"
if [ -z "$GEN" ]; then
  GEN="$(docker run --rm python:3.12-slim python -c 'import secrets;print(secrets.token_hex(32))')"
fi
G "[3/5] 已生成 JWT 密钥"

ADMIN="$ADMIN" PASS="$PASS" GEN="$GEN" python3 - <<'PY'
import os, re
f = "docker-compose.yml"
s = open(f, encoding="utf-8").read()
admin, pwd, gen = os.environ["ADMIN"], os.environ["PASS"], os.environ["GEN"]
# 替换 JWT_SECRET
s = re.sub(r"JWT_SECRET=.*", "JWT_SECRET=" + gen, s)
# 替换 ADMIN_USER
s = re.sub(r"ADMIN_USER=.*", "ADMIN_USER=" + admin, s)
# 替换 AUTH_USERS 中的管理员账号（保留其余用户）
def repl(m):
    users = m.group(1).split(",")
    users[0] = f"{admin}:{pwd}"
    return "AUTH_USERS=" + ",".join(users)
s = re.sub(r"AUTH_USERS=([^\n]*)", repl, s)
open(f, "w", encoding="utf-8").write(s)
print("[4/5] 已写入管理员账号与密钥")
PY

# 5. 构建启动
G "[5/5] 构建并启动容器（首次拉取镜像可能需要几分钟）..."
docker compose up -d --build

# 健康检查
G "等待服务就绪..."
for i in $(seq 1 20); do
  if curl -fs http://localhost:8981/portal/health >/dev/null 2>&1; then
    G "✓ portal 已就绪"
    break
  fi
  sleep 3
  [ "$i" = 20 ] && { D "portal 未在 60s 内就绪，请查看：docker compose logs pansou-portal"; exit 1; }
done

cat <<EOF

────────────────────────────────────────
 部署完成
   portal 门脸 : http://localhost:8981
   pansou 上游 : http://localhost:8980
   前端静态页  : web/index.html（需 nginx 托管，见 deploy/nginx.conf）
 下一步：
   1. 公网访问：把 deploy/nginx.conf 配好，用 TLS 反代 portal
   2. 内网穿透：见 deploy/frpc.example.toml
   3. 追剧推送：在 docker-compose.yml 填 BARK_KEY
   命令：docker compose logs -f / docker compose down
────────────────────────────────────────
EOF
