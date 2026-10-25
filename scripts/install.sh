#!/usr/bin/env bash
# BigCat T 一键安装脚本（Debian / Ubuntu）
#
# 一键粘贴安装（首次安装会交互式询问端口 / 管理员用户名 / 密码等）:
#   curl -fsSL https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/install.sh | sudo bash -s -- server
#
# 重复运行即升级：检测到已安装后自动复用原有配置（端口/账号/密码/主控地址/token），
# 直接更新程序并重启，不再重复提问。如需改端口可加 --port 参数；如需重置管理员密码可加 --admin-password 参数。
#
# 被控端（agent）:
#   curl -fsSL https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/install.sh | sudo bash -s -- agent
#   # 安装过程中会询问主控地址和 token
#
# 非交互式（自动化）可用参数或环境变量预设全部答案:
#   curl -fsSL .../install.sh | sudo bash -s -- server --port 8080 --admin-user admin --admin-password "xxx"
#   BIGCAT_PORT=8080 BIGCAT_ADMIN_USER=admin BIGCAT_ADMIN_PASSWORD=xxx \
#     curl -fsSL .../install.sh | sudo bash -s -- server
#
# agent 可调选项（参数或 BIGCAT_ 前缀环境变量）:
#   --interval 5                上报间隔秒数（默认 2）
#   --install-dir /data/bigcat  安装目录（默认 /opt/bigcat）
#   --service-name my-agent     systemd 服务名（默认 bigcat-agent）
#   --repo-url <地址>           源码仓库地址，用于 GitHub 访问困难时走代理
#   --traffic-reset-day 1       月流量重置日 1-28，0=关闭（默认 0）
#   --gpu                       启用详细 GPU 监控（nvidia-smi）
#   --disable-remote-exec       禁用远程命令执行
#   --insecure                  忽略主控 TLS 证书校验（自签证书）
#   --nic-ip                    从网卡获取本机 IP 上报
#   --disk-mount /data          磁盘用量监控的挂载点（默认 /）
#   --include-nics eth0,eth1    只统计这些网卡（逗号分隔，支持 * 通配）
#   --exclude-nics 'docker*,veth*'  排除这些网卡（逗号分隔，支持 * 通配）
#     例: ... | sudo bash -s -- agent http://主控IP:25774 <token> \
#           --interval 5 --repo-url https://ghproxy.com/https://github.com/zhanghaobo1987/BigCat-T
#   curl -fsSL .../install.sh | sudo bash -s -- agent http://主控IP:25774 <token>
#
# 也支持 git clone 后本地运行: sudo bash scripts/install.sh server
set -euo pipefail

REPO_URL="${BIGCAT_REPO_URL:-https://github.com/zhanghaobo1987/BigCat-T}"
INSTALL_DIR="${BIGCAT_INSTALL_DIR:-/opt/bigcat}"
VENV="$INSTALL_DIR/venv"
DEFAULT_PORT=25774
# agent 可调选项（也可用 --interval/--install-dir/--service-name/--repo-url 等参数覆盖）
AGENT_INTERVAL="${BIGCAT_INTERVAL:-2}"
AGENT_SERVICE="${BIGCAT_SERVICE_NAME:-bigcat-agent}"
AGENT_TRAFFIC_RESET_DAY="${BIGCAT_TRAFFIC_RESET_DAY:-0}"
AGENT_GPU="${BIGCAT_GPU:-no}"
AGENT_NO_REMOTE="${BIGCAT_DISABLE_REMOTE_EXEC:-no}"
AGENT_INSECURE="${BIGCAT_INSECURE:-no}"
AGENT_NIC_IP="${BIGCAT_NIC_IP:-no}"
AGENT_DISK_MOUNT="${BIGCAT_DISK_MOUNT:-}"
AGENT_INCLUDE_NICS="${BIGCAT_INCLUDE_NICS:-}"
AGENT_EXCLUDE_NICS="${BIGCAT_EXCLUDE_NICS:-}"

MODE="${1:-}"
shift || true
PORT="${BIGCAT_PORT:-}"
ADMIN_USER="${BIGCAT_ADMIN_USER:-}"
ADMIN_PASSWORD="${BIGCAT_ADMIN_PASSWORD:-}"
SERVER_URL="${BIGCAT_SERVER_URL:-}"
TOKEN="${BIGCAT_AGENT_TOKEN:-}"
PASSWORD_GIVEN="no"
[ -n "${BIGCAT_ADMIN_PASSWORD+x}" ] && PASSWORD_GIVEN="yes"

while [ $# -gt 0 ]; do
  case "$1" in
    --port)           PORT="${2:?--port 需要一个端口号}"; shift 2 ;;
    --admin-user)     ADMIN_USER="${2:?--admin-user 需要一个用户名}"; shift 2 ;;
    --admin-password) ADMIN_PASSWORD="${2:?--admin-password 需要一个密码}"; PASSWORD_GIVEN="yes"; shift 2 ;;
    --interval)       AGENT_INTERVAL="${2:?--interval 需要一个秒数}"; shift 2 ;;
    --install-dir)    INSTALL_DIR="${2:?--install-dir 需要一个路径}"; VENV="$INSTALL_DIR/venv"; shift 2 ;;
    --service-name)   AGENT_SERVICE="${2:?--service-name 需要一个名称}"; shift 2 ;;
    --repo-url)       REPO_URL="${2:?--repo-url 需要一个地址}"; shift 2 ;;
    --traffic-reset-day) AGENT_TRAFFIC_RESET_DAY="${2:?--traffic-reset-day 需要 1-28}"; shift 2 ;;
    --gpu)            AGENT_GPU="yes"; shift ;;
    --disable-remote-exec) AGENT_NO_REMOTE="yes"; shift ;;
    --insecure)       AGENT_INSECURE="yes"; shift ;;
    --nic-ip)         AGENT_NIC_IP="yes"; shift ;;
    --disk-mount)     AGENT_DISK_MOUNT="${2:?--disk-mount 需要一个挂载点}"; shift 2 ;;
    --include-nics)   AGENT_INCLUDE_NICS="$(printf '%s' "${2:?--include-nics 需要网卡列表}" | tr -d '[:space:]')"; shift 2 ;;
    --exclude-nics)   AGENT_EXCLUDE_NICS="$(printf '%s' "${2:?--exclude-nics 需要网卡列表}" | tr -d '[:space:]')"; shift 2 ;;
    *) if [ -z "$SERVER_URL" ]; then SERVER_URL="$1"; else TOKEN="$1"; fi; shift ;;
  esac
done

log() { echo "[BigCat T] $*" >&2; }  # 输出到 stderr，避免污染 $(...) 命令替换捕获的路径
die() { echo "[BigCat T] 错误: $*" >&2; exit 1; }

# ---------------------------------------------------------------- 交互式提问
# 关键：从 /dev/tty 读取，而不是 stdin，这样 curl ... | bash 管道模式下也能提问
# have_tty 用真实 open 测试（[ -r /dev/tty ] 只看权限位，没有控制终端时 open 会失败）
have_tty() { : <> /dev/tty; } 2>/dev/null

ask() { # ask <提示语> <默认值> -> 输出答案（无 TTY 时直接用默认值）
  local msg="$1" def="$2" ans=""
  if have_tty; then
    printf "%s [%s]: " "$msg" "$def" > /dev/tty
    IFS= read -r ans < /dev/tty || ans=""
  fi
  printf "%s" "${ans:-$def}"
}

ask_required() { # ask_required <提示语> -> 输出非空答案
  local msg="$1" ans=""
  while [ -z "$ans" ]; do
    if have_tty; then
      printf "%s: " "$msg" > /dev/tty
      IFS= read -r ans < /dev/tty || ans=""
    else
      die "缺少必填项: $msg（无交互终端，请用参数或环境变量提供）"
    fi
    [ -n "$ans" ] || { echo "  不能为空，请重新输入" > /dev/tty; }
  done
  printf "%s" "$ans"
}

ask_secret() { # ask_secret <提示语> -> 输出密码（可为空表示跳过）；带确认
  local msg="$1" p1="" p2=""
  have_tty || { printf ""; return; }
  while true; do
    printf "%s: " "$msg" > /dev/tty
    stty -echo < /dev/tty 2>/dev/null || true
    IFS= read -r p1 < /dev/tty || p1=""
    stty echo < /dev/tty 2>/dev/null || true
    printf "\n" > /dev/tty
    [ -z "$p1" ] && { printf ""; return; }   # 留空 = 跳过
    printf "再输入一次确认: " > /dev/tty
    stty -echo < /dev/tty 2>/dev/null || true
    IFS= read -r p2 < /dev/tty || p2=""
    stty echo < /dev/tty 2>/dev/null || true
    printf "\n" > /dev/tty
    if [ "$p1" = "$p2" ]; then printf "%s" "$p1"; return; fi
    echo "  两次输入不一致，请重新输入（留空跳过）" > /dev/tty
  done
}

# ---------------------------------------------------------------- 基础能力
need_root() {
  [ "$(id -u)" -eq 0 ] || die "请用 root 运行此脚本（加 sudo）"
}

ensure_sources() {
  local script_dir="$1"
  if [ -d "$script_dir/../server" ] && [ -f "$script_dir/../agent/agent.py" ]; then
    echo "$script_dir/.."
    return
  fi
  log "未检测到本地仓库源码，正在从 GitHub 下载..."
  command -v git >/dev/null || { apt-get update -qq && apt-get install -y -qq git curl; }
  local tmp
  tmp="$(mktemp -d)"
  if git clone --depth 1 "$REPO_URL" "$tmp/bigcat" 2>/dev/null; then
    echo "$tmp/bigcat"
  else
    curl -fsSL "$REPO_URL/archive/refs/heads/main.tar.gz" -o "$tmp/bigcat.tgz"
    tar -xzf "$tmp/bigcat.tgz" -C "$tmp"
    echo "$tmp/bigcat-main"
  fi
}

install_python() {
  if ! command -v python3 >/dev/null; then
    log "安装 Python3..."
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-venv python3-pip \
      || die "apt 安装 Python3 失败"
  elif ! python3 -c "import ensurepip" 2>/dev/null; then
    # Debian/Ubuntu 的 python3 默认不带 ensurepip，需补装 python3-venv
    log "补装 python3-venv（当前 python3 缺少 ensurepip，无法创建虚拟环境）..."
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-venv \
      || die "apt 安装 python3-venv 失败"
  fi
  command -v python3 >/dev/null || die "安装 python3 失败"
}

setup_venv() {
  # pip 不可用视为 venv 已损坏（例如上次安装中途失败留下的半截目录），删掉重建
  if [ ! -x "$VENV/bin/pip" ]; then
    [ -n "$VENV" ] && rm -rf "$VENV"
    log "创建虚拟环境 $VENV ..."
    python3 -m venv "$VENV" || die "创建虚拟环境失败"
  fi
  log "安装 Python 依赖..."
  "$VENV/bin/pip" install -q --upgrade pip
  "$VENV/bin/pip" install -q Flask flask-cors flask-sock psutil requests
}

open_firewall() {
  local port="$1"
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    log "放行防火墙端口 $port (ufw)"
    ufw allow "$port/tcp" >/dev/null || true
  fi
}

# ---------------------------------------------------------------- 升级检测
# 已安装检测：systemd 单元或程序目录存在即视为已安装，进入升级模式
is_server_installed() { [ -f /etc/systemd/system/bigcat.service ] || [ -f "$INSTALL_DIR/server/app.py" ]; }
is_agent_installed()  { [ -f "/etc/systemd/system/${AGENT_SERVICE}.service" ] || [ -f "$INSTALL_DIR/agent.py" ]; }
# 从已安装的 systemd 单元 ExecStart 行中读取 --<参数名> 后面的值
# （单元文件不存在时返回空串，不报错，避免 set -e/pipefail 直接退出）
unit_arg() { # unit_arg <单元文件> <参数名>
  sed -n "s/.*--$2 \([^ ]*\).*/\1/p" "$1" 2>/dev/null | head -1 || true
}

# ---------------------------------------------------------------- 安装
install_server() {
  need_root

  # ---- 升级检测：已安装则复用原有配置，跳过端口/账号/密码提问 ----
  UPGRADE="no"
  is_server_installed && UPGRADE="yes"
  if [ -z "$PORT" ]; then
    SAVED_PORT="$(unit_arg /etc/systemd/system/bigcat.service port)"
    [ -n "$SAVED_PORT" ] && PORT="$SAVED_PORT"
  fi

  if [ "$UPGRADE" = "yes" ]; then
    [ -n "$PORT" ] || PORT="$DEFAULT_PORT"
    log "检测到已安装 BigCat T，进入升级模式：保留原有配置（端口=$PORT、管理员账号与数据不动），仅更新程序并重启"
  else
    # ---- 交互式收集配置（参数/环境变量优先）----
    [ -n "$PORT" ]         || PORT="$(ask "服务端监听端口" "$DEFAULT_PORT")"
    [ -n "$ADMIN_USER" ]   || ADMIN_USER="$(ask "管理员用户名" "admin")"
    if [ "$PASSWORD_GIVEN" = "no" ]; then
      ADMIN_PASSWORD="$(ask_secret "管理员密码（留空则跳过，可稍后设置）")"
    fi
    log "配置: 端口=$PORT, 管理员=$ADMIN_USER"
  fi
  case "$PORT" in ''|*[!0-9]*) die "端口必须是数字" ;; esac
  local src
  src="$(ensure_sources "$(cd "$(dirname "$0")" && pwd)")"
  log "安装服务端..."
  install_python
  mkdir -p "$INSTALL_DIR/data"
  cp -r "$src/server" "$INSTALL_DIR/"
  cp -r "$src/agent" "$INSTALL_DIR/" 2>/dev/null || true
  setup_venv

  if [ -n "$ADMIN_PASSWORD" ]; then
    [ -n "$ADMIN_USER" ] || ADMIN_USER="admin"
    (cd "$INSTALL_DIR/server" && "$VENV/bin/python" app.py --db "$INSTALL_DIR/data/bigcat.db" \
      --set-admin "$ADMIN_USER:$ADMIN_PASSWORD" >/dev/null)
    log "管理员账号已设置（用户名: $ADMIN_USER）"
  elif [ "$UPGRADE" = "yes" ]; then
    log "升级模式：保留原有管理员账号（如需重置，重新运行时加 --admin-password 参数）"
  else
    log "未设置管理员账号，稍后可用以下命令设置："
    log "  $VENV/bin/python $INSTALL_DIR/server/app.py --db $INSTALL_DIR/data/bigcat.db --set-admin \"用户名:密码\""
  fi

  cat >/etc/systemd/system/bigcat.service <<EOF
[Unit]
Description=BigCat T monitoring server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR/server
ExecStart=$VENV/bin/python app.py --port $PORT --db $INSTALL_DIR/data/bigcat.db
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable bigcat
  systemctl restart bigcat   # 重装/升级时确保加载新代码
  open_firewall "$PORT"
  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  log "服务端已启动: http://${ip:-本机IP}:$PORT"
  systemctl --no-pager --lines=3 status bigcat | head -8 || true
}

install_agent() {
  need_root

  # ---- 升级检测：已安装则复用原主控地址与 token，跳过提问 ----
  UPGRADE="no"
  is_agent_installed && UPGRADE="yes"
  AGENT_UNIT="/etc/systemd/system/${AGENT_SERVICE}.service"
  LEGACY_UNIT="/etc/systemd/system/bigcat-agent.service"
  [ -z "$SERVER_URL" ] && SERVER_URL="$(unit_arg "$AGENT_UNIT" server)"
  [ -z "$SERVER_URL" ] && SERVER_URL="$(unit_arg "$LEGACY_UNIT" server)"
  [ -z "$TOKEN" ] && TOKEN="$(unit_arg "$AGENT_UNIT" token)"
  [ -z "$TOKEN" ] && TOKEN="$(unit_arg "$LEGACY_UNIT" token)"
  [ "$UPGRADE" = "yes" ] && log "检测到已安装 agent，进入升级模式：保留原有主控地址与 token，仅更新程序并重启"

  [ -n "$SERVER_URL" ] || SERVER_URL="$(ask_required "主控地址（例如 http://主控IP:25774）")"
  if [ -z "$TOKEN" ]; then
    if have_tty; then
      printf "Agent token（在主控执行 /api/agent/register 获取）: " > /dev/tty
      stty -echo < /dev/tty 2>/dev/null || true
      IFS= read -r TOKEN < /dev/tty || TOKEN=""
      stty echo < /dev/tty 2>/dev/null || true
      printf "\n" > /dev/tty
    fi
    [ -n "$TOKEN" ] || die "缺少 token（无交互终端，请用参数或 BIGCAT_AGENT_TOKEN 提供）"
  fi

  local src
  src="$(ensure_sources "$(cd "$(dirname "$0")" && pwd)")"
  log "安装 agent，上报目标 $SERVER_URL ..."
  install_python
  mkdir -p "$INSTALL_DIR"
  cp "$src/agent/agent.py" "$INSTALL_DIR/"
  setup_venv

  # 组装 agent 启动参数（只附加用户实际启用的选项，保持默认安装命令干净）
  local agent_args="--server $SERVER_URL --token $TOKEN --interval $AGENT_INTERVAL"
  [ "${AGENT_TRAFFIC_RESET_DAY:-0}" -gt 0 ] 2>/dev/null && agent_args="$agent_args --traffic-reset-day $AGENT_TRAFFIC_RESET_DAY"
  [ "$AGENT_GPU" = "yes" ] && agent_args="$agent_args --gpu"
  [ "$AGENT_NO_REMOTE" = "yes" ] && agent_args="$agent_args --disable-remote-exec"
  [ "$AGENT_INSECURE" = "yes" ] && agent_args="$agent_args --insecure"
  [ "$AGENT_NIC_IP" = "yes" ] && agent_args="$agent_args --nic-ip"
  [ -n "$AGENT_DISK_MOUNT" ] && [ "$AGENT_DISK_MOUNT" != "/" ] && agent_args="$agent_args --disk-mount $AGENT_DISK_MOUNT"
  [ -n "$AGENT_INCLUDE_NICS" ] && agent_args="$agent_args --include-nics $AGENT_INCLUDE_NICS"
  [ -n "$AGENT_EXCLUDE_NICS" ] && agent_args="$agent_args --exclude-nics $AGENT_EXCLUDE_NICS"

  cat >/etc/systemd/system/${AGENT_SERVICE}.service <<EOF
[Unit]
Description=BigCat T monitoring agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV/bin/python $INSTALL_DIR/agent.py $agent_args
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable $AGENT_SERVICE
  systemctl restart $AGENT_SERVICE   # 重装/升级时确保加载新代码
  # 服务改名时卸载旧单元，避免重复上报
  if [ "$AGENT_SERVICE" != "bigcat-agent" ] && [ -f "$LEGACY_UNIT" ]; then
    systemctl disable --now bigcat-agent 2>/dev/null || true
    rm -f "$LEGACY_UNIT"
    log "已移除旧 systemd 服务 bigcat-agent"
  fi
  log "agent 已启动，正在向 $SERVER_URL 上报"
}

case "$MODE" in
  server) install_server ;;
  agent)  install_agent ;;
  *)
    echo "用法:" >&2
    echo "  一键安装（交互式）:" >&2
    echo "    curl -fsSL https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/install.sh | sudo bash -s -- server" >&2
    echo "    curl -fsSL https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/install.sh | sudo bash -s -- agent" >&2
    echo "  非交互式:" >&2
    echo "    ... | sudo bash -s -- server --port 8080 --admin-user admin --admin-password \"xxx\"" >&2
    echo "    ... | sudo bash -s -- agent http://主控IP:25774 <token>" >&2
    echo "" >&2
    echo "环境变量: BIGCAT_PORT / BIGCAT_ADMIN_USER / BIGCAT_ADMIN_PASSWORD /" >&2
    echo "          BIGCAT_SERVER_URL / BIGCAT_AGENT_TOKEN" >&2
    exit 1 ;;
esac
