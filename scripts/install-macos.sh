#!/usr/bin/env bash
# BigCat T 一键安装脚本（macOS）
#
# 一键粘贴安装（首次安装会交互式询问端口 / 管理员用户名 / 密码等）:
#   curl -fsSL https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/install-macos.sh | sudo bash -s -- server
#
# 重复运行即升级：检测到已安装后自动复用原有配置（端口/账号/密码/主控地址/token），
# 直接更新程序并重启，不再重复提问。如需改端口可加 --port 参数；如需重置管理员密码可加 --admin-password 参数。
#
# 被控端（agent）:
#   curl -fsSL https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/install-macos.sh | sudo bash -s -- agent
#   # 安装过程中会询问主控地址和 token
#
# 非交互式（自动化）可用参数或环境变量预设全部答案:
#   curl -fsSL .../install-macos.sh | sudo bash -s -- server --port 8080 --admin-user admin --admin-password "xxx"
#   curl -fsSL .../install-macos.sh | sudo bash -s -- agent http://主控IP:25774 <token>
#
# 也支持 git clone 后本地运行: sudo bash scripts/install-macos.sh server
set -euo pipefail

REPO_URL="${BIGCAT_REPO_URL:-https://github.com/zhanghaobo1987/BigCat-T}"
INSTALL_DIR="${BIGCAT_INSTALL_DIR:-/usr/local/bigcat}"
VENV="$INSTALL_DIR/venv"
DEFAULT_PORT=25774
PLIST_DIR="/Library/LaunchDaemons"
# agent 可调选项（也可用 --interval/--install-dir/--service-name/--repo-url 等参数覆盖）
AGENT_INTERVAL="${BIGCAT_INTERVAL:-2}"
AGENT_SERVICE="${BIGCAT_SERVICE_NAME:-agent}"   # launchd 标签为 com.bigcat.<AGENT_SERVICE>
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

[ "$(uname)" = "Darwin" ] || die "此脚本仅适用于 macOS"
[ "$(id -u)" -eq 0 ] || die "请用 root 运行此脚本（加 sudo），以便注册系统级 launchd 服务"

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
ensure_sources() {
  local script_dir="$1"
  if [ -d "$script_dir/../server" ] && [ -f "$script_dir/../agent/agent.py" ]; then
    echo "$script_dir/.."
    return
  fi
  log "未检测到本地仓库源码，正在从 GitHub 下载..."
  command -v git >/dev/null || die "请先安装 git（xcode-select --install 或 brew install git）"
  local tmp
  tmp="$(mktemp -d)"
  git clone --depth 1 "$REPO_URL" "$tmp/bigcat"
  echo "$tmp/bigcat"
}

install_python() {
  if command -v python3 >/dev/null; then
    return
  fi
  if command -v brew >/dev/null; then
    log "通过 Homebrew 安装 Python3..."
    brew install python
  else
    die "未找到 python3，请先安装：brew install python（或从 python.org 下载安装包）"
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

write_plist() {
  local label="$1"       # com.bigcat.server
  local prog_args="$2"    # plist ProgramArguments 片段
  local plist="$PLIST_DIR/$label.plist"
  if [ -f "$plist" ]; then
    launchctl bootout system "$plist" 2>/dev/null || true
  fi
  cat >"$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$label</string>
  <key>ProgramArguments</key>
  <array>
$prog_args
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/bigcat-$label.log</string>
  <key>StandardErrorPath</key><string>/var/log/bigcat-$label.log</string>
</dict>
</plist>
EOF
  chmod 644 "$plist"
  launchctl bootstrap system "$plist"
  log "launchd 服务 $label 已加载（开机自启）"
}

# ---------------------------------------------------------------- 安装
# 已安装检测：launchd plist 或程序目录存在即视为已安装，进入升级模式
is_server_installed() { [ -f "$PLIST_DIR/com.bigcat.server.plist" ] || [ -f "$INSTALL_DIR/server/app.py" ]; }
is_agent_installed()  { [ -f "$PLIST_DIR/com.bigcat.agent.plist" ] || [ -f "$INSTALL_DIR/agent.py" ]; }
# 从已安装的 plist 中读取 <string>--port</string> 后一行的值
plist_arg() { # plist_arg <plist文件> <参数名>
  grep -A1 "<string>$2</string>" "$1" 2>/dev/null | tail -1 | sed -n 's|.*<string>\(.*\)</string>.*|\1|p'
}

install_server() {
  # ---- 升级检测：已安装则复用原有配置，跳过端口/账号/密码提问 ----
  UPGRADE="no"
  is_server_installed && UPGRADE="yes"
  if [ -z "$PORT" ]; then
    SAVED_PORT="$(plist_arg "$PLIST_DIR/com.bigcat.server.plist" --port)"
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
  setup_venv

  if [ -n "$ADMIN_PASSWORD" ]; then
    (cd "$INSTALL_DIR/server" && "$VENV/bin/python" app.py --db "$INSTALL_DIR/data/bigcat.db" \
      --set-admin "$ADMIN_USER:$ADMIN_PASSWORD" >/dev/null)
    log "管理员账号已设置（用户名: $ADMIN_USER）"
  elif [ "$UPGRADE" = "yes" ]; then
    log "升级模式：保留原有管理员账号（如需重置，重新运行时加 --admin-password 参数）"
  else
    log "未设置管理员账号，稍后可用以下命令设置："
    log "  $VENV/bin/python $INSTALL_DIR/server/app.py --db $INSTALL_DIR/data/bigcat.db --set-admin \"用户名:密码\""
  fi

  write_plist "com.bigcat.server" "\
    <string>$VENV/bin/python</string>
    <string>$INSTALL_DIR/server/app.py</string>
    <string>--port</string>
    <string>$PORT</string>
    <string>--db</string>
    <string>$INSTALL_DIR/data/bigcat.db</string>"
  log "服务端已启动: http://本机IP:$PORT"
}

install_agent() {
  # ---- 升级检测：已安装则复用原主控地址与 token，跳过提问 ----
  UPGRADE="no"
  is_agent_installed && UPGRADE="yes"
  AGENT_LABEL="com.bigcat.${AGENT_SERVICE}"
  PLIST="$PLIST_DIR/$AGENT_LABEL.plist"
  LEGACY_PLIST="$PLIST_DIR/com.bigcat.agent.plist"
  [ -z "$SERVER_URL" ] && SERVER_URL="$(plist_arg "$PLIST" --server)"
  [ -z "$SERVER_URL" ] && SERVER_URL="$(plist_arg "$LEGACY_PLIST" --server)"
  [ -z "$TOKEN" ] && TOKEN="$(plist_arg "$PLIST" --token)"
  [ -z "$TOKEN" ] && TOKEN="$(plist_arg "$LEGACY_PLIST" --token)"
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

  # 组装 agent 附加启动参数（只附加用户实际启用的选项）
  AGENT_EXTRA=""
  [ "${AGENT_TRAFFIC_RESET_DAY:-0}" -gt 0 ] 2>/dev/null && AGENT_EXTRA="$AGENT_EXTRA
    <string>--traffic-reset-day</string>
    <string>$AGENT_TRAFFIC_RESET_DAY</string>"
  [ "$AGENT_GPU" = "yes" ] && AGENT_EXTRA="$AGENT_EXTRA
    <string>--gpu</string>"
  [ "$AGENT_NO_REMOTE" = "yes" ] && AGENT_EXTRA="$AGENT_EXTRA
    <string>--disable-remote-exec</string>"
  [ "$AGENT_INSECURE" = "yes" ] && AGENT_EXTRA="$AGENT_EXTRA
    <string>--insecure</string>"
  [ "$AGENT_NIC_IP" = "yes" ] && AGENT_EXTRA="$AGENT_EXTRA
    <string>--nic-ip</string>"
  [ -n "$AGENT_DISK_MOUNT" ] && [ "$AGENT_DISK_MOUNT" != "/" ] && AGENT_EXTRA="$AGENT_EXTRA
    <string>--disk-mount</string>
    <string>$AGENT_DISK_MOUNT</string>"
  [ -n "$AGENT_INCLUDE_NICS" ] && AGENT_EXTRA="$AGENT_EXTRA
    <string>--include-nics</string>
    <string>$AGENT_INCLUDE_NICS</string>"
  [ -n "$AGENT_EXCLUDE_NICS" ] && AGENT_EXTRA="$AGENT_EXTRA
    <string>--exclude-nics</string>
    <string>$AGENT_EXCLUDE_NICS</string>"

  write_plist "$AGENT_LABEL" "\
    <string>$VENV/bin/python</string>
    <string>$INSTALL_DIR/agent.py</string>
    <string>--server</string>
    <string>$SERVER_URL</string>
    <string>--token</string>
    <string>$TOKEN</string>
    <string>--interval</string>
    <string>$AGENT_INTERVAL</string>$AGENT_EXTRA"
  # 服务改名时卸载旧标签，避免重复上报
  if [ "$AGENT_LABEL" != "com.bigcat.agent" ] && [ -f "$LEGACY_PLIST" ]; then
    launchctl bootout system "$LEGACY_PLIST" 2>/dev/null || true
    rm -f "$LEGACY_PLIST"
    log "已移除旧 launchd 服务 com.bigcat.agent"
  fi
  log "agent 已启动，正在向 $SERVER_URL 上报"
}

case "$MODE" in
  server) install_server ;;
  agent)  install_agent ;;
  *)
    echo "用法:" >&2
    echo "  一键安装（交互式）:" >&2
    echo "    curl -fsSL https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/install-macos.sh | sudo bash -s -- server" >&2
    echo "    curl -fsSL https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/install-macos.sh | sudo bash -s -- agent" >&2
    echo "  非交互式:" >&2
    echo "    ... | sudo bash -s -- server --port 8080 --admin-user admin --admin-password \"xxx\"" >&2
    echo "    ... | sudo bash -s -- agent http://主控IP:25774 <token>" >&2
    echo "" >&2
    echo "环境变量: BIGCAT_PORT / BIGCAT_ADMIN_USER / BIGCAT_ADMIN_PASSWORD /" >&2
    echo "          BIGCAT_SERVER_URL / BIGCAT_AGENT_TOKEN" >&2
    exit 1 ;;
esac
