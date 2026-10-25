#!/bin/sh
# ---------------------------------------------------------------------------
# BigCat ASUSWRT-Merlin 路由器一键安装脚本
#
# 在路由器 SSH 上执行（已是 root，不用 sudo）：
#
#   curl -fsSL https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/install-router.sh \
#     | sh -s -- http://主控IP:25774 <agent-token>
#
# 选项：
#   --interval 5            上报间隔秒数（默认 2）
#   --disk-mount /data      磁盘用量监控挂载点（默认: U 盘挂载点）
#   --usb /tmp/mnt/sda1     手动指定 U 盘挂载点（默认自动检测）
#   --raw-base <url>        agent.py 下载基地址（默认 GitHub raw；国内可用代理前缀）
# 环境变量：BIGCAT_SERVER_URL / BIGCAT_AGENT_TOKEN / BIGCAT_INTERVAL / BIGCAT_REPO_RAW
#
# 做了什么：自动找 ext2/3/4 的 U 盘 → 装 Entware（已有则跳过）→
#           装 Python3 + psutil → 下载 agent.py → 写开机自启 → 立即启动。
# 重复运行 = 升级：只更新 agent.py 并重启，不动 Entware/Python。
#
# 要求：ASUSWRT-Merlin 固件，aarch64/armv7，插有 ext2/3/4 格式的 U 盘。
# 注意：本脚本为 POSIX sh（路由器是 busybox ash，没有 bash），请勿用 bash 特性改写。
# ---------------------------------------------------------------------------

set -eu
# 路由器上固定用干净 PATH；测试时可用 BIGCAT_PATH 注入桩命令
PATH="${BIGCAT_PATH:-/bin:/sbin:/usr/bin:/usr/sbin}"
export PATH

SCRIPT_VERSION="1.11.6"

OPT_DIR="${BIGCAT_OPT_DIR:-/opt}"
JFFS_DIR="${BIGCAT_JFFS_DIR:-/jffs/scripts}"
RAW_BASE="${BIGCAT_REPO_RAW:-https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main}"
SERVER_URL="${BIGCAT_SERVER_URL:-}"
TOKEN="${BIGCAT_AGENT_TOKEN:-}"
INTERVAL="${BIGCAT_INTERVAL:-2}"
DISK_MOUNT=""
USB_REQ=""
USB=""
AGENT_DIR=""

log() { echo "[BigCat T] $*" >&2; }
die() { echo "[BigCat T] 错误: $*" >&2; exit 1; }
# 部分精简 ash（如 Merlin 的 busybox）没有 command 内建命令，用 type 检测命令是否存在更可靠
have() { type "$1" >/dev/null 2>&1; }

usage() {
    echo "用法: sh install-router.sh http://主控IP:25774 <agent-token> [--interval 5] [--disk-mount /path] [--usb /tmp/mnt/sda1]" >&2
}

have_tty() { : <> /dev/tty; } 2>/dev/null

ask() {
    _m="$1"; _d="$2"; _a=""
    if have_tty; then
        printf "%s [%s]: " "$_m" "$_d" > /dev/tty
        IFS= read -r _a < /dev/tty || _a=""
    fi
    printf "%s" "${_a:-$_d}"
}

ask_secret() {
    _m="$1"; _p=""
    if have_tty; then
        printf "%s: " "$_m" > /dev/tty
        stty -echo < /dev/tty 2>/dev/null || true
        IFS= read -r _p < /dev/tty || _p=""
        stty echo < /dev/tty 2>/dev/null || true
        printf "\n" > /dev/tty
    fi
    printf "%s" "$_p"
}

need_root() {
    # 部分路由器 busybox 精简掉了 id，逐级兜底：id -u → whoami → $USER/$LOGNAME
    _uid="$(id -u 2>/dev/null)" || _uid=""
    if [ -n "$_uid" ]; then
        [ "$_uid" = "0" ] || die "请用 root 运行（路由器 SSH 默认就是 root）"
        return 0
    fi
    _who="$(whoami 2>/dev/null)" || _who=""
    if [ -n "$_who" ]; then
        [ "$_who" = "root" ] || die "请用 root 运行（路由器 SSH 默认就是 root）"
        return 0
    fi
    case "${USER:-}${LOGNAME:-}" in
        *root*) return 0 ;;
    esac
    # Merlin 只有一个 admin（即 root）用户，实在判断不出时警告后继续
    log "警告: 无法确认当前用户（缺少 id/whoami），假设为 root 继续执行"
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --interval) INTERVAL="${2:?--interval 需要一个秒数}"; shift 2 ;;
            --disk-mount) DISK_MOUNT="${2:?--disk-mount 需要一个路径}"; shift 2 ;;
            --usb) USB_REQ="${2:?--usb 需要一个挂载点}"; shift 2 ;;
            --raw-base) RAW_BASE="${2:?--raw-base 需要一个 URL}"; shift 2 ;;
            -h|--help) usage; exit 0 ;;
            --*) die "未知参数: $1" ;;
            *)
                if [ -z "$SERVER_URL" ]; then SERVER_URL="$1";
                elif [ -z "$TOKEN" ]; then TOKEN="$1";
                else die "多余的参数: $1"; fi
                shift ;;
        esac
    done
}

detect_usb() {
    # 打印第一个 ext2/3/4 格式、挂载于 /tmp/mnt/* 的设备挂载点
    df -T 2>/dev/null | awk '$1 ~ /^\/dev\// && $2 ~ /^ext[234]$/ && $7 ~ /^\/tmp\/mnt\// {print $7; exit}' || true
}

resolve_usb() {
    if [ -n "$USB_REQ" ]; then
        _t="$(df -T "$USB_REQ" 2>/dev/null | awk 'NR==2{print $2}' || true)"
        case "$_t" in
            ext2|ext3|ext4) USB="$USB_REQ" ;;
            *) die "$USB_REQ 不是 ext2/3/4 格式（检测到: ${_t:-未知}）" ;;
        esac
    else
        USB="$(detect_usb || true)"
        [ -n "$USB" ] || die "未检测到 ext2/3/4 格式的 U 盘（需挂载于 /tmp/mnt/*）"
    fi
    log "U 盘: $USB"
}

opt_mounted() {
    # /opt 可能是软链接（如 -> tmp/opt），mount 表里记的是解析后的路径
    _o="$OPT_DIR"
    if [ -L "$_o" ]; then
        _t="$(readlink "$_o")"
        case "$_t" in
            /*) _o="$_t" ;;
            *) _d="$(dirname "$_o")"; _o="${_d%/}/$_t"; unset _d ;;
        esac
        unset _t
    fi
    mount 2>/dev/null | grep -q " on ${_o} "
    _r=$?; unset _o; return $_r
}

# Merlin 上 /opt 常是悬空符号链接（如 /opt -> tmp/opt），且根分区只读、删不掉；
# 正确做法是创建链接指向的目标目录，之后 mount -o bind 即可正常挂载。
# $1: 要确保的目录（默认 $OPT_DIR）
ensure_opt_dir() {
    _o="${1:-$OPT_DIR}"
    if [ -L "$_o" ] && [ ! -e "$_o" ]; then
        _t="$(readlink "$_o")"
        case "$_t" in
            /*) _d="$_t" ;;
            *) _d="$(dirname "$_o")"; _d="${_d%/}/$_t" ;;  # 相对链接相对于链接所在目录解析
        esac
        mkdir -p "$_d" || die "无法创建 $_o 的链接目标目录 $_d"
        unset _t _d
    else
        mkdir -p "$_o" || die "无法创建 $_o"
    fi
    unset _o
}

setup_entware() {
    if [ -x "$OPT_DIR/bin/opkg" ]; then
        log "检测到 Entware，跳过安装"
        return 0
    fi
    log "正在安装 Entware..."
    mkdir -p "$USB/entware" || die "无法创建 $USB/entware"
    ensure_opt_dir "$OPT_DIR"
    if ! opt_mounted; then
        mount -o bind "$USB/entware" "$OPT_DIR" || die "挂载 $OPT_DIR 失败"
    fi
    case "$(uname -m)" in
        aarch64|armv8*) _url="http://bin.entware.net/aarch64-k3.10/installer/generic.sh" ;;
        armv7*|armvh*) _url="http://bin.entware.net/armv7sf-k3.2/installer/generic.sh" ;;
        *) die "不支持的架构: $(uname -m)" ;;
    esac
    cd "$OPT_DIR" || die "无法进入 $OPT_DIR"
    # 注意：ash 没有 pipefail；wget 失败时 sh 收到空输入会直接退出(0)，
    # 靠下面的 opkg 存在性检查兜底报错。
    wget -O - "$_url" | sh || die "Entware 安装失败"
    [ -x "$OPT_DIR/bin/opkg" ] || die "Entware 安装后仍未找到 opkg"
    log "Entware 安装完成"
}

ensure_persist() {
    mkdir -p "$JFFS_DIR" || die "无法创建 $JFFS_DIR"
    # 1) 开启 JFFS 自定义脚本（对应 Web 后台“系统管理 → 系统设置”开关）
    if have nvram; then
        if [ "$(nvram get jffs2_scripts 2>/dev/null || true)" != "1" ]; then
            log "开启 JFFS 自定义脚本支持..."
            nvram set jffs2_scripts=1 && nvram commit \
                || log "警告: nvram 写入失败，请手动在 Web 后台开启 JFFS 自定义脚本"
        fi
    else
        log "警告: 未找到 nvram，请确认 Web 后台已开启 JFFS 自定义脚本"
    fi
    # 2) post-mount：重启后自动把 Entware 目录挂载回 /opt（幂等：有标记则跳过）
    _pm="$JFFS_DIR/post-mount"
    if [ -f "$_pm" ] && grep -q "BigCat-entware" "$_pm" 2>/dev/null; then
        log "post-mount 已配置，跳过"
    else
        [ -f "$_pm" ] || printf '#!/bin/sh\n' > "$_pm"
        cat >> "$_pm" <<EOF
# BigCat-entware: 重启后自动挂载 Entware 到 /opt
if [ "\$1" = "$USB" ]; then
    # /opt 可能是只读分区上的悬空链接：创建其目标目录，不删除链接
    if [ -L /opt ] && [ ! -e /opt ]; then
        _t="\$(readlink /opt)"
        case "\$_t" in /*) _d="\$_t";; *) _d="/\$_t";; esac
        mkdir -p "\$_d"
        unset _t _d
    else
        mkdir -p /opt
    fi
    mount -o bind $USB/entware /opt
    /opt/etc/init.d/rc.unslung start
fi
EOF
        chmod +x "$_pm"
        log "已写入 $_pm"
    fi
}

install_python() {
    if [ ! -x "$OPT_DIR/bin/python3" ]; then
        log "安装 Python3..."
        "$OPT_DIR/bin/opkg" update || die "opkg update 失败"
        "$OPT_DIR/bin/opkg" install python3 python3-pip || die "Python3 安装失败"
    else
        log "检测到 Python3，跳过安装"
    fi
    log "安装 psutil..."
    "$OPT_DIR/bin/python3" -m pip install -q psutil || die "psutil 安装失败（pip 报错）"
}

stop_agent() {
    _pids="$(ps 2>/dev/null | awk '/[a]gent\.py/ {print $1}' || true)"
    for _p in $_pids; do
        kill "$_p" 2>/dev/null || true
    done
    sleep 1
}

deploy_agent() {
    mkdir -p "$AGENT_DIR" || die "无法创建 $AGENT_DIR"
    if [ -f "$AGENT_DIR/agent.py" ]; then
        log "检测到已安装 agent，进入升级模式：更新程序并重启"
    fi
    stop_agent
    log "下载 agent.py..."
    if have curl; then
        curl -fsSL -o "$AGENT_DIR/agent.py" "$RAW_BASE/agent/agent.py" || die "下载 agent.py 失败"
    else
        wget -O "$AGENT_DIR/agent.py" "$RAW_BASE/agent/agent.py" || die "下载 agent.py 失败"
    fi
}

install_autostart() {
    _ss="$JFFS_DIR/services-start"
    if [ -f "$_ss" ]; then
        # 删掉旧的 BigCat-agent 行避免重复（shebang 与其他内容保留）
        grep -v "BigCat-agent" "$_ss" > "$_ss.bigcat.tmp" || true
        mv "$_ss.bigcat.tmp" "$_ss"
    else
        printf '#!/bin/sh\n' > "$_ss"
    fi
    cat >> "$_ss" <<EOF
# BigCat-agent: 启动 bigcat 探针
if [ ! -x /opt/bin/python3 ]; then
    # /opt 可能是只读分区上的悬空链接：创建其目标目录，不删除链接
    if [ -L /opt ] && [ ! -e /opt ]; then
        _t="\$(readlink /opt)"
        case "\$_t" in /*) _d="\$_t";; *) _d="/\$_t";; esac
        mkdir -p "\$_d"
        unset _t _d
    else
        mkdir -p /opt
    fi
    mount -o bind $USB/entware /opt
fi
/opt/bin/python3 $AGENT_DIR/agent.py --server "$SERVER_URL" --token "$TOKEN" --interval $INTERVAL --disk-mount "$DISK_MOUNT" >> $AGENT_DIR/agent.log 2>&1 < /dev/null &
EOF
    chmod +x "$_ss"
    log "已写入 $_ss（重启后自动启动）"
}

start_agent() {
    log "启动 agent..."
    "$OPT_DIR/bin/python3" "$AGENT_DIR/agent.py" \
        --server "$SERVER_URL" --token "$TOKEN" \
        --interval "$INTERVAL" --disk-mount "$DISK_MOUNT" \
        >> "$AGENT_DIR/agent.log" 2>&1 < /dev/null &
    sleep 2
    if ps 2>/dev/null | grep -q "[a]gent\.py"; then
        log "agent 已启动，日志: $AGENT_DIR/agent.log"
    else
        die "agent 启动失败，请查看 $AGENT_DIR/agent.log"
    fi
}

check_server() {
    if have curl; then
        if curl -fsSL -m 8 -o /dev/null "$SERVER_URL/api/version" 2>/dev/null; then
            log "主控连接正常: $SERVER_URL"
        else
            log "警告: 无法访问 $SERVER_URL/api/version，请检查主控地址与网络（继续安装）"
        fi
    fi
}

main() {
    log "BigCat 路由器一键安装 v$SCRIPT_VERSION"
    parse_args "$@"
    need_root
    resolve_usb
    AGENT_DIR="$USB/bigcat"
    [ -z "$DISK_MOUNT" ] && DISK_MOUNT="$USB"
    if [ -z "$SERVER_URL" ]; then
        SERVER_URL="$(ask "主控地址 (例如 http://192.168.50.2:25774)" "")"
    fi
    if [ -z "$TOKEN" ]; then
        TOKEN="$(ask_secret "Agent token")"
    fi
    [ -n "$SERVER_URL" ] || die "缺少主控地址"
    [ -n "$TOKEN" ] || die "缺少 token（无交互终端时请用参数或 BIGCAT_AGENT_TOKEN 提供）"
    case "$INTERVAL" in ''|*[!0-9]*) die "--interval 必须是数字" ;; esac

    check_server
    setup_entware
    ensure_persist
    install_python
    deploy_agent
    install_autostart
    start_agent

    echo "----------------------------------------" >&2
    log "完成！agent 正在向 $SERVER_URL 上报"
    log "安装目录: $AGENT_DIR ／ 日志: $AGENT_DIR/agent.log"
    log "重启路由器后 agent 会自动启动；重复运行本脚本即升级 agent"
}

main "$@"
