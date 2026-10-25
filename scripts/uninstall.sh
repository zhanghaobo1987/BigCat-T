#!/usr/bin/env bash
# BigCat 卸载脚本（Debian / Ubuntu）
#
#   sudo bash uninstall.sh server   # 只卸载主控端
#   sudo bash uninstall.sh agent    # 只卸载被控端
#   sudo bash uninstall.sh all      # 全部卸载
#   sudo bash uninstall.sh all --purge  # 全部卸载并删除数据（SQLite 数据库）
set -euo pipefail

MODE="${1:-}"
PURGE="no"
[ "${2:-}" = "--purge" ] && PURGE="yes"

INSTALL_DIR="/opt/bigcat"

log() { echo "[BigCat T] $*"; }
die() { echo "[BigCat T] 错误: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行此脚本（加 sudo）"

stop_service() {
  local name="$1"
  if systemctl list-unit-files 2>/dev/null | grep -q "^$name"; then
    log "停止并禁用 $name ..."
    systemctl disable --now "$name" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/$name"
    systemctl daemon-reload
  fi
}

remove_server() {
  stop_service "bigcat.service"
  log "服务端已卸载"
}

remove_agent() {
  stop_service "bigcat-agent.service"
  log "agent 已卸载"
}

case "$MODE" in
  server) remove_server ;;
  agent)  remove_agent ;;
  all)
    remove_server
    remove_agent
    if [ -d "$INSTALL_DIR" ]; then
      if [ "$PURGE" = "yes" ]; then
        log "删除 $INSTALL_DIR（含监控数据）..."
        rm -rf "$INSTALL_DIR"
      else
        log "保留监控数据 $INSTALL_DIR/data，如需彻底删除请加 --purge"
        # 只删程序文件，保留 data
        rm -rf "$INSTALL_DIR/server" "$INSTALL_DIR/agent" "$INSTALL_DIR/venv" "$INSTALL_DIR/agent.py" 2>/dev/null || true
      fi
    fi
    log "卸载完成"
    ;;
  *)
    echo "用法: sudo bash uninstall.sh server|agent|all [--purge]" >&2
    exit 1 ;;
esac
