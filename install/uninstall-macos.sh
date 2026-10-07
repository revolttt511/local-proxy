#!/bin/bash
# SelfProxy — macOS uninstaller
#
# Usage:
#   bash uninstall-macos.sh            # remove app bundle + CLI command, keep config
#   bash uninstall-macos.sh --purge    # also delete the app folder (incl. proxy_config.json)
#   bash uninstall-macos.sh --system   # uninstall a /Applications install (sudo)
#   bash uninstall-macos.sh --dry-run

set -euo pipefail

APP_NAME="SelfProxy"
SYSTEM_WIDE=0
PURGE=0
DRY_RUN=0

while [ $# -gt 0 ]; do
  case "$1" in
    --system)  SYSTEM_WIDE=1 ;;
    --purge)   PURGE=1 ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "Неизвестный аргумент: $1" >&2; exit 2 ;;
  esac
  shift
done

say()  { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
ok()   { printf '   OK  %s\n' "$*"; }
warn() { printf '   !   %s\n' "$*"; }
run()  { if [ "$DRY_RUN" = "1" ]; then say "   [dry-run] $*"; else eval "$@"; fi; }

if [ "$SYSTEM_WIDE" = "1" ]; then
  APP_DIR="/Applications/$APP_NAME"; SUDO="sudo"
else
  APP_DIR="$HOME/Applications/$APP_NAME"; SUDO=""
fi
BUNDLE="$(dirname "$APP_DIR")/$APP_NAME.app"
CLI="/usr/local/bin/selfproxy"
[ "$SYSTEM_WIDE" = "1" ] || CLI="$HOME/.local/bin/selfproxy"

step "Удаление $APP_NAME"
say "   app    : $APP_DIR"
say "   bundle : $BUNDLE"
if [ "$DRY_RUN" = "1" ]; then warn "DRY RUN — ничего не удаляется"; fi

# Stop a running instance so the bundle can be replaced/removed
if pgrep -f "$APP_DIR/start.pyw" >/dev/null 2>&1; then
  run "pkill -f '$APP_DIR/start.pyw' || true"
  ok "остановлен запущенный SelfProxy"
fi

if [ -d "$BUNDLE" ]; then run "$SUDO rm -rf '$BUNDLE'"; ok "удалён bundle: $BUNDLE"; fi
if [ -e "$CLI" ];    then run "$SUDO rm -f '$CLI'";     ok "удалена команда: $CLI"; fi

if [ "$PURGE" = "1" ]; then
  if [ -d "$APP_DIR" ]; then
    run "$SUDO rm -rf '$APP_DIR'"
    ok "удалена папка: $APP_DIR"
  fi
else
  warn "папка оставлена (запусти с --purge, чтобы удалить): $APP_DIR"
fi

step "Готово"
exit 0
