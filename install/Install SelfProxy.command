#!/bin/bash
# SelfProxy — macOS installer, double-click friendly.
# Двойной клик по этому файлу в Finder запускает установку.
# Если macOS отказывается запускать: правый клик → Open, либо в Терминале:
#   chmod +x "Install SelfProxy.command" && bash "Install SelfProxy.command"
cd "$(dirname "$0")" || exit 1
echo "=== SelfProxy installer (macOS) ==="
echo
bash ./install-macos.sh "$@"
RC=$?
echo
if [ "$RC" -ne 0 ]; then
  echo "Установка не завершилась (код $RC). Смотри сообщения выше."
fi
echo "Нажми Enter, чтобы закрыть это окно."
read -r _
exit "$RC"
