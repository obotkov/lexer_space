#!/usr/bin/env bash
# VPN Admin — обновление: git pull и пересборка контейнеров.
#
#   sudo ./update.sh             скачать новую версию и перезапустить
#   sudo ./update.sh --no-pull   только пересобрать текущую версию (так его вызывает install.sh)
#
# Запускается и из админки: кнопка «Обновить» кладёт data/update.request, systemd-юнит
# vpn-admin-update.path (ставит install.sh) замечает файл и вызывает этот скрипт.
# Ход обновления пишется в data/update.status и data/update.log — их показывает админка.

# Everything lives in main(): bash reads a script lazily, and `git pull` below
# may replace this very file while it runs. A function is parsed in full first.
main() {
  set -Eeuo pipefail
  cd "$(dirname "$(readlink -f "$0")")"
  local pull=1
  [ "${1:-}" = "--no-pull" ] && pull=0

  mkdir -p data
  rm -f data/update.request
  local started_at; started_at=$(date +%s)
  status() {  # status STATE MESSAGE
    printf '{"state":"%s","message":"%s","started_at":%s,"finished_at":%s}\n' \
      "$1" "$2" "$started_at" "$([ "$1" = running ] && echo null || date +%s)" > data/update.status.tmp
    mv data/update.status.tmp data/update.status
  }
  trap 'status failed "Обновление прервано с ошибкой, подробности в журнале"; echo "!! Ошибка в команде: $BASH_COMMAND"' ERR

  exec > >(tee data/update.log) 2>&1
  status running "Обновление запущено"
  echo "==> $(date '+%F %T') обновление VPN Admin"

  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    if [ "$pull" = 1 ]; then
      status running "Скачиваю новую версию"
      echo "==> git pull"
      git pull --ff-only
    fi
    export APP_TREE APP_COMMIT APP_COMMIT_DATE
    APP_TREE=$(git rev-parse "HEAD:./")
    APP_COMMIT=$(git rev-parse HEAD)
    APP_COMMIT_DATE=$(TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ)
  else
    echo "!! Папка не является git-репозиторием: обновить код нельзя, только пересобрать"
  fi
  export APP_BUILT_AT; APP_BUILT_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  echo "==> версия $(cat VERSION 2>/dev/null || echo '?') (${APP_COMMIT:0:7})"

  local profile=()
  if grep -qE '^DOMAIN=.+' .env 2>/dev/null; then profile=(--profile https); fi

  status running "Собираю образ"
  echo "==> docker compose build"
  docker compose ${profile[@]+"${profile[@]}"} build

  status running "Перезапускаю контейнеры"
  echo "==> docker compose up -d"
  docker compose ${profile[@]+"${profile[@]}"} up -d --remove-orphans
  docker image prune -f >/dev/null 2>&1 || true

  status done "Обновлено до версии $(cat VERSION 2>/dev/null || echo '?')"
  echo "==> готово"
}

main "$@"
exit
