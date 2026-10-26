#!/usr/bin/env bash
# VPN Admin — установка/обновление одной командой.
#
#   С GitHub:          curl -fsSL https://raw.githubusercontent.com/obotkov/lexer_space/main/vpn-admin/install.sh | sudo bash
#   Из папки проекта:  sudo ./install.sh
#
# Всё можно передать переменными окружения, тогда вопросов не будет:
#   ADMIN_USERNAME ADMIN_PASSWORD PORT DOMAIN XUI_URL XUI_USERNAME XUI_PASSWORD XUI_VERIFY_TLS
set -euo pipefail

# The project lives in a subfolder of a larger repository; only that folder is checked out
REPO_URL="${REPO_URL:-https://github.com/obotkov/lexer_space.git}"
REPO_BRANCH="${REPO_BRANCH:-main}"
REPO_SUBDIR="${REPO_SUBDIR:-vpn-admin}"
CLONE_DIR="${CLONE_DIR:-/opt/lexer_space}"

c_green=$'\e[32m'; c_yellow=$'\e[33m'; c_red=$'\e[31m'; c_bold=$'\e[1m'; c_reset=$'\e[0m'
info() { echo "${c_green}==>${c_reset} $*"; }
warn() { echo "${c_yellow}!!${c_reset} $*"; }
die()  { echo "${c_red}xx${c_reset} $*" >&2; exit 1; }

# Read from the terminal even when the script itself comes from `curl | bash`
TTY=/dev/tty
[ -r "$TTY" ] || TTY=/dev/null
ask() {  # ask VAR "Question" "default"
  local var="$1" question="$2" default="${3:-}" answer
  if [ -n "${!var:-}" ]; then return; fi
  if [ "$TTY" = /dev/null ]; then printf -v "$var" '%s' "$default"; return; fi
  read -r -p "$question${default:+ [$default]}: " answer < "$TTY" || true
  printf -v "$var" '%s' "${answer:-$default}"
}
ask_secret() {
  local var="$1" question="$2" answer
  if [ -n "${!var:-}" ] || [ "$TTY" = /dev/null ]; then return; fi
  read -r -s -p "$question: " answer < "$TTY" || true
  echo
  printf -v "$var" '%s' "$answer"
}
rand() { tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$1" || true; }

[ "$(id -u)" -eq 0 ] || die "Запустите от root: sudo $0"

# ---------- 1. project files ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo "")"
if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/docker-compose.yml" ]; then
  PROJECT_DIR="$SCRIPT_DIR"
elif [ -f "$CLONE_DIR/$REPO_SUBDIR/docker-compose.yml" ]; then
  PROJECT_DIR="$CLONE_DIR/$REPO_SUBDIR"
else
  command -v git >/dev/null || { info "Ставлю git"; apt-get update -qq && apt-get install -y -qq git; }
  info "Скачиваю $REPO_SUBDIR из $REPO_URL в $CLONE_DIR"
  git clone --depth 1 --branch "$REPO_BRANCH" --filter=blob:none --sparse "$REPO_URL" "$CLONE_DIR"
  git -C "$CLONE_DIR" sparse-checkout set "$REPO_SUBDIR"
  PROJECT_DIR="$CLONE_DIR/$REPO_SUBDIR"
  [ -f "$PROJECT_DIR/docker-compose.yml" ] || die "В репозитории нет папки $REPO_SUBDIR с проектом"
  JUST_CLONED=1
fi
if [ -z "${JUST_CLONED:-}" ] && git -C "$PROJECT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  info "Обновляю код"
  git -C "$PROJECT_DIR" pull --ff-only || warn "Не удалось обновить код из git, продолжаю с текущей версией"
fi
cd "$PROJECT_DIR"

# ---------- 2. docker ----------
if ! command -v docker >/dev/null; then
  info "Устанавливаю Docker"
  curl -fsSL https://get.docker.com | sh
fi
docker compose version >/dev/null 2>&1 || die "Не найден плагин docker compose. Установите docker-compose-plugin"
systemctl enable --now docker >/dev/null 2>&1 || true

# ---------- 3. config ----------
if [ -f .env ]; then
  info "Найден .env — оставляю текущие настройки"
  env_get() { grep -E "^$1=" .env | tail -1 | cut -d= -f2-; }
  ADMIN_USERNAME="$(env_get ADMIN_USERNAME)"; PORT="$(env_get PORT)"; DOMAIN="$(env_get DOMAIN)"
  FIRST_RUN=0
else
  FIRST_RUN=1
  echo
  echo "${c_bold}Настройка VPN Admin${c_reset} (Enter — значение по умолчанию)"
  ask ADMIN_USERNAME "Логин администратора" "admin"
  GENERATED_PASSWORD=""
  if [ -z "${ADMIN_PASSWORD:-}" ]; then
    ask_secret ADMIN_PASSWORD "Пароль администратора (пусто — сгенерировать)"
    if [ -z "${ADMIN_PASSWORD:-}" ]; then ADMIN_PASSWORD="$(rand 20)"; GENERATED_PASSWORD=1; fi
  fi
  ask DOMAIN "Домен для HTTPS (пусто — без домена, по IP)" ""
  if [ -n "$DOMAIN" ]; then
    PORT="${PORT:-8080}"; BIND_ADDR=127.0.0.1; COOKIE_SECURE=true; FORWARDED_ALLOW_IPS="*"
  else
    ask PORT "Порт админки" "8080"
    BIND_ADDR=0.0.0.0; COOKIE_SECURE=false; FORWARDED_ALLOW_IPS=127.0.0.1
  fi

  echo
  echo "Подключение к 3x-ui (можно пропустить и добавить сервер позже в интерфейсе)"
  ask XUI_URL "Адрес панели 3x-ui, например https://1.2.3.4:2053/путь" ""
  if [ -n "$XUI_URL" ]; then
    ask XUI_USERNAME "Логин 3x-ui" "admin"
    ask_secret XUI_PASSWORD "Пароль 3x-ui"
    XUI_VERIFY_TLS="${XUI_VERIFY_TLS:-true}"
    # 3x-ui on this same host: the container reaches it through host.docker.internal
    if [[ "$XUI_URL" =~ ://(localhost|127\.0\.0\.1)([:/]|$) ]]; then
      XUI_URL="${XUI_URL/localhost/host.docker.internal}"
      XUI_URL="${XUI_URL/127.0.0.1/host.docker.internal}"
      XUI_VERIFY_TLS=false
      warn "Панель на этом же сервере: использую $XUI_URL (без проверки TLS)"
    fi
  fi

  umask 077
  cat > .env <<EOF
ADMIN_USERNAME=${ADMIN_USERNAME}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
SECRET_KEY=$(rand 48)
PORT=${PORT}
BIND_ADDR=${BIND_ADDR}
DOMAIN=${DOMAIN}
COOKIE_SECURE=${COOKIE_SECURE}
FORWARDED_ALLOW_IPS=${FORWARDED_ALLOW_IPS}
XUI_URL=${XUI_URL:-}
XUI_USERNAME=${XUI_USERNAME:-}
XUI_PASSWORD=${XUI_PASSWORD:-}
XUI_VERIFY_TLS=${XUI_VERIFY_TLS:-true}
CACHE_TTL=30
SESSION_HOURS=24
EOF
  umask 022
  info "Настройки сохранены в $PROJECT_DIR/.env"
fi

mkdir -p data

# ---------- 4. start ----------
PROFILE_ARGS=()
[ -n "${DOMAIN:-}" ] && PROFILE_ARGS=(--profile https)
info "Собираю и запускаю контейнеры (первый раз занимает пару минут)"
docker compose ${PROFILE_ARGS[@]+"${PROFILE_ARGS[@]}"} up -d --build --remove-orphans

info "Жду запуска"
for _ in $(seq 1 30); do
  if curl -fs "http://127.0.0.1:${PORT:-8080}/api/health" >/dev/null 2>&1; then OK=1; break; fi
  sleep 2
done
[ "${OK:-0}" = 1 ] || { docker compose logs --tail 50 app; die "Админка не ответила. Логи выше"; }

# ---------- 5. summary ----------
if [ -n "${DOMAIN:-}" ]; then
  URL="https://${DOMAIN}"
else
  IP="$(curl -fs4 --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"
  URL="http://${IP}:${PORT:-8080}"
fi

echo
echo "${c_bold}${c_green}VPN Admin запущен${c_reset}"
echo "  Адрес:  ${c_bold}${URL}${c_reset}"
echo "  Логин:  ${ADMIN_USERNAME}"
if [ "$FIRST_RUN" = 1 ] && [ -n "${GENERATED_PASSWORD:-}" ]; then
  echo "  Пароль: ${c_bold}${ADMIN_PASSWORD}${c_reset}  (сохраните, он также лежит в $PROJECT_DIR/.env)"
else
  echo "  Пароль: указан при установке (см. $PROJECT_DIR/.env)"
fi
[ -z "${DOMAIN:-}" ] && warn "Без домена админка работает по HTTP. Для HTTPS перезапустите установку с DOMAIN=ваш.домен (после удаления .env)"
echo
echo "Обновление: cd $PROJECT_DIR && sudo ./install.sh   ·   Логи: docker compose logs -f app"
