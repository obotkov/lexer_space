#!/usr/bin/env bash
# VPN Admin — установка одной командой.
#
#   С GitHub:          curl -fsSL https://raw.githubusercontent.com/obotkov/lexer_space/main/vpn-admin/install.sh | sudo bash
#   Из папки проекта:  sudo ./install.sh
#
# Что делает:
#   * порт админки — случайный пятизначный, логин и пароль — случайные (выводятся в конце);
#   * nginx с сайтом-заглушкой (один из 5 шаблонов, сменить можно в админке) на домене;
#   * сертификат Let's Encrypt для домена: им пользуются и админка, и заглушка;
#   * подключение к 3x-ui по API-токену или логину и паролю.
#
# Всё можно передать переменными окружения, тогда вопросов не будет:
#   ADMIN_USERNAME ADMIN_PASSWORD PORT SITE_DOMAIN LE_EMAIL SITE_TEMPLATE SITE=0 (без nginx)
#   XUI_URL XUI_API_TOKEN (или XUI_USERNAME + XUI_PASSWORD) XUI_VERIFY_TLS
#
# Повторный запуск обновляет код, пересобирает контейнеры и переустанавливает
# автообновление; настройки из .env сохраняются.

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
{ : < /dev/tty; } 2>/dev/null || TTY=/dev/null
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
rand_lower() { tr -dc 'a-z0-9' < /dev/urandom | head -c "$1" || true; }

port_busy() { ss -Hltn "( sport = :$1 )" 2>/dev/null | grep -q .; }

random_port() {  # a free five-digit TCP port
  local port
  for _ in $(seq 1 50); do
    port=$(shuf -i 10000-65535 -n 1)
    port_busy "$port" || { echo "$port"; return; }
  done
  die "Не нашёл свободный порт"
}

env_get() { grep -E "^$1=" .env 2>/dev/null | tail -1 | cut -d= -f2- || true; }
env_set() {  # env_set KEY VALUE: replace or append in .env
  if grep -qE "^$1=" .env; then sed -i "s|^$1=.*|$1=$2|" .env; else echo "$1=$2" >> .env; fi
}

fetch_project() {
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
    return
  fi
  if git -C "$PROJECT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    info "Обновляю код"
    git -C "$PROJECT_DIR" pull --ff-only || warn "Не удалось обновить код из git, продолжаю с текущей версией"
  fi
}

ensure_docker() {
  if ! command -v docker >/dev/null; then
    info "Устанавливаю Docker"
    curl -fsSL https://get.docker.com | sh
  fi
  docker compose version >/dev/null 2>&1 || die "Не найден плагин docker compose. Установите docker-compose-plugin"
  systemctl enable --now docker >/dev/null 2>&1 || true
}

configure() {
  if [ -f .env ]; then
    info "Найден .env — оставляю текущие настройки"
    ADMIN_USERNAME="$(env_get ADMIN_USERNAME)"; PORT="$(env_get PORT)"; DOMAIN="$(env_get DOMAIN)"
    # a domain for the decoy site can be added to an existing install: SITE_DOMAIN=... ./install.sh
    if [ -n "${SITE_DOMAIN:-}" ] && [ -z "$(env_get SITE_DOMAIN)" ]; then
      env_set SITE_DOMAIN "${SITE_DOMAIN,,}"
      env_set SITE_HTTPS "$(port_busy 443 && echo 0 || echo 1)"
    fi
    SITE_DOMAIN="$(env_get SITE_DOMAIN)"
    FIRST_RUN=0
    return
  fi
  FIRST_RUN=1
  # Credentials and port are random: they are printed at the end and stored in .env
  ADMIN_USERNAME="${ADMIN_USERNAME:-adm_$(rand_lower 6)}"
  ADMIN_PASSWORD="${ADMIN_PASSWORD:-$(rand 20)}"
  PORT="${PORT:-$(random_port)}"
  if port_busy "$PORT"; then die "Порт $PORT уже занят"; fi

  echo
  echo "${c_bold}Настройка VPN Admin${c_reset} (Enter — значение по умолчанию)"
  echo "Домен нужен для сайта-заглушки и сертификата Let's Encrypt: A-запись должна указывать на этот сервер,"
  echo "порт 80 должен быть открыт. Админка будет на https://домен:${PORT}, на самом домене — заглушка."
  ask SITE_DOMAIN "Домен (пусто — без домена, админка по IP)" ""
  SITE_DOMAIN="${SITE_DOMAIN,,}"
  SITE_HTTPS=0
  if [ -n "$SITE_DOMAIN" ]; then
    if port_busy 443; then
      warn "Порт 443 занят (например, VLESS Reality): заглушка будет только по HTTP, админка — по HTTPS на порту ${PORT}"
    else
      SITE_HTTPS=1
    fi
    ask LE_EMAIL "Email для уведомлений Let's Encrypt (необязательно)" ""
    ask LE_ACCEPT "Выпустить сертификат Let's Encrypt? Это согласие с условиями https://letsencrypt.org/repository/ [Y/n]" "Y"
  fi

  echo
  echo "Подключение к 3x-ui (можно пропустить и добавить сервер позже в интерфейсе)"
  ask XUI_URL "Адрес панели 3x-ui, например https://1.2.3.4:2053/путь" ""
  if [ -n "$XUI_URL" ]; then
    echo "Для 3x-ui v3.0.2+ лучше API-токен: Настройки → Безопасность → API Token, область Admin"
    ask_secret XUI_API_TOKEN "API-токен 3x-ui (пусто — входить по логину и паролю)"
    if [ -z "${XUI_API_TOKEN:-}" ]; then
      ask XUI_USERNAME "Логин 3x-ui" "admin"
      ask_secret XUI_PASSWORD "Пароль 3x-ui"
    fi
    XUI_VERIFY_TLS="${XUI_VERIFY_TLS:-true}"
    # 3x-ui on this same host (the container shares the host network): its certificate is not for 127.0.0.1
    if [[ "$XUI_URL" =~ ://(localhost|127\.0\.0\.1)([:/]|$) ]]; then
      XUI_VERIFY_TLS=false
      warn "Панель на этом же сервере: подключаюсь к $XUI_URL без проверки TLS"
    fi
  fi

  umask 077
  cat > .env <<EOF
ADMIN_USERNAME=${ADMIN_USERNAME}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
SECRET_KEY=$(rand 48)
PORT=${PORT}
BIND_ADDR=0.0.0.0
DOMAIN=
SITE_DOMAIN=${SITE_DOMAIN}
SITE_HTTPS=${SITE_HTTPS}
COOKIE_SECURE=false
FORWARDED_ALLOW_IPS=127.0.0.1
XUI_URL=${XUI_URL:-}
XUI_API_TOKEN=${XUI_API_TOKEN:-}
XUI_USERNAME=${XUI_USERNAME:-}
XUI_PASSWORD=${XUI_PASSWORD:-}
XUI_VERIFY_TLS=${XUI_VERIFY_TLS:-true}
CACHE_TTL=30
SESSION_HOURS=24
EOF
  umask 022
  info "Настройки сохранены в $PROJECT_DIR/.env"
}

# nginx serves the decoy page on port 80 (and 443 with the certificate) and the
# Let's Encrypt challenge files; see nginx.sh
setup_site() {
  if [ "${SITE:-1}" = 0 ]; then return; fi
  if [ ! -f data/nginx.enabled ] && port_busy 80 && ! pgrep -x nginx >/dev/null; then
    warn "Порт 80 занят не nginx: сайт-заглушку не ставлю. Сертификат можно выпустить позже в админке"
    return
  fi
  if [ ! -f data/site/index.html ]; then
    local template domain
    template="${SITE_TEMPLATE:-$(ls backend/app/site_templates/*.html | xargs -n1 basename | sed 's/\.html$//' | shuf -n 1)}"
    [ -f "backend/app/site_templates/$template.html" ] || die "Нет шаблона заглушки $template"
    domain="${SITE_DOMAIN:-example.com}"
    mkdir -p data/site
    sed -e "s/{{domain}}/$domain/g" -e "s/{{year}}/$(date +%Y)/g" "backend/app/site_templates/$template.html" > data/site/index.html
    printf '{"template": "%s", "domain": "%s"}\n' "$template" "${SITE_DOMAIN:-}" > data/site.json
    info "Сайт-заглушка: шаблон «$template»"
  fi
  ./nginx.sh install
}

issue_certificate() {
  [ -n "${SITE_DOMAIN:-}" ] || return 0
  [[ "${LE_ACCEPT:-Y}" =~ ^[YyДд] ]] || return 0
  if grep -q '"enabled": *true' data/tls.json 2>/dev/null; then return 0; fi
  local resolved server_ip
  resolved="$(getent ahostsv4 "$SITE_DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' || true)"
  server_ip="$(curl -fs4 --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  if [ -n "$server_ip" ] && [[ " $resolved " != *" $server_ip "* ]]; then
    warn "Домен $SITE_DOMAIN указывает на «${resolved:-ничего}», а IP сервера $server_ip: Let's Encrypt, скорее всего,"
    warn "не подтвердит домен. Исправьте A-запись и выпустите сертификат в админке: Система → HTTPS"
  fi
  info "Выпускаю сертификат Let's Encrypt для $SITE_DOMAIN"
  if docker compose exec -T app python -m app.tls_cli issue "$SITE_DOMAIN" "${LE_EMAIL:-}"; then
    if [ -f data/nginx.enabled ]; then ./nginx.sh apply; fi
    docker compose restart app >/dev/null
    wait_healthy
  else
    warn "Сертификат не выпущен. Админка работает по HTTP, повторить можно в админке: Система → HTTPS"
  fi
}

open_firewall() {
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    info "Открываю порты в ufw: ${PORT}$( [ -f data/nginx.enabled ] && echo ', 80, 443')"
    ufw allow "${PORT}/tcp" >/dev/null
    if [ -f data/nginx.enabled ]; then ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null; fi
  fi
}

# The admin cannot rebuild its own container: it drops data/update.request, and this
# path unit runs update.sh on the host when the file appears.
install_updater() {
  if ! command -v systemctl >/dev/null || [ ! -d /run/systemd/system ]; then
    warn "systemd не найден: обновление из админки недоступно, используйте ./update.sh"
    rm -f data/updater.enabled
    return
  fi
  cat > /etc/systemd/system/vpn-admin-update.service <<EOF
[Unit]
Description=VPN Admin self-update (git pull + rebuild)
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$PROJECT_DIR/update.sh
TimeoutStartSec=1800
EOF
  cat > /etc/systemd/system/vpn-admin-update.path <<EOF
[Unit]
Description=Watch for VPN Admin update requests

[Path]
PathExists=$PROJECT_DIR/data/update.request
Unit=vpn-admin-update.service

[Install]
WantedBy=multi-user.target
EOF
  # same idea for nginx: the admin drops data/nginx.reload after a new certificate
  cat > /etc/systemd/system/vpn-admin-nginx.service <<EOF
[Unit]
Description=VPN Admin: regenerate nginx config for the decoy site and reload nginx

[Service]
Type=oneshot
ExecStart=$PROJECT_DIR/nginx.sh apply
EOF
  cat > /etc/systemd/system/vpn-admin-nginx.path <<EOF
[Unit]
Description=Watch for VPN Admin nginx reload requests

[Path]
PathExists=$PROJECT_DIR/data/nginx.reload
Unit=vpn-admin-nginx.service

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now vpn-admin-update.path vpn-admin-nginx.path >/dev/null
  touch data/updater.enabled
  info "Обновление из админки включено (systemd: vpn-admin-update.path)"
}

wait_healthy() {
  info "Жду запуска"
  local ok=0
  for _ in $(seq 1 30); do
    if curl -fsk "https://127.0.0.1:${PORT:-8080}/api/health" >/dev/null 2>&1 \
      || curl -fs "http://127.0.0.1:${PORT:-8080}/api/health" >/dev/null 2>&1; then ok=1; break; fi
    sleep 2
  done
  [ "$ok" = 1 ] || { docker compose logs --tail 50 app; die "Админка не ответила. Логи выше"; }
}

summary() {
  local url ip tls_domain
  tls_domain=$(grep -o '"domain": *"[^"]*"' data/tls.json 2>/dev/null | sed 's/.*"\([^"]*\)"$/\1/' || true)
  if [ -n "${DOMAIN:-}" ]; then
    url="https://${DOMAIN}"
  elif [ -n "$tls_domain" ] && grep -q '"enabled": *true' data/tls.json 2>/dev/null; then
    url="https://${tls_domain}:${PORT}"
  else
    ip="$(curl -fs4 --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"
    url="http://${ip}:${PORT}"
  fi
  echo
  echo "${c_bold}${c_green}VPN Admin запущен${c_reset}"
  echo "  Админка:  ${c_bold}${url}${c_reset}"
  echo "  Логин:    ${c_bold}${ADMIN_USERNAME}${c_reset}"
  if [ "$FIRST_RUN" = 1 ]; then
    echo "  Пароль:   ${c_bold}${ADMIN_PASSWORD}${c_reset}"
    echo "  Сохраните их: логин и пароль также лежат в $PROJECT_DIR/.env"
  else
    echo "  Пароль:   см. ADMIN_PASSWORD в $PROJECT_DIR/.env"
  fi
  if [ -f data/nginx.enabled ] && [ -n "${SITE_DOMAIN:-}" ]; then
    local site_scheme=http
    if [ "$(env_get SITE_HTTPS)" = 1 ] && [ -f data/letsencrypt/live/vpn-admin/fullchain.pem ]; then site_scheme=https; fi
    echo "  Заглушка: ${site_scheme}://${SITE_DOMAIN}  (сменить шаблон: Система → Сайт-заглушка)"
  fi
  if [[ "$url" == http://* ]]; then
    warn "Админка работает по HTTP. Включите HTTPS: Система → HTTPS (Let's Encrypt, нужен домен и открытый порт 80)"
  fi
  echo
  echo "Обновление: в админке (раздел «Система») или sudo $PROJECT_DIR/update.sh   ·   Логи: docker compose logs -f app"
}

# Everything runs from main(): bash reads scripts lazily, and `git pull` may
# replace this file while it is running. A function is parsed in full first.
main() {
  set -euo pipefail
  [ "$(id -u)" -eq 0 ] || die "Запустите от root: sudo $0"
  fetch_project
  cd "$PROJECT_DIR"
  ensure_docker
  configure
  mkdir -p data
  install_updater
  setup_site
  info "Собираю и запускаю контейнеры (первый раз занимает пару минут)"
  ./update.sh --no-pull
  wait_healthy
  issue_certificate
  open_firewall
  summary
}

main "$@"
exit
