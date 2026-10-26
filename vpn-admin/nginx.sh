#!/usr/bin/env bash
# VPN Admin — nginx для сайта-заглушки на домене.
#
#   sudo ./nginx.sh install   поставить nginx (если его нет) и включить сайт-заглушку
#   sudo ./nginx.sh apply     пересобрать конфиг и перечитать nginx
#
# nginx отдаёт data/site/index.html (страницу выбирают в админке: Система → Сайт-заглушка)
# и /.well-known/acme-challenge/ из data/acme для проверки домена Let's Encrypt.
# Когда сертификат выпущен и SITE_HTTPS=1, сайт открывается и по HTTPS (порт 443).
# apply запускается и сам: админка кладёт data/nginx.reload, а systemd-юнит
# vpn-admin-nginx.path (ставит install.sh) вызывает этот скрипт.

main() {
  set -Eeuo pipefail
  local dir data conf env_file
  dir="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
  data="$dir/data"
  conf=/etc/nginx/conf.d/vpn-admin-site.conf
  env_file="$dir/.env"
  env_get() { grep -E "^$1=" "$env_file" 2>/dev/null | tail -1 | cut -d= -f2- || true; }

  case "${1:-apply}" in
    install) install_nginx ;;
    apply) apply_config ;;
    *) echo "Использование: $0 install|apply" >&2; exit 2 ;;
  esac
}

install_nginx() {
  if ! command -v nginx >/dev/null; then
    echo "==> Устанавливаю nginx"
    if command -v apt-get >/dev/null; then
      DEBIAN_FRONTEND=noninteractive apt-get update -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx >/dev/null
    elif command -v dnf >/dev/null; then
      dnf install -y -q nginx
    else
      echo "!! Не знаю, как поставить nginx в этой системе: установите его вручную и повторите" >&2
      exit 1
    fi
    # our nginx: the stub becomes the default site, the distro welcome page goes away
    rm -f /etc/nginx/sites-enabled/default
    touch "$data/nginx.owned"
  fi
  mkdir -p "$data/site" "$data/acme"
  touch "$data/nginx.enabled"
  systemctl enable nginx >/dev/null 2>&1 || true
  apply_config
}

apply_config() {
  rm -f "$data/nginx.reload"
  [ -f "$data/nginx.enabled" ] || { echo "nginx для заглушки не включён (./nginx.sh install)"; return 0; }
  mkdir -p "$data/site" "$data/acme"
  [ -f "$data/site/index.html" ] || echo "<!doctype html><title>Welcome</title>" > "$data/site/index.html"

  local domain https cert key default names ipv6 tmp
  domain="$(env_get SITE_DOMAIN)"
  https="$(env_get SITE_HTTPS)"
  cert="$data/letsencrypt/live/vpn-admin/fullchain.pem"
  key="$data/letsencrypt/live/vpn-admin/privkey.pem"
  default=""; names="${domain:-_}"
  if [ -f "$data/nginx.owned" ]; then default=" default_server"; names="${domain} _"; fi
  ipv6=0; [ -f /proc/net/if_inet6 ] && ipv6=1
  local with_tls=0
  if [ "$https" = 1 ] && [ -f "$cert" ] && [ -f "$key" ]; then with_tls=1; fi

  tmp="$(mktemp)"
  {
    echo "# Managed by vpn-admin (nginx.sh) — overwritten on every change, edit nginx.sh instead"
    echo "server {"
    echo "    listen 80${default};"
    [ "$ipv6" = 1 ] && echo "    listen [::]:80${default};"
    echo "    server_name ${names};"
    echo "    server_tokens off;"
    echo "    location ^~ /.well-known/acme-challenge/ {"
    echo "        root $data/acme;"
    echo "        default_type text/plain;"
    echo "        try_files \$uri =404;"
    echo "    }"
    if [ "$with_tls" = 1 ]; then
      echo "    location / { return 301 https://\$host\$request_uri; }"
    else
      echo "    root $data/site;"
      echo "    index index.html;"
      echo "    location / { try_files \$uri \$uri/ =404; }"
    fi
    echo "}"
    if [ "$with_tls" = 1 ]; then
      echo "server {"
      echo "    listen 443 ssl${default};"
      [ "$ipv6" = 1 ] && echo "    listen [::]:443 ssl${default};"
      echo "    server_name ${names};"
      echo "    server_tokens off;"
      echo "    ssl_certificate $cert;"
      echo "    ssl_certificate_key $key;"
      echo "    ssl_protocols TLSv1.2 TLSv1.3;"
      echo "    ssl_session_cache shared:vpnadmin:1m;"
      echo "    root $data/site;"
      echo "    index index.html;"
      echo "    location / { try_files \$uri \$uri/ =404; }"
      echo "}"
    fi
  } > "$tmp"

  local backup=""
  if [ -f "$conf" ]; then backup="$(mktemp)"; cp "$conf" "$backup"; fi
  install -m 644 "$tmp" "$conf"
  rm -f "$tmp"
  if ! nginx -t -q 2>/tmp/vpn-admin-nginx-test.log; then
    echo "!! Конфиг nginx не прошёл проверку, возвращаю прежний:" >&2
    cat /tmp/vpn-admin-nginx-test.log >&2
    if [ -n "$backup" ]; then cp "$backup" "$conf"; else rm -f "$conf"; fi
    exit 1
  fi
  [ -n "$backup" ] && rm -f "$backup"
  if systemctl is-active --quiet nginx; then systemctl reload nginx; else systemctl start nginx; fi
  echo "==> nginx: сайт-заглушка ${domain:-по IP}$([ "$with_tls" = 1 ] && echo ' (HTTP + HTTPS)' || echo ' (HTTP)')"
}

main "$@"
exit
