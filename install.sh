#!/bin/sh
# Установка и обновление xsub на роутере Keenetic (Entware + XKeen с ядром Xray).
#
#   curl -fsSL https://raw.githubusercontent.com/furriest/xsub/main/install.sh | sh
#
# Переменные:
#   XSUB_VERSION=v0.2.0  — конкретная версия (по умолчанию последняя)
#   XSUB_FEED=1          — подключить репозиторий opkg, чтобы обновляться через «opkg upgrade»
set -e

REPO="${XSUB_REPO:-furriest/xsub}"
TMP=/opt/tmp/xsub.ipk

say() { echo "xsub: $*"; }
die() { echo "xsub: $*" >&2; exit 1; }

command -v opkg >/dev/null 2>&1 || die "не найден opkg — нужен Entware (Keenetic: компонент «Поддержка открытых пакетов»)."

case "$(uname -m)" in
  aarch64|arm64) ARCH=aarch64 ;;
  armv7*|armv6*|armv5*) ARCH=armv7 ;;
  mips*)
    if opkg print-architecture 2>/dev/null | grep -q mipsel; then
      ARCH=mipsel
    elif opkg print-architecture 2>/dev/null | grep -q 'mips'; then
      ARCH=mips
    else
      die "не удалось определить порядок байт MIPS (opkg print-architecture)."
    fi
    ;;
  *) die "архитектура $(uname -m) не поддерживается." ;;
esac

if [ -n "$XSUB_VERSION" ]; then
  URL="https://github.com/$REPO/releases/download/$XSUB_VERSION/xsub_$ARCH.ipk"
else
  URL="https://github.com/$REPO/releases/latest/download/xsub_$ARCH.ipk"
fi

mkdir -p /opt/tmp
say "скачиваю $URL"
if command -v curl >/dev/null 2>&1; then
  curl -fL --retry 3 -o "$TMP" "$URL" || die "не удалось скачать пакет."
elif command -v wget >/dev/null 2>&1; then
  wget -O "$TMP" "$URL" || die "не удалось скачать пакет (установите curl: opkg install curl)."
else
  die "нужен curl: opkg install curl"
fi

[ -x /opt/sbin/xray ] || say "внимание: не найден /opt/sbin/xray — xsub работает с XKeen на ядре Xray (xkeen -xray)."

opkg install "$TMP"
rm -f "$TMP"

if [ "$XSUB_FEED" = "1" ]; then
  OWNER="${REPO%%/*}"
  NAME="${REPO#*/}"
  echo "src/gz xsub https://$OWNER.github.io/$NAME/$ARCH" > /opt/etc/opkg/xsub.conf
  say "репозиторий подключён: обновление — opkg update && opkg upgrade xsub"
fi
