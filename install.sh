#!/usr/bin/env bash
# cnip installer. Installs the CLI only; it does not change any website settings.
set -Eeuo pipefail

if [[ "$(id -u)" != 0 ]]; then
  echo '错误：请以 root 执行（sudo bash install.sh）。' >&2
  exit 1
fi
for command in python3 install curl docker grep mktemp dirname rm cp; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "错误：缺少依赖 $command" >&2
    exit 1
  fi
done
python3 - <<'PY'
import sys
if sys.version_info < (3, 8):
    raise SystemExit('需要 Python 3.8 或更高版本')
PY

DEST='/usr/local/bin/cnip'
if [[ -L "$DEST" ]]; then
  echo "错误：$DEST 是符号链接，拒绝覆盖。" >&2
  exit 1
fi
if [[ -e "$DEST" ]] && ! grep -q 'cnip — 1Panel OpenResty mainland-China IP access policy manager' "$DEST"; then
  echo "错误：$DEST 已存在，但不是 cnip 管理程序。为防覆盖已停止。" >&2
  exit 1
fi
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Only trust an adjacent source in a complete local checkout, never a loose /tmp file.
SRC=''
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-/dev/stdin}")" && pwd)
if [[ "${BASH_SOURCE[0]:-}" == */install.sh || "${BASH_SOURCE[0]:-}" == install.sh ]] && [[ -f "$SCRIPT_DIR/cnip.py" && -f "$SCRIPT_DIR/README.md" && -f "$SCRIPT_DIR/LICENSE" && -d "$SCRIPT_DIR/tests" ]]; then
  SRC="$SCRIPT_DIR/cnip.py"
else
  RAW_BASE="${CNIP_RAW_BASE:-https://raw.githubusercontent.com/frbico/cn-ip/main}"
  echo "从 $RAW_BASE 下载 cnip.py ..."
  curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fLsS --retry 2 --connect-timeout 10 --max-time 60 \
    "$RAW_BASE/cnip.py" -o "$TMP/cnip.py"
  SRC="$TMP/cnip.py"
fi
cp -- "$SRC" "$TMP/validated.py"
SRC="$TMP/validated.py"
python3 -m py_compile "$SRC"
if ! grep -q 'cnip — 1Panel OpenResty mainland-China IP access policy manager' "$SRC"; then
  echo '文件校验失败：不是预期的 cnip.py' >&2
  exit 1
fi
install -m 0755 "$SRC" "$DEST"
echo '✅ cnip 已安装到 /usr/local/bin/cnip'
echo '现在运行 cnip 即可打开中文数字菜单。'
echo '如没有自动识别 OpenResty，请运行 cnip doctor 检查环境。'
