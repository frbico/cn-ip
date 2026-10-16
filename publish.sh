#!/usr/bin/env bash
# Publish this local source tree to the user's GitHub repository. Does not handle GitHub credentials.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
REPO='https://github.com/frbico/cn-ip.git'
command -v git >/dev/null || { echo '需要安装 Git。' >&2; exit 1; }
if [[ ! -f cnip.py || ! -f README.md ]]; then
  echo '请在完整解压的 cn-ip 项目目录内运行 publish.sh' >&2
  exit 1
fi
if [[ ! -d .git ]]; then
  git init -b main
fi
if [[ -z "$(git config --get user.name || true)" ]]; then
  read -r -p '请输入 Git 提交用户名：' USERNAME
  git config --local user.name "$USERNAME"
fi
if [[ -z "$(git config --get user.email || true)" ]]; then
  read -r -p '请输入 Git 提交邮箱：' EMAIL
  git config --local user.email "$EMAIL"
fi
git branch -M main
if git remote get-url origin >/dev/null 2>&1; then
  if [[ "$(git remote get-url origin)" != "$REPO" ]]; then
    echo '当前项目已连接其他远程仓库，拒绝修改。' >&2; exit 1
  fi
else
  git remote add origin "$REPO"
fi
REMOTE_HEAD=$(git ls-remote --heads origin main)
if [[ -n "$REMOTE_HEAD" ]]; then
  echo '远程 main 分支不为空。为避免覆盖他人提交，请手动拉取并合并后再推送。' >&2
  exit 1
fi
git add .github .gitignore LICENSE README.md PUBLISH.md cnip.py install.sh tests publish.sh
git commit -m 'Initial release: cnip 1Panel China IP access manager'
echo '正在推送到 GitHub。需要你在本机完成 GitHub 授权；不会要求你向脚本输入密码或令牌。'
git push -u origin main
printf '\n✅ 已推送：https://github.com/frbico/cn-ip\n'
