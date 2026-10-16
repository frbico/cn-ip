# 把本项目发布到 frbico/cn-ip

发布需要仓库写入权限。请通过 GitHub 官方登录或已授权的连接完成，不要共享密码或令牌。

`main` 分支推送后，GitHub Actions 会运行 Python 测试矩阵、真实 Nginx 回归和安装器测试，全部通过后自动创建 `v1.0.0` Release。若该 Release 已存在则保持不变；不会移动已有标签或覆盖 Release。Release 作业仅对本仓库 `main` 的 push 生效，使用 GitHub 自动提供的 `GITHUB_TOKEN`，无需上传凭据。仓库需要启用 Actions，并允许该作业的 `contents: write` 权限。

如果你拿到的是 `cn-ip.zip` 文件，可以在自己的电脑或可访问 GitHub 的服务器上运行：

```bash
unzip cn-ip.zip
cd cn-ip
bash publish.sh
```

脚本会初始化 Git 仓库、设置 `main` 分支、创建首次提交并尝试推送到 `https://github.com/frbico/cn-ip.git`。如果本机还没有配置 Git 提交用户名/邮箱，会提示输入；GitHub 登录由本机 Git Credential Manager 或 GitHub CLI 处理，不需要把令牌发送到聊天窗口。

可以先安装 [GitHub CLI](https://cli.github.com/) 并登录：

```bash
gh auth login
gh auth setup-git
bash publish.sh
```

注意：如果远程 `main` 分支已存在，`publish.sh` 会拒绝覆盖；此时应该克隆仓库并合并更改，不要强制推送。

发布成功后，其他 1Panel 服务器就可以使用：

```bash
curl -fsSL https://raw.githubusercontent.com/frbico/cn-ip/main/install.sh -o /tmp/cnip-install.sh && sudo bash /tmp/cnip-install.sh
sudo cnip
```

在 GitHub 网页中上传也可以：先解压 ZIP，将所有文件和目录通过 **Add file → Upload files** 上传。必须确保 `.github/workflows/test.yml`、`install.sh`、`cnip.py` 等处于正确路径，不能只上传 ZIP 文件，否则一键安装地址无法工作。
