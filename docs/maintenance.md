# 维护指南

## GitHub 仓库

上游：`https://github.com/lichenlang89/dn64`，默认分支 `main`。资源及成员变更通过 PR 处理。

建议并在初始化时配置：

- main 要求 `registry` 检查通过并更新到最新基线。
- 至少一名审核人、CODEOWNERS 审核，推送新变更后撤销旧批准。
- 禁止强推和删除 main；只启用 merge commit。
- GitHub Actions 默认 contents:read，不向普通 PR 提供 secrets，也不使用服务器作为 self-hosted runner。

由于目前只有一位管理员，保留 GitHub 管理员对分支规则的紧急绕过能力，供项目维护与恢复；普通成员仍必须通过 PR、签名和审核。管理员日常也应使用相同流程，不把紧急绕过作为常规注册入口。

## 检查器的信任边界

`pull_request_target` 在 GitHub 托管的临时 runner 上执行，只有 contents:read 权限。checkout 固定使用 PR base SHA，且不保留 Git 凭据。PR head 仅 fetch 为 Git 对象，检查实际 SHA 与事件提供的 SHA 一致，再由主分支校验器读取 data blob。

不会检出 PR head、运行其脚本、安装其依赖或执行其测试。schema 检查使用基线版本并额外检查候选 schema；非注册对象变更需要管理员签名。依赖 action 使用提交 SHA 固定。

每个申请必须 rebase 到当前 main；配合 strict 分支检查防止并发 PR 同时抢占资源。重新运行后若资源已被登记，申请者需重新选择。

## 初始化管理员

DN64-MNT 的初始密钥是项目所有者已有 GitHub SSH 认证公钥，其指纹：

```text
SHA256:umQTnLYDFexvMzKKRAlBrgqHWN5YGGm/JPf+VbGv+Hk
```

公钥已登记在 data/mntner/DN64-MNT。私钥没有进入本仓库。建议管理员后续按密钥轮换流程添加独立的日常密钥和离线恢复公钥；仓库不依赖最初使用的 Bash 主机运行。

## 数据消费

```sh
git fetch origin main
# 在可信、隔离的副本中更新后：
./check-my-stuff
python3 utils/registry.py export > registry-export.json
```

JSON 导出仅包含通过验证的注册对象，schema 单独保留于仓库。WHOIS 查询命令也是本地 CLI，不开放端口。DNS zone、BGP prefix filter、ROA/RPKI 或网络服务的生成与部署暂未实现，后续应单独开发并测试，再接入受保护主分支的部署流程。

## 政策或 schema 变化

现有对象始终先按主分支 schema 检查。要添加新字段或对象类型，可先提交管理员签名的兼容 schema 扩展，合并后再提交使用新字段的数据；不要在单个普通注册 PR 中修改规则自我放行。
