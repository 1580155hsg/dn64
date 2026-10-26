# 贡献和注册

## 第一次注册

先阅读 README 的完整步骤。注册生成器产生 mntner、person、aut-num、inetnum、inet6num、route 和 route6 共 7 个对象。先预览再 `--write`；不要把公钥文件或私钥文件复制进 data。

维护者句柄使用 `FOO-MNT`，联系人使用 `FOO-DN64`。每个对象都必须指向存在的维护者；地址和 ASN 还须满足开放资源池的规则。邮箱和提交内容将公开保存于 Git 历史，请使用适合公开的联系方式。

同一个空闲资源可能被多个 PR 同时申请。资源以先合并的合法申请为准；另一申请需更新主分支后重新选择。CI 严格要求 PR 是最新 main 之上的一个非合并提交，分支保护要求重新检查更新后的主分支。

## 更新注册信息

```sh
git fetch upstream main
git rebase upstream/main
# 编辑对象
./fmt-my-stuff FOO-MNT
./check-my-stuff FOO-MNT
git add data
git commit -S -m "Update FOO-MNT contact details"
./check-pol upstream/main
git push -u origin HEAD
```

若 PR 已有一个提交，使用 `git commit --amend --no-edit -S`。多个提交使用交互式 rebase 压成一个；压缩或 rebase 后必须重新签名。

```sh
git rebase -i upstream/main
./sign-my-commit ~/.ssh/id_ed25519
./check-pol upstream/main
git push --force-with-lease
```

只对自己的申请分支使用 `--force-with-lease`。保留原 PR，后续推送会更新检查结果。

`./check-my-stuff FOO-MNT` 为保持引用和冲突检查完整，会检查整个注册库，并确认该维护者存在。它不校验尚未提交的修改签名；`./check-pol upstream/main` 检查已经提交的单个签名提交。

## DNS 委派

创建 `data/dns/foo.dn64`，例如：

```text
domain:             foo.dn64
nserver:            ns1.foo.dn64 10.64.1.53
nserver:            ns2.example.net
admin-c:            FOO-DN64
tech-c:             FOO-DN64
mnt-by:             FOO-MNT
source:             DN64
```

域内 nameserver 必须提供 glue 地址；可重复 `ds-rdata` 登记 SHA-256 / SHA-384 DS。子域登记须由已登记父域的维护者管理。对象登记不会自动部署 DNS 服务。

## 项目代码和规则变更

修改 data 以外的文件、schema、registry、ASN 池、地址池，或转移对象所有权，需要 `DN64-MNT` 密钥签名。外部贡献者可提出方案，管理员审核后把认可的补丁整理成管理员签名的提交；CI 不会让普通注册密钥修改执行逻辑。

## 开发验证

```sh
python3 -m unittest discover -s tests -v
python3 utils/registry.py check
```

测试使用 tests/fixtures 的独立注册库，不改变真实 data，不访问网络；会临时生成 SSH 密钥并创建 Git 仓库验证授权边界。运行测试不会使用开发者的私钥。
