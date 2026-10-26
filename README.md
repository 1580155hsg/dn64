# DN64

[![DN64 Registry](https://github.com/lichenlang89/dn64/actions/workflows/registry.yml/badge.svg)](https://github.com/lichenlang89/dn64/actions/workflows/registry.yml)

DN64 是一个 IPv4 / IPv6 双栈实验网络社区。本仓库是 ASN、地址、路由来源、维护者及 DNS 委派的注册来源。

沿用 dn42 的管理风格：**文本对象 → Fork → 签名提交 → Pull Request → 自动校验 → 人工审核**。
DN64 独立管理资源，工具为本项目独立实现，不包含 dn42 成员数据或提交历史，也不代表已经与 dn42 互联。

DN64 is an independent dual-stack experimental network registry, inspired by dn42's RPSL-style objects and signed pull-request workflow.

## 初始资源

| 资源 | DN64 约定 |
| --- | --- |
| 私有 ASN | `4206400000`–`4206409999` |
| IPv4 | `10.64.0.0/16`，默认申请 `/24` |
| IPv6 | 独立随机生成 ULA `/48`，在注册库中查重 |
| 内部 DNS | `*.dn64`，需自行配置网络内 DNS 解析 |

`fd00::/8` 对象仅是 ULA 分配规则的根节点，不是 DN64 对整个 ULA 空间的独占声明。私有 ASN、IPv4 和 ULA 可能与其他私网重叠；计划互联时需要协调。`.dn64` 是本社区内部 DNS 约定，不是公网 DNS 委派。

本项目当前提供注册管理和本地查询工具。仓库中没有部署隧道、BGP、权威 DNS 或公网 WHOIS 服务；登记资源后仍需成员自行建立网络和对等互联。

## 快速注册

需要 Python 3.10+、Git 2.34+、OpenSSH 8.2+；没有第三方 Python 依赖。推荐 Linux / WSL / macOS。

1. Fork 本仓库，克隆你的 Fork，添加上游并创建分支：

```sh
git clone git@github.com:YOUR-USER/dn64.git
cd dn64
git remote add upstream https://github.com/lichenlang89/dn64.git
git fetch upstream main
git switch -c register-my-network upstream/main
```

2. 使用自己的 SSH Ed25519 **公钥**生成注册对象。生成器选择空闲 ASN、IPv4 `/24` 和随机 IPv6 ULA `/48`；分配以 PR 合并为准。

```sh
# 默认只预览；确认后加 --write 写入 7 个对象。
./new-registration --handle YOURHANDLE --email you@example.net --key ~/.ssh/id_ed25519.pub
./new-registration --handle YOURHANDLE --email you@example.net --key ~/.ssh/id_ed25519.pub --write

# 也可以明确指定未占用的资源：
# ./new-registration --handle YOURHANDLE --email you@example.net --key ~/.ssh/id_ed25519.pub \
#   --asn 4206400001 --ipv4 10.64.1.0/24 --ipv6 fd12:3456:789a::/48 --write
```

3. 格式化、校验并签名提交。下面的 Git 设置仅影响这个仓库。

```sh
./fmt-my-stuff YOURHANDLE-MNT
./check-my-stuff YOURHANDLE-MNT
git config gpg.format ssh
git config user.signingkey ~/.ssh/id_ed25519
git add data
git commit -S -m "Register YOURHANDLE-MNT and dual-stack network"
./check-pol upstream/main
git push -u origin HEAD
```

4. 在 GitHub 发起目标为 `lichenlang89/dn64:main` 的 PR。CI 校验通过、维护者审核合并后，资源才完成登记。

请保留私钥备份；私钥不进入仓库。详细流程见 [贡献指南](CONTRIBUTING.md)、[分配政策](docs/policy.md) 和 [认证说明](docs/authentication.md)。

## 仓库结构

```text
data/
  schema/      对象字段、必填项、引用定义
  registry/    注册机构
  mntner/      维护者与 SSH 公钥
  person/      联系人
  role/        团队联系人（申请后出现）
  as-block/    ASN 池
  aut-num/     ASN（申请后出现）
  inetnum/     IPv4 池与分配
  inet6num/    IPv6 策略根与分配
  route/       IPv4 前缀及 origin ASN（申请后出现）
  route6/      IPv6 前缀及 origin ASN（申请后出现）
  dns/         DNS 委派（申请后出现）
utils/         校验、签名授权、导出和注册生成器
tests/         独立测试数据和安全回归测试
.github/       PR 模板、CODEOWNERS 和 GitHub Actions
```

每个对象一个文件，使用 `source: DN64`。IPv4 文件名如 `10.64.1.0_24`。IPv6 文件名将 `:` 替换为 `-`、`/` 替换为 `_`，如 `fd12-3456-789a--_48`，因此 Windows 也可以检出。对象内容仍使用标准 IPv6 表示。字段与文件名对照见[对象格式参考](docs/objects.md)。

## 管理与查询

```sh
./check-my-stuff                             # 检查整个注册库
python3 -m unittest discover -s tests -v     # 含真实 SSH 签名的回归测试
python3 utils/registry.py ula                # 生成随机 ULA /48
python3 utils/registry.py whois DN64-MNT
python3 utils/registry.py whois 10.64.0.0/16
python3 utils/registry.py export > registry-export.json
```

PR 的校验程序从目标主分支读取，候选对象通过 Git blob 读取，不检出或执行 PR 中的脚本。首次注册需要自己的密钥签名；已有对象的更改按**更改前**的所有者和公钥验证。策略、工具、资源池和所有权转移需要 `DN64-MNT` 签名。签名核验独立于 GitHub 的 Verified 标记。

管理员操作与合并规则见 [维护指南](docs/maintenance.md)。本项目使用 [MIT License](LICENSE)，设计参考见 [来源说明](docs/provenance.md)。
