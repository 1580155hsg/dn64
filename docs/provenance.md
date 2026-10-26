# 来源与实现

DN64 的目录布局、RPSL 风格属性文本、mntner / auth / mnt-by 关系以及签名 PR 管理方式参考了 dn42 的公开资料：

- https://dn42.dev/howto/Getting-Started
- https://dn42.dev/howto/Registry-Authentication
- https://dn42.dev/services/Whois
- https://git.dn42.dev/dn42/registry.git

调研时原站匿名访问要求登录，代码结构通过其公开镜像查看：

- https://git.origami.pub/Bingxin/dn42-registry

本仓库工具、schema、测试和文档为 DN64 独立实现，没有复制 dn42 的成员注册数据、提交历史或校验脚本。它不是 dn42 registry 的完整兼容替代品：

- source 和 schema namespace 为 DN64 / dn64。
- CI 使用 GitHub Actions，支持原生 SSH Ed25519 Git 签名。
- IPv6 文件名使用可逆的 Windows 兼容字符替换。
- 第一版支持直接成员分配，不实现嵌套资源池、跨维护者路由委托、PGP、外部签名评论、在线自动恢复或 dn42 私有服务集成。

后续扩展应继续保留清晰的来源与授权记录。
