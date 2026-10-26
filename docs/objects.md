# 对象格式参考

所有注册对象均为 UTF-8 / LF 文本，一个文件一个对象。属性名小写，值从第 21 列开始；使用 `./fmt-my-stuff` 统一空格。schema 定义见 `data/schema/dn64.*`。

| 对象 | 首行字段 | 文件名 | 主要关系 |
| --- | --- | --- | --- |
| mntner | mntner | FOO-MNT | auth 公钥、自身 mnt-by、联系人 |
| person | person | FOO-DN64 | nic-hdl 是主键，e-mail 为公开联系方式 |
| role | role | NOC-DN64 | nic-hdl 是团队联系句柄 |
| aut-num | aut-num | AS4206400001 | 私有 ASN、as-name、联系人 |
| as-block | as-block | AS4206400000-AS4206409999 | 管理员定义开放或保留的 ASN 池 |
| inetnum | inetnum | 10.64.1.0_24 | 地址区间、cidr、状态和联系人 |
| inet6num | inet6num | fd12-3456-789a--_48 | 标准 IPv6 前缀、状态和联系人 |
| route | route | 10.64.1.0_24 | IPv4 前缀和已登记的 origin ASN |
| route6 | route6 | fd12-3456-789a--_48 | IPv6 前缀和已登记的 origin ASN |
| dns | domain | foo.dn64 | nserver、可选 ds-rdata、联系人 |
| registry | registry | DN64 | 注册机构、网址及管理员 |

`source: DN64` 对所有对象必填。`mnt-by`、`admin-c`、`tech-c`、`auth`、`nserver`、`remarks` 等字段是否可重复，以各对象 schema 的 `multiple` 规则为准。只有 `remarks` 接受缩进的续行。未知字段会被拒绝。

IPv4 地址对象使用地址区间作为首行，`cidr` 单独写规范前缀；例如：

```text
inetnum:            10.64.1.0 - 10.64.1.255
cidr:               10.64.1.0/24
netname:            FOO-IPV4
status:             ASSIGNED
admin-c:            FOO-DN64
tech-c:             FOO-DN64
mnt-by:             FOO-MNT
source:             DN64
```

示例不会自动分配资源。首次申请优先使用注册生成器，避免手工遗漏对应的路由和引用对象。每个资源只有一个对象文件；第一版不支持同一前缀的多个 origin。

资源池对象使用 `status: ALLOCATED` 并指定 `policy`、`min-length`、`max-length`。成员使用 `status: ASSIGNED`，不能给自己的对象添加资源池政策来扩大分配权限。
