#!/usr/bin/env python3
"""DN64 RPSL-style registry checks. Python standard library only."""
from __future__ import annotations

import argparse
import base64
from collections import defaultdict
from dataclasses import dataclass
import ipaddress
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ADMIN = "DN64-MNT"
SAFE_PATH = re.compile(r"data/[a-z0-9-]+/[A-Za-z0-9_.-]+\Z")
MAX_FILE = 65536
MAX_TOTAL = 32 * 1024 * 1024


class Invalid(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise Invalid(message)


def git(repo, *args, input=None, check=True):
    return subprocess.run(
        ["git", "-C", str(repo), *args], input=input, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=check,
    )


def git_snapshot(repo, revision):
    """Read blobs without checking out, importing, or executing submitted code."""
    tree = git(repo, "ls-tree", "-r", "-z", revision, "--", "data").stdout
    result = {}
    total = 0
    for entry in tree.split(b"\0"):
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split()
        path = raw_path.decode("utf-8")
        need(SAFE_PATH.fullmatch(path), "Unsupported data path: " + repr(path))
        need(mode == "100644" and kind == "blob", "Data must be regular files: " + path)
        size = int(git(repo, "cat-file", "-s", oid).stdout)
        need(size <= MAX_FILE, "Object exceeds 64 KiB: " + path)
        total += size
        need(total <= MAX_TOTAL and len(result) < 50000, "Registry size limit exceeded")
        result[path] = git(repo, "cat-file", "blob", oid).stdout.decode("utf-8")
    return result


def working_snapshot(root):
    data = Path(root) / "data"
    need(data.is_dir() and not data.is_symlink(), "Missing regular data directory")
    result = {}
    total = 0
    for path in sorted(data.rglob("*")):
        need(not path.is_symlink(), "Symlinks are not allowed in data")
        if path.is_dir():
            continue
        rel = path.relative_to(root).as_posix()
        need(SAFE_PATH.fullmatch(rel), "Unsupported data path: " + repr(rel))
        need(path.is_file() and path.stat().st_size <= MAX_FILE, "Invalid or oversized file: " + rel)
        total += path.stat().st_size
        need(total <= MAX_TOTAL and len(result) < 50000, "Registry size limit exceeded")
        result[rel] = path.read_text(encoding="utf-8")
    return result


def parse(text, path="object"):
    need(bool(text.strip()), "Empty object: " + path)
    need("\r" not in text and "\0" not in text, "Use UTF-8 text and LF line endings: " + path)
    attrs = defaultdict(list)
    previous = None
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        need(not any(ord(c) < 32 and c != "\t" for c in line), "Control character: " + path)
        if line[0].isspace():
            need(previous == "remarks", "Only remarks may continue on another line: " + path)
            attrs[previous][-1] += "\n" + line.strip()
            continue
        match = re.fullmatch(r"([a-z][a-z0-9-]*):[ \t]*(\S.*)", line)
        need(match, "Malformed attribute in " + path)
        previous, value = match.groups()
        attrs[previous].append(value.rstrip())
    need(bool(attrs), "Empty object: " + path)
    return dict(attrs)


def render(attrs):
    return "".join(f"{key + ':':<20}{value.replace(chr(10), chr(10) + ' ' * 20)}\n"
                   for key, values in attrs.items() for value in values)


def schemas(snapshot):
    result = {}
    for path, text in snapshot.items():
        if not path.startswith("data/schema/"):
            continue
        attrs = parse(text, path)
        need(set(attrs) == {"schema", "ref", "key"}, "Invalid schema: " + path)
        need(len(attrs["schema"]) == len(attrs["ref"]) == 1, "Repeated schema identity")
        name = attrs["schema"][0]
        need(name.startswith("dn64.") and path == "data/schema/" + name, "Schema filename mismatch")
        kind = name.removeprefix("dn64.")
        need(attrs["ref"] == [name], "Schema ref mismatch")
        rules = {}
        for line in attrs["key"]:
            field, *options = line.split()
            need(field not in rules and options, "Invalid schema field: " + field)
            need(all(o in {"required", "optional", "single", "multiple", "primary"}
                     or re.fullmatch(r"lookup=[a-z,-]+", o) for o in options), "Unknown schema rule")
            need(("required" in options) != ("optional" in options), "Missing requirement rule")
            need(("single" in options) != ("multiple" in options), "Missing cardinality rule")
            rules[field] = options
        need(sum("primary" in v for v in rules.values()) == 1, "Schema needs one primary key")
        result[kind] = rules
    need(bool(result), "No schemas found")
    return result


@dataclass
class Object:
    kind: str
    name: str
    path: str
    attrs: dict

    def values(self, key):
        return self.attrs.get(key, [])

    def get(self, key, default=None):
        return self.values(key)[0] if self.values(key) else default


def asn(value):
    need(bool(re.fullmatch(r"AS[1-9][0-9]*", value)), "Invalid ASN: " + value)
    number = int(value[2:])
    need(4200000000 <= number <= 4294967294 or 64512 <= number <= 65534,
         "Only private ASNs are supported")
    return number


def network(value, family):
    try:
        net = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise Invalid("Invalid canonical prefix: " + value) from exc
    need(net.version == family and str(net) == value, "Use canonical prefix notation: " + value)
    return net


def prefix_filename(value):
    return value.replace(":", "-").replace("/", "_")


def public_key(value):
    parts = value.split()
    need(len(parts) == 2 and parts[0] == "ssh-ed25519", "auth must be an SSH Ed25519 public key without comment")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except ValueError as exc:
        raise Invalid("Invalid public key encoding") from exc
    need(len(blob) == 51 and blob[:19] == b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20", "Invalid Ed25519 public key")
    return value


def objects(snapshot, rules):
    result = {}
    for path, text in snapshot.items():
        _, kind, filename = path.split("/")
        if kind == "schema":
            continue
        need(kind in rules, "Unknown object type: " + kind)
        attrs = parse(text, path)
        first_key = "domain" if kind == "dns" else kind
        need(next(iter(attrs)) == first_key, "Object must start with " + first_key + ": " + path)
        for key, options in rules[kind].items():
            need("required" not in options or key in attrs, f"Missing {key}: {path}")
            need("single" not in options or len(attrs.get(key, [])) <= 1, f"Repeated {key}: {path}")
        need(set(attrs) <= set(rules[kind]), "Unknown fields in " + path)
        primary = next(k for k, v in rules[kind].items() if "primary" in v)
        name = attrs[primary][0]
        need(attrs.get("source") == ["DN64"], "source must be DN64: " + path)
        obj = Object(kind, name, path, attrs)
        expected = name
        if kind in {"inetnum", "inet6num", "route", "route6"}:
            prefix = obj.get("cidr") if kind == "inetnum" else name
            net = network(prefix, 4 if kind in {"inetnum", "route"} else 6)
            expected = prefix_filename(str(net))
            if kind == "inetnum":
                need(name == f"{net.network_address} - {net.broadcast_address}", "inetnum range/cidr mismatch")
        elif kind == "as-block":
            parts = name.split(" - ")
            need(len(parts) == 2 and asn(parts[0]) <= asn(parts[1]), "Invalid AS block")
            expected = "-".join(parts)
        elif kind == "aut-num":
            asn(name)
        elif kind == "dns":
            need(name == name.lower() and len(name) <= 253 and bool(re.fullmatch(
                r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*dn64", name)), "Domain must be under dn64")
        else:
            need(bool(re.fullmatch(r"[A-Z][A-Z0-9-]{0,63}", name)), "Invalid object handle: " + path)
        need(filename == expected, "Filename must be " + expected + ": " + path)
        if kind == "mntner":
            need(name.endswith("-MNT"), "Maintainer handle must end in -MNT")
            need(obj.values("mnt-by") == [name], "Maintainers must be self-maintained")
            for key in obj.values("auth"):
                public_key(key)
        if kind in {"person", "role"}:
            need(name.endswith("-DN64"), "Contact handle must end in -DN64")
        for email in obj.values("e-mail"):
            need(bool(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email)), "Invalid contact email")
        need((kind, name) not in result, "Duplicate object: " + name)
        result[kind, name] = obj
    for obj in result.values():
        for field, options in rules[obj.kind].items():
            lookup = next((v[7:].split(",") for v in options if v.startswith("lookup=")), None)
            if lookup:
                for value in obj.values(field):
                    need(any((kind, value) in result for kind in lookup),
                         f"Missing reference {field}={value}: {obj.path}")
    return result


def maintainers(obj):
    return set(obj.values("mnt-by"))


def covering_pools(net, pools):
    return sorted((o for n, o in pools if n.version == net.version and net.subnet_of(n)),
                  key=lambda o: network(o.get("cidr") if o.kind == "inetnum" else o.name, net.version).prefixlen,
                  reverse=True)


def validate(snapshot, rule_snapshot=None):
    registry = objects(snapshot, schemas(rule_snapshot or snapshot))
    need(("mntner", ADMIN) in registry and ("registry", "DN64") in registry, "Missing bootstrap registry/maintainer")
    need(registry["registry", "DN64"].values("mnt-by") == [ADMIN], "Registry must be maintained by DN64-MNT")
    pools, assigned, blocks = [], [], []
    for obj in registry.values():
        if obj.kind == "as-block":
            lo, hi = [asn(v) for v in obj.name.split(" - ")]
            need((64512 <= lo <= hi <= 65534) or (4200000000 <= lo <= hi <= 4294967294),
                 "AS block cannot span public ASN space")
            need(obj.get("policy") in {"open", "closed", "reserved"}, "Invalid AS block policy")
            blocks.append((lo, hi, obj))
        if obj.kind not in {"inetnum", "inet6num"}:
            continue
        net = network(obj.get("cidr") if obj.kind == "inetnum" else obj.name, 4 if obj.kind == "inetnum" else 6)
        need(any(net.subnet_of(ipaddress.ip_network(p)) for p in
                 (["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] if net.version == 4 else ["fd00::/8"])),
             "Only RFC1918 IPv4 / locally assigned ULA IPv6 are allowed")
        status = obj.get("status")
        need(status in {"ALLOCATED", "ASSIGNED"}, "Invalid allocation status")
        if status == "ALLOCATED":
            need(obj.get("policy") in {"open", "closed", "reserved"}, "Pool requires policy")
            try:
                lower, upper = int(obj.get("min-length")), int(obj.get("max-length"))
            except (TypeError, ValueError) as exc:
                raise Invalid("Pool needs min-length and max-length") from exc
            need(net.prefixlen <= lower <= upper <= net.max_prefixlen, "Invalid prefix length policy")
            pools.append((net, obj))
        else:
            need(not any(obj.values(k) for k in ["policy", "min-length", "max-length"]), "Assignment cannot set pool policy")
            assigned.append((net, obj))
    for i, (lo, hi, obj) in enumerate(blocks):
        need(not any(lo <= other_hi and other_lo <= hi for other_lo, other_hi, _ in blocks[:i]), "Overlapping AS blocks")
    for group, label in [(pools, "pools"), (assigned, "assignments")]:
        for i, (net, obj) in enumerate(group):
            need(not any(net.version == other.version and net.overlaps(other) for other, _ in group[:i]),
                 "Overlapping " + label + ": " + obj.path)
    for net, obj in assigned:
        parent = covering_pools(net, pools)
        need(parent, "Assignment outside registered pools: " + obj.path)
        parent = parent[0]
        need(parent.get("policy") == "open", "Assignment in a closed/reserved pool")
        need(int(parent.get("min-length")) <= net.prefixlen <= int(parent.get("max-length")), "Assignment prefix length violates policy")
    for obj in registry.values():
        if obj.kind == "aut-num":
            number = asn(obj.name)
            need(any(lo <= number <= hi and block.get("policy") == "open" for lo, hi, block in blocks),
                 "ASN outside an open AS block: " + obj.name)
        elif obj.kind in {"route", "route6"}:
            net = network(obj.name, 4 if obj.kind == "route" else 6)
            parents = [o for n, o in assigned if n.version == net.version and net.subnet_of(n)]
            need(parents, "Route lacks an assigned parent: " + obj.path)
            need(maintainers(obj) <= maintainers(parents[0]), "Route maintainers must own the assigned prefix")
            origin = registry["aut-num", obj.get("origin")]
            need(bool(maintainers(obj) & maintainers(origin)), "Route origin must share an authorized maintainer")
        elif obj.kind == "dns":
            for nserver in obj.values("nserver"):
                parts = nserver.split()
                need(1 <= len(parts) <= 2 and bool(re.fullmatch(
                    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]+", parts[0])), "Invalid nameserver")
                if len(parts) == 2:
                    try:
                        ipaddress.ip_address(parts[1])
                    except ValueError as exc:
                        raise Invalid("Invalid nameserver glue") from exc
                if parts[0] == obj.name or parts[0].endswith("." + obj.name):
                    need(len(parts) == 2, "In-bailiwick nameserver needs glue")
            for ds in obj.values("ds-rdata"):
                parts = ds.split()
                need(len(parts) == 4 and all(v.isdecimal() for v in parts[:3]), "Invalid DS record")
                need(0 <= int(parts[0]) <= 65535 and 0 <= int(parts[1]) <= 255 and
                     int(parts[2]) in {2, 4} and bool(re.fullmatch(r"[0-9A-Fa-f]+", parts[3])) and
                     len(parts[3]) == {2: 64, 4: 96}[int(parts[2])], "Invalid DS digest")
    domains = [o for o in registry.values() if o.kind == "dns"]
    for obj in domains:
        parents = sorted((p for p in domains if obj.name.endswith("." + p.name)), key=lambda p: len(p.name), reverse=True)
        if parents:
            need(maintainers(obj) <= maintainers(parents[0]), "Subdomain must be maintained by parent owner")
    return registry


def verify_signature(repo, commit, keys):
    """Try trusted maintainer keys against the exact Git commit signature."""
    if not keys:
        return False
    header = git(repo, "cat-file", "commit", commit).stdout.split(b"\n\n", 1)[0]
    if b"\ngpgsig -----BEGIN SSH SIGNATURE-----\n" not in header:
        return False
    with tempfile.TemporaryDirectory(prefix="dn64-signers-") as folder:
        allowed = Path(folder) / "allowed_signers"
        allowed.write_text("".join("dn64 " + public_key(key) + "\n" for key in sorted(keys)), encoding="utf-8")
        result = git(repo, "-c", "gpg.format=ssh", "-c", f"gpg.ssh.allowedSignersFile={allowed}",
                     "-c", "gpg.ssh.program=ssh-keygen", "verify-commit", commit, check=False)
        return result.returncode == 0


def authorize(repo, base, head, before, after, before_objects, after_objects):
    need(git(repo, "merge-base", "--is-ancestor", base, head, check=False).returncode == 0,
         "Rebase your branch on the current main before submitting")
    commits = git(repo, "rev-list", "--reverse", base + ".." + head).stdout.decode().splitlines()
    need(len(commits) == 1, "Squash changes into exactly one signed commit on current main")
    parents = git(repo, "rev-list", "--parents", "-n", "1", head).stdout.decode().split()
    need(len(parents) == 2 and parents[1] == base, "PR must contain one non-merge commit directly on current main")
    changed = git(repo, "diff", "--name-only", "-z", base, head).stdout.decode().split("\0")
    changed = [p for p in changed if p]
    need(bool(changed), "PR contains no changes")
    admin_keys = set(before_objects["mntner", ADMIN].values("auth"))
    admin_signed = verify_signature(repo, head, admin_keys)
    signature_cache = {frozenset(admin_keys): admin_signed}
    before_paths = {o.path: o for o in before_objects.values()}
    after_paths = {o.path: o for o in after_objects.values()}

    def signed_by(owners, registry):
        for owner in owners:
            keys = frozenset(registry["mntner", owner].values("auth"))
            if keys not in signature_cache:
                signature_cache[keys] = verify_signature(repo, head, keys)
            if signature_cache[keys]:
                return True
        return False

    for path in changed:
        old, new = before_paths.get(path), after_paths.get(path)
        governance = (not path.startswith("data/") or path.startswith("data/schema/") or
                      (new or old) is None or (new or old).kind in {"registry", "as-block"} or
                      any(o and o.get("status") == "ALLOCATED" for o in [old, new]))
        if governance:
            need(admin_signed, "Governance/pool changes require a DN64-MNT signature: " + repr(path))
            continue
        # New maintainers prove possession; existing objects always trust the old snapshot.
        if old:
            need(admin_signed or signed_by(maintainers(old), before_objects), "Not authorized by existing owner: " + path)
            if new and maintainers(new) != maintainers(old):
                need(admin_signed, "Ownership transfer requires administrator review/signature: " + path)
        elif new:
            need(admin_signed or signed_by(maintainers(new), after_objects), "New object must be signed by its maintainer: " + path)
        if new and new.kind == "mntner" and old and set(new.values("auth")) != set(old.values("auth")):
            need(admin_signed or bool(set(new.values("auth")) & set(old.values("auth"))),
                 "Keep an old key during rotation; replacing all keys requires an admin-signed recovery")
        if new and new.kind in {"route", "route6"}:
            family = 4 if new.kind == "route" else 6
            net = network(new.name, family)
            # A new route cannot acquire somebody else's prefix by editing its mnt-by.
            for candidate in before_objects.values():
                if candidate.kind == ("inetnum" if family == 4 else "inet6num") and candidate.get("status") == "ASSIGNED":
                    parent = network(candidate.get("cidr") if family == 4 else candidate.name, family)
                    if net.subnet_of(parent):
                        need(admin_signed or signed_by(maintainers(candidate), before_objects), "Route needs prefix-owner authorization")
            old_origin = before_objects.get(("aut-num", new.get("origin")))
            if old_origin:
                need(admin_signed or signed_by(maintainers(old_origin), before_objects), "Route needs origin-AS owner authorization")


def check_pr(repo, base, head):
    for revision in [base, head]:
        need(bool(re.fullmatch(r"[0-9a-f]{40}", revision)), "Use a full 40-character commit SHA")
    before, after = git_snapshot(repo, base), git_snapshot(repo, head)
    before_objects = validate(before)
    # The trusted base schema is mandatory even when the PR modifies schemas.
    after_objects = validate(after, before)
    validate(after)
    authorize(repo, base, head, before, after, before_objects, after_objects)
    return after_objects


def export(registry):
    return {"source": "DN64", "objects": [dict(type=o.kind, name=o.name, attributes=o.attrs)
            for o in sorted(registry.values(), key=lambda o: o.path)]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["check", "format", "check-pr", "export", "ula", "whois"])
    parser.add_argument("query", nargs="?")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--base")
    parser.add_argument("--head")
    args = parser.parse_args(argv)
    try:
        if args.command == "ula":
            print(ipaddress.IPv6Network((int.from_bytes(b"\xfd" + secrets.token_bytes(5) + b"\0" * 10), 48)))
            return 0
        if args.command == "check-pr":
            need(args.base and args.head, "check-pr needs --base SHA --head SHA")
            registry = check_pr(args.root, args.base, args.head)
        else:
            snapshot = working_snapshot(args.root)
            if args.command == "format":
                # Parse everything before writing anything. This command deliberately does not mask semantic errors.
                formatted = {path: render(parse(text, path)) for path, text in snapshot.items()}
                for path, text in formatted.items():
                    if path.startswith("data/schema/"):
                        continue
                    if args.query and args.query not in parse(text).get("mnt-by", []):
                        continue
                    (args.root / path).write_text(text, encoding="utf-8", newline="\n")
                return 0
            registry = validate(snapshot)
        if args.command == "export":
            print(json.dumps(export(registry), ensure_ascii=False, indent=2))
        elif args.command == "whois":
            need(bool(args.query), "whois needs an object handle, ASN, prefix or domain")
            matches = [o for o in registry.values() if o.name.casefold() == args.query.casefold() or o.get("cidr") == args.query]
            need(matches, "Object not found")
            print("\n".join(render(o.attrs) for o in matches), end="")
        else:
            if args.query:
                need(("mntner", args.query) in registry, "Unknown maintainer")
            print(f"PASS: {len(registry)} DN64 objects; schema, references and allocation policies valid")
        return 0
    except (Invalid, OSError, UnicodeError, subprocess.CalledProcessError) as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
