#!/usr/bin/env python3
"""Prepare a complete dual-stack DN64 registration; preview by default."""
import argparse
import ipaddress
from pathlib import Path
import re
import sys

from registry import (ROOT, Invalid, asn, need, network,
                      prefix_filename, public_key, render, validate, working_snapshot)


def registration(root, handle, email, key, requested_asn=None, ipv4=None, ipv6=None):
    need(bool(re.fullmatch(r"[A-Z][A-Z0-9-]{0,40}", handle)), "Handle must be 1-41 uppercase letters, digits or hyphens")
    need(not handle.endswith(("-MNT", "-DN64")), "Use the bare handle, without -MNT/-DN64")
    need("\n" not in email and "\r" not in email, "Invalid email")
    key = " ".join(key.split()[:2])
    public_key(key)
    snapshot = working_snapshot(root)
    registry = validate(snapshot)
    mnt, person = handle + "-MNT", handle + "-DN64"
    need(("mntner", mnt) not in registry, "Maintainer already registered")
    if requested_asn:
        chosen_asn = requested_asn if requested_asn.startswith("AS") else "AS" + requested_asn
        asn(chosen_asn)
    else:
        used = {asn(o.name) for o in registry.values() if o.kind == "aut-num"}
        chosen_asn = None
        for obj in registry.values():
            if obj.kind == "as-block" and obj.get("policy") == "open":
                lo, hi = [asn(v) for v in obj.name.split(" - ")]
                # Skip used values without iterating enormous ASN ranges.
                candidate = lo
                while candidate in used and candidate <= hi:
                    candidate += 1
                if candidate <= hi:
                    chosen_asn = "AS" + str(candidate)
                    break
        need(chosen_asn, "No available ASN")
    if ipv4:
        net4 = network(ipv4, 4)
    else:
        net4 = None
        used = [network(o.get("cidr"), 4) for o in registry.values() if o.kind == "inetnum" and o.get("status") == "ASSIGNED"]
        for obj in registry.values():
            if obj.kind == "inetnum" and obj.get("status") == "ALLOCATED" and obj.get("policy") == "open":
                pool = network(obj.get("cidr"), 4)
                for candidate in pool.subnets(new_prefix=int(obj.get("min-length"))):
                    if not any(candidate.overlaps(n) for n in used):
                        net4 = candidate
                        break
                if net4:
                    break
        need(net4, "No available IPv4 prefix")
    if ipv6:
        net6 = network(ipv6, 6)
    else:
        import secrets
        used = [network(o.name, 6) for o in registry.values() if o.kind == "inet6num" and o.get("status") == "ASSIGNED"]
        for _ in range(100):
            net6 = ipaddress.IPv6Network((int.from_bytes(b"\xfd" + secrets.token_bytes(5) + b"\0" * 10), 48))
            if not any(net6.overlaps(n) for n in used):
                break
        else:
            raise Invalid("Unable to generate unused ULA prefix")
    owners = [("mnt-by", mnt), ("source", "DN64")]
    contacts = [("admin-c", person), ("tech-c", person)]
    result = {}

    def add(kind, filename, pairs):
        attrs = {}
        for field, value in pairs:
            attrs.setdefault(field, []).append(value)
        result["data/" + kind + "/" + filename] = render(attrs)

    add("person", person, [("person", handle), ("nic-hdl", person), ("e-mail", email), *owners])
    add("mntner", mnt, [("mntner", mnt), *contacts, ("auth", key), *owners])
    add("aut-num", chosen_asn, [("aut-num", chosen_asn), ("as-name", handle + "-AS"), *contacts, *owners])
    add("inetnum", prefix_filename(str(net4)), [("inetnum", f"{net4.network_address} - {net4.broadcast_address}"),
        ("cidr", str(net4)), ("netname", handle + "-IPV4"), ("status", "ASSIGNED"), *contacts, *owners])
    add("inet6num", prefix_filename(str(net6)), [("inet6num", str(net6)), ("netname", handle + "-IPV6"),
        ("status", "ASSIGNED"), *contacts, *owners])
    add("route", prefix_filename(str(net4)), [("route", str(net4)), ("origin", chosen_asn), *owners])
    add("route6", prefix_filename(str(net6)), [("route6", str(net6)), ("origin", chosen_asn), *owners])
    need(not (set(result) & set(snapshot)), "Selected resource already exists")
    validate(dict(snapshot, **result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handle", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--key", required=True, type=Path, help="SSH Ed25519 PUBLIC key file")
    parser.add_argument("--asn")
    parser.add_argument("--ipv4")
    parser.add_argument("--ipv6")
    parser.add_argument("--write", action="store_true", help="Write objects instead of previewing")
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        result = registration(args.root, args.handle, args.email, args.key.read_text(encoding="utf-8"), args.asn, args.ipv4, args.ipv6)
        for path, text in result.items():
            if args.write:
                dest = args.root / path
                dest.parent.mkdir(parents=True, exist_ok=True)
                with dest.open("x", encoding="utf-8", newline="\n") as stream:
                    stream.write(text)
            else:
                print("# " + path + "\n" + text)
        if args.write:
            print(f"Created {len(result)} objects. Check, sign your commit, and submit a PR.")
        return 0
    except (Invalid, OSError) as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
