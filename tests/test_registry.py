"""Policy and real SSH/Git authorization regression tests, no network access."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "utils"))
import registry as r
from new_registration import registration


def command(*args, cwd=None):
    return subprocess.run(args, cwd=cwd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class RegistryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix="dn64-tests-")
        cls.folder = Path(cls.work.name)
        cls.keys = {}
        for name in ["admin", "alice", "mallory"]:
            path = cls.folder / name
            command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path))
            cls.keys[name] = path.with_suffix(".pub").read_text().split()[:2]
        cls.seed = r.working_snapshot(ROOT / "tests/fixtures")
        admin = cls.seed["data/mntner/DN64-MNT"]
        oldkey = r.parse(admin)["auth"][0]
        cls.seed["data/mntner/DN64-MNT"] = admin.replace(oldkey, " ".join(cls.keys["admin"]))

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dn64-case-", dir=self.folder)
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.snapshot = dict(self.seed)
        self.write(self.snapshot)

    def write(self, snapshot):
        for path, text in snapshot.items():
            dest = self.root / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(text, encoding="utf-8", newline="\n")

    def member(self, name="ALICE", key="alice", ipv4="10.64.1.0/24", ipv6="fd12:3456:789a::/48", number="4206400001"):
        return registration(self.root, name, name.lower() + "@example.net", " ".join(self.keys[key]), number, ipv4, ipv6)

    def registered(self):
        self.snapshot.update(self.member())
        self.write(self.snapshot)

    def init_git(self):
        command("git", "init", "-b", "main", str(self.root))
        for key, value in {"user.name": "DN64 tests", "user.email": "tests@example.net", "gpg.format": "ssh",
                           "core.autocrlf": "false", "commit.gpgsign": "false"}.items():
            r.git(self.root, "config", key, value)
        r.git(self.root, "add", "data")
        r.git(self.root, "commit", "-m", "bootstrap")
        return r.git(self.root, "rev-parse", "HEAD").stdout.decode().strip()

    def commit(self, key="alice", signed=True):
        r.git(self.root, "add", "-A")
        args = ["-c", "user.signingkey=" + str(self.folder / key), "commit", "-m", "registration"]
        if signed:
            args.append("-S")
        r.git(self.root, *args)
        return r.git(self.root, "rev-parse", "HEAD").stdout.decode().strip()

    def invalid(self, snapshot, pattern):
        with self.assertRaisesRegex(r.Invalid, pattern):
            r.validate(snapshot)

    def test_bootstrap_and_dual_stack_registration(self):
        self.registered()
        objects = r.validate(self.snapshot)
        self.assertEqual(len(objects), 13)
        self.assertEqual(objects["route6", "fd12:3456:789a::/48"].get("origin"), "AS4206400001")

    def test_generator_does_not_write_on_preview(self):
        files = list((self.root / "data").rglob("*"))
        generated = registration(self.root, "ALICE", "alice@example.net", " ".join(self.keys["alice"]))
        self.assertEqual(len(generated), 7)
        self.assertEqual(files, list((self.root / "data").rglob("*")))
        self.assertIn("data/aut-num/AS4206400000", generated)

    def test_duplicate_resource_rejected(self):
        self.registered()
        with self.assertRaisesRegex(r.Invalid, "already exists"):
            self.member("BOB", "mallory")

    def test_overlapping_assignment_rejected(self):
        self.registered()
        bad = dict(self.snapshot)
        text = self.snapshot["data/inetnum/10.64.1.0_24"]
        bad["data/inetnum/10.64.1.0_25"] = text.replace("10.64.1.255", "10.64.1.127").replace("10.64.1.0/24", "10.64.1.0/25")
        self.invalid(bad, "Overlapping assignments")

    def test_prefix_length_policy(self):
        with self.assertRaisesRegex(r.Invalid, "prefix length"):
            self.member(ipv4="10.64.0.0/23")

    def test_prefix_outside_pool(self):
        with self.assertRaisesRegex(r.Invalid, "outside registered pools"):
            self.member(ipv4="10.65.1.0/24")

    def test_asn_outside_pool(self):
        with self.assertRaisesRegex(r.Invalid, "outside an open AS block"):
            self.member(number="4206500001")

    def test_missing_reference(self):
        self.registered()
        del self.snapshot["data/person/ALICE-DN64"]
        self.invalid(self.snapshot, "Missing reference")

    def test_route_without_allocation(self):
        self.registered()
        del self.snapshot["data/inet6num/fd12-3456-789a--_48"]
        self.invalid(self.snapshot, "assigned parent")

    def test_noncanonical_prefix_and_filename(self):
        self.registered()
        path = "data/route6/fd12-3456-789a--_48"
        self.snapshot[path] = self.snapshot[path].replace("fd12:3456:789a::/48", "fd12:3456:789a:0000::/48")
        self.invalid(self.snapshot, "canonical prefix")

    def test_empty_unknown_and_duplicate_fields(self):
        self.invalid(dict(self.snapshot, **{"data/person/EMPTY-DN64": ""}), "Empty object")
        bad = dict(self.snapshot)
        bad["data/person/LICHENLANG-DN64"] += "unknown:            value\n"
        self.invalid(bad, "Unknown fields")
        bad = dict(self.snapshot)
        bad["data/person/LICHENLANG-DN64"] += "source:             DN64\n"
        self.invalid(bad, "Repeated source")

    def test_foreign_route_origin(self):
        self.registered()
        bob = self.member("BOB", "mallory", "10.64.2.0/24", "fd23:4567:89ab::/48", "4206400002")
        self.snapshot.update(bob)
        self.snapshot["data/route/10.64.1.0_24"] = self.snapshot["data/route/10.64.1.0_24"].replace("AS4206400001", "AS4206400002")
        self.invalid(self.snapshot, "origin must share")

    def test_closed_pool(self):
        self.registered()
        self.snapshot["data/as-block/AS4206400000-AS4206409999"] = self.snapshot["data/as-block/AS4206400000-AS4206409999"].replace("open", "reserved")
        self.invalid(self.snapshot, "outside an open AS block")

    def test_ipv6_filename_windows_roundtrip(self):
        self.assertEqual(r.prefix_filename("fd12:3456:789a::/48"), "fd12-3456-789a--_48")

    def test_dns_glue_and_ds(self):
        self.registered()
        path = "data/dns/alice.dn64"
        self.snapshot[path] = r.render({"domain": ["alice.dn64"], "nserver": ["ns1.alice.dn64 10.64.1.1"],
            "admin-c": ["ALICE-DN64"], "tech-c": ["ALICE-DN64"], "mnt-by": ["ALICE-MNT"], "source": ["DN64"]})
        r.validate(self.snapshot)
        self.snapshot[path] = self.snapshot[path].replace("ns1.alice.dn64 10.64.1.1", "ns1.alice.dn64")
        self.invalid(self.snapshot, "needs glue")

    def test_real_signed_new_registration(self):
        base = self.init_git()
        self.write(self.member())
        head = self.commit()
        self.assertEqual(len(r.check_pr(self.root, base, head)), 13)

    def test_unsigned_registration_rejected(self):
        base = self.init_git()
        self.write(self.member())
        head = self.commit(signed=False)
        with self.assertRaisesRegex(r.Invalid, "must be signed"):
            r.check_pr(self.root, base, head)

    def test_wrong_key_registration_rejected(self):
        base = self.init_git()
        self.write(self.member())
        head = self.commit("mallory")
        with self.assertRaisesRegex(r.Invalid, "must be signed"):
            r.check_pr(self.root, base, head)

    def test_existing_owner_cannot_be_replaced_by_new_key(self):
        self.registered()
        base = self.init_git()
        path = "data/mntner/ALICE-MNT"
        self.write({path: self.snapshot[path].replace(" ".join(self.keys["alice"]), " ".join(self.keys["mallory"]))})
        head = self.commit("mallory")
        with self.assertRaisesRegex(r.Invalid, "existing owner"):
            r.check_pr(self.root, base, head)

    def test_add_backup_key_with_old_key(self):
        self.registered()
        base = self.init_git()
        path = "data/mntner/ALICE-MNT"
        self.write({path: self.snapshot[path] + "auth:               " + " ".join(self.keys["mallory"]) + "\n"})
        head = self.commit("alice")
        r.check_pr(self.root, base, head)

    def test_remove_all_old_keys_requires_admin_recovery(self):
        self.registered()
        base = self.init_git()
        path = "data/mntner/ALICE-MNT"
        self.write({path: self.snapshot[path].replace(" ".join(self.keys["alice"]), " ".join(self.keys["mallory"]))})
        head = self.commit("alice")
        with self.assertRaisesRegex(r.Invalid, "Keep an old key"):
            r.check_pr(self.root, base, head)

    def test_admin_recovery(self):
        self.registered()
        base = self.init_git()
        path = "data/mntner/ALICE-MNT"
        self.write({path: self.snapshot[path].replace(" ".join(self.keys["alice"]), " ".join(self.keys["mallory"]))})
        head = self.commit("admin")
        r.check_pr(self.root, base, head)

    def test_validator_change_requires_admin_signature(self):
        base = self.init_git()
        (self.root / "utils").mkdir()
        (self.root / "utils/registry.py").write_text("raise SystemExit(0)\n")
        head = self.commit("mallory")
        with self.assertRaisesRegex(r.Invalid, "Governance/pool changes"):
            r.check_pr(self.root, base, head)

    def test_schema_bypass_uses_base_schema(self):
        base = self.init_git()
        generated = self.member()
        generated["data/schema/dn64.mntner"] = self.snapshot["data/schema/dn64.mntner"].replace("auth required", "auth optional")
        generated["data/mntner/ALICE-MNT"] = "\n".join(line for line in generated["data/mntner/ALICE-MNT"].splitlines() if not line.startswith("auth:")) + "\n"
        self.write(generated)
        head = self.commit("mallory")
        with self.assertRaisesRegex(r.Invalid, "Missing auth"):
            r.check_pr(self.root, base, head)

    def test_multiple_commits_rejected(self):
        base = self.init_git()
        self.write(self.member())
        self.commit()
        (self.root / "note.txt").write_text("additional change")
        head = self.commit()
        with self.assertRaisesRegex(r.Invalid, "exactly one"):
            r.check_pr(self.root, base, head)

    @unittest.skipIf(sys.platform == "win32", "Git symlink fixture runs on Linux CI")
    def test_symlink_blob_is_rejected_without_following(self):
        base = self.init_git()
        (self.root / "data/person/ATTACK-DN64").symlink_to("/etc/passwd")
        head = self.commit("mallory")
        with self.assertRaisesRegex(r.Invalid, "regular files"):
            r.check_pr(self.root, base, head)

    def test_ownership_transfer_needs_admin(self):
        self.registered()
        self.snapshot.update(self.member("BOB", "mallory", "10.64.2.0/24", "fd23:4567:89ab::/48", "4206400002"))
        self.write(self.snapshot)
        base = self.init_git()
        path = "data/person/ALICE-DN64"
        self.write({path: self.snapshot[path].replace("ALICE-MNT", "BOB-MNT")})
        head = self.commit("alice")
        with self.assertRaisesRegex(r.Invalid, "Ownership transfer"):
            r.check_pr(self.root, base, head)


if __name__ == "__main__":
    unittest.main()
