"""Offline regression suite. No live services, network, keys or global paths."""
import dataclasses
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from core import (Context, Paths, Failure, NODE, STACK, FILES, KEYS, logged, bounded_process,
                  digest, peer_uri, safe_config, atomic, read_regular)
import checks
import management
import telemetry
import recovery
import main

PIN = "1" * 64
URI = "tls://192.0.2.1:443?key=" + PIN + "&maxbackoff=30s"


class ConsoleTests(unittest.TestCase):
    @logged
    def test_offline_root_gate_precedes_fixture_creation(self):
        ctx = Context(require_root=True)
        with patch("core.os.geteuid", return_value=1000), patch("tests.run_suite") as suite:
            with self.assertRaisesRegex(Failure, "root_required"):
                main.selftest(ctx, offline=True)
            suite.assert_not_called()

    @logged
    def setUp(self):
        here = Path(__file__).resolve().parent
        folder = here.parents[1] / "data" / "console-fix-20261013" / "tests" if "/Work/" in str(here) else Path("/var/lib/yggdrasil-lab/selftests")
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.tmp = tempfile.TemporaryDirectory(dir=folder)
        root = Path(self.tmp.name)
        self.paths = Paths(etc=root/"etc", units=root/"units", state=root/"state", runtime=root/"runtime",
                           node_sock=root/"run/node/admin.sock", stack_sock=root/"run/stack/admin.sock",
                           node=str(root/"node"), stack=str(root/"stack"), decoder=str(root/"decoder"), ctl=str(root/"ctl"))
        for p in (self.paths.etc, self.paths.units, self.paths.state, self.paths.runtime): p.mkdir()
        self.ctx = Context(self.paths, runner=self.runner, require_root=False)
        self.responses = {}
        self.calls = []
        self.failed_command = None
        self.ps = [{"remote": URI, "up": True, "inbound": False, "latency": 1000000}]
        config = {"Peers": [URI, URI.replace("192.0.2.1", "192.0.2.2"), URI.replace("192.0.2.1", "192.0.2.3")],
                  "IfName": "none", "Listen": [], "MulticastInterfaces": [], "InterfacePeers": {},
                  "NodeInfoPrivacy": True, "AdminListen": "unix:///run/fake/admin.sock", "PrivateKeyPath": "/run/credentials/fake/key"}
        for n in FILES:
            atomic(self.paths.etc/n, json.dumps(config) if n.endswith("conf") else "direct\n" if n == "mode" else "fixture gate\n")
        for n in (NODE, STACK, "ygg-metrics.timer", "ygg-metrics.service"): atomic(self.paths.units/n, "fixture unit")
        for p in (Path(self.paths.node), Path(self.paths.stack)): atomic(p, "fixture binary")
        for n in KEYS: atomic(self.paths.etc/n, "synthetic test fixture, not a key")
        required = [Path(self.paths.node), Path(self.paths.stack), self.paths.units/NODE, self.paths.units/STACK,
                    *(self.paths.etc/n for n in FILES if n != "mode")]
        atomic(self.paths.etc/"integrity.manifest", "".join(digest(read_regular(p))+"  "+str(p)+"\n" for p in required))

    @logged
    def tearDown(self):
        self.tmp.cleanup()

    @logged
    def runner(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[0] == self.paths.decoder:
            return subprocess.CompletedProcess(argv, 0, kwargs["input"], b"")
        if self.failed_command and self.failed_command in argv: return subprocess.CompletedProcess(argv, 1, b"", b"SECRET_DO_NOT_LOG")
        if argv[0] == self.paths.ctl:
            method = argv[3]
            value = self.responses.get(method, {"peers": self.ps} if method == "getPeers" else {"key": "2"*64} if method == "getSelf" else {})
            return subprocess.CompletedProcess(argv, 0, json.dumps(value).encode(), b"")
        if "systemctl" in argv[0]:
            data = "ActiveState=active\nSubState=running\nMainPID=" + ("1002" if STACK in argv else "1001") + "\nNRestarts=0\nExecMainStatus=0\n"
        elif "mullvad" in argv[0]: data = "Excluded PIDs:\n1001\n1002\n"
        elif "ss" == Path(argv[0]).name:
            data = '\n'.join(f'tcp ESTAB 0 0 10.0.0.2:{p} 192.0.2.1:443 users:(("ygg",pid={p},fd=1))' for p in (1001,1002))
        elif "conntrack" in argv[0]:
            data = '\n'.join(f'tcp 6 100 ESTABLISHED src=10.0.0.2 dst=192.0.2.1 sport={p} dport=443 src=192.0.2.1 dst=10.0.0.2 sport=443 dport={p} mark=3905 use=1' for p in (1001,1002))
        elif "curl" in argv[0]: data = "200 0.001 0.05 0.1 0.2"
        else: data = ""
        return subprocess.CompletedProcess(argv, 0, data.encode(), b"")

    @logged
    def test_peer_canonical(self):
        uri, hp = peer_uri("tls://192.0.2.1:443?key=" + PIN)
        self.assertEqual(hp, "192.0.2.1:443")
        self.assertEqual(uri, URI)

    @logged
    def test_peer_bad_inputs(self):
        for uri in (URI.replace("192.0.2.1", "999.0.2.1"), URI.replace("192.0.2.1", "host.example"),
                    URI.replace(":443", ":99999"), URI+"&key="+PIN, URI+"&bad", URI+"&evil=1",
                    URI.replace("tls://", "tls://user@"), URI+"#fragment", URI+"\n", URI.replace("tls://", "ftp://")):
            with self.subTest(uri=uri), self.assertRaises(Failure): peer_uri(uri)

    @logged
    def test_ws_requires_force(self):
        with self.assertRaises(Failure): peer_uri(URI.replace("tls://", "wss://"))
        self.assertEqual(peer_uri(URI.replace("tls://", "wss://"), True)[1], "192.0.2.1:443")
        with self.assertRaises(Failure): peer_uri(URI.replace("tls://", "wss://")+"&origin=https%3A%2F%2Fuser%3Apassword%40example.com",True)

    @logged
    def test_guard_structured_public_listener(self):
        c = self.ctx.config("yggdrasil-lab.conf")
        self.assertEqual(safe_config(c), [])
        for k, v in (("Listen", ["tls://0.0.0.0:9001"]), ("MulticastInterfaces", [{}]), ("IfName", "auto"), ("InterfacePeers", {"eth0":[URI]}), ("PrivateKey", "synthetic")):
            with self.subTest(k=k): self.assertTrue(safe_config(dict(c, **{k:v})))

    @logged
    def test_atomic_reject_symlink(self):
        p = self.paths.etc/"link"
        p.symlink_to(self.paths.etc/"mode")
        with self.assertRaises(Failure): atomic(p, "bad")
        self.assertEqual(read_regular(self.paths.etc/"mode"), b"direct\n")

    @logged
    def test_read_reject_link_and_size(self):
        p = self.paths.etc/"link"
        p.symlink_to(self.paths.etc/"mode")
        with self.assertRaises(OSError): read_regular(p)
        with self.assertRaises(Failure): read_regular(self.paths.etc/"mode", 1)

    @logged
    def test_missing_manifest_fail(self):
        (self.paths.etc/"integrity.manifest").unlink()
        with self.assertRaises(OSError): checks.integrity(self.ctx)

    @logged
    def test_hash_mismatch_fail(self):
        atomic(self.paths.etc/"gate.nft", "modified")
        with self.assertRaises(Failure): checks.integrity(self.ctx)

    @logged
    def test_hash_missing_coverage(self):
        atomic(self.paths.etc/"integrity.manifest", "")
        with self.assertRaises(Failure): checks.integrity(self.ctx)

    @logged
    def test_external_failed_no_secret(self):
        self.failed_command = "getPeers"
        with patch("core.event") as log, self.assertRaises(Failure) as error: checks.peers(self.ctx)
        self.assertNotIn("SECRET", str(error.exception))
        self.assertNotIn("SECRET", str(log.call_args_list))

    @logged
    def test_admin_unknown_schema_fail(self):
        for value in ({}, {"peers": {}}, {"peers": [{"up": "true"}]}, {"error": "bad"}):
            self.responses["getPeers"] = value
            with self.assertRaises(Failure): checks.peers(self.ctx)

    @logged
    def test_multicast_admin_failure_not_empty(self):
        self.failed_command = "getMulticastInterfaces"
        with self.assertRaises(Failure): checks.multicast_gate(self.ctx, False)

    @logged
    def test_underlay_own_tuples(self):
        self.assertEqual(checks.underlay(self.ctx)["own_connections"], [1,1])
        original = self.ctx.runner
        @logged
        def other(argv, **kw):
            if "conntrack" in argv[0]: return subprocess.CompletedProcess(argv,0,b"tcp 6 100 src=1.1.1.1 dst=2.2.2.2 sport=3 dport=4 mark=3905\n",b"")
            return original(argv, **kw)
        self.ctx.runner = other
        with self.assertRaises(Failure): checks.underlay(self.ctx)

    @logged
    def test_notify_off_honoured_unknown_saved(self):
        atomic(self.paths.state/"notify.state", "off\n")
        self.failed_command = "getPeers"
        with self.assertRaises(Failure): telemetry.collect(self.ctx)
        row = telemetry.rows(self.ctx)[0]
        self.assertIsNone(row["up"])
        self.assertTrue(row["errors"])
        self.assertEqual(telemetry.rows(self.ctx,"alerts.jsonl"), [])

    @logged
    def test_hourly_dedup_not_empty(self):
        atomic(self.paths.state/"notify.state", "on\n")
        self.ps = []
        for _ in range(2):
            with self.assertRaises(Failure): telemetry.collect(self.ctx)
        alerts = telemetry.rows(self.ctx,"alerts.jsonl")
        self.assertEqual(len(alerts),1)
        self.assertRegex(alerts[0]["key"], r"^collect:\d{10}$")

    @logged
    def test_collect_one_query_each(self):
        telemetry.collect(self.ctx)
        self.assertEqual(sum("getPeers" in a for a in self.calls),2)

    @logged
    def test_parallel_collect_no_loss(self):
        contexts = [Context(self.paths,runner=self.runner,require_root=False) for _ in range(4)]
        errors = []
        @logged
        def worker(c):
            try: telemetry.collect(c)
            except BaseException as e: errors.append(e)
        threads = [threading.Thread(target=worker,args=(c,)) for c in contexts]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual(errors,[])
        self.assertEqual(len(telemetry.rows(self.ctx)),4)

    @logged
    def test_transaction_rolls_back_exact(self):
        path = self.paths.etc/"mode"
        old = read_regular(path)
        @logged
        def fail(): raise Failure("injected_runtime_failure")
        @logged
        def ok(): return None
        with self.assertRaises(Failure): management.transaction(self.ctx,{path:"tunnel\n"},fail,ok)
        self.assertEqual(read_regular(path),old)
        self.assertFalse((self.paths.state/"transaction.json").exists())
        checks.integrity(self.ctx)

    @logged
    def test_transaction_failed_compensation_retains_journal(self):
        @logged
        def fail(): raise Failure("injected")
        with self.assertRaises(Failure): management.transaction(self.ctx,{self.paths.etc/"mode":"tunnel\n"},fail,fail)
        self.assertTrue((self.paths.state/"transaction.json").exists())

    @logged
    def test_pending_transaction_blocks_mutation(self):
        atomic(self.paths.state/"transaction.json", "{}")
        @logged
        def ok(): return None
        with self.assertRaises(Failure): management.transaction(self.ctx,{self.paths.etc/"mode":"tunnel\n"},ok,ok)

    @logged
    def test_key_free_archive_allowlist(self):
        data = recovery.archive(recovery.members(self.ctx))
        files, keys = recovery.inspect_archive(data)
        self.assertFalse(keys)
        self.assertFalse(any(k.startswith("keys/") for k in files))
        self.assertNotIn(b"synthetic test fixture, not a key", data)

    @logged
    def test_archive_traversal_link_duplicate_rejected(self):
        for name, kind in (("../../etc/passwd",tarfile.REGTYPE),("config/mode",tarfile.SYMTYPE)):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer,mode="w:gz") as tar:
                info = tarfile.TarInfo(name); info.type=kind; info.linkname="/etc/passwd"
                tar.addfile(info,io.BytesIO())
            with self.assertRaises(Failure): recovery.inspect_archive(buffer.getvalue())

    @logged
    def test_full_backup_needs_explicit_recipient(self):
        with self.assertRaises(Failure): recovery.backup(self.ctx,full=True)

    @logged
    def test_backup_digest_and_permissions(self):
        path = recovery.backup(self.ctx)
        self.assertEqual(path.stat().st_mode & 0o777,0o600)
        recovery.restore(self.ctx,path)
        atomic(path,b"corrupt")
        with self.assertRaises(Failure): recovery.restore(self.ctx,path)

    @logged
    def test_peer_preview_no_changes(self):
        before=read_regular(self.paths.etc/"yggdrasil-lab.conf")
        management.change_peer(self.ctx,URI.replace("192.0.2.1","192.0.2.9"))
        self.assertEqual(before,read_regular(self.paths.etc/"yggdrasil-lab.conf"))
        self.assertFalse(any("addpeer" in a for a in self.calls))

    @logged
    def test_remove_exact_not_regex(self):
        with self.assertRaises(Failure): management.change_peer(self.ctx,"192.0.2.10:443",remove=True)

    @logged
    def test_http_failure_and_status(self):
        self.failed_command="/usr/bin/curl"
        with self.assertRaises(Failure): main.http_probe(self.ctx,"[200::1]:80")
        for target in ("[::1]:80","[200::1]:65536","example.com:80","[200::1]:80;id"):
            with self.assertRaises((Failure,ValueError)): main.http_probe(self.ctx,target)

    @logged
    def test_subprocess_timeout_and_output_cap(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            bounded_process(["/usr/bin/sleep","1"],timeout=0.05)
        with self.assertRaises(Failure):
            bounded_process(["/usr/bin/head","-c","18000000","/dev/zero"])
        result=bounded_process(["/usr/bin/cat"], input=b"fixture")
        self.assertEqual(result.stdout,b"fixture")

    @logged
    def test_http_non_2xx_rejected(self):
        original = self.ctx.runner
        @logged
        def bad(argv, **kw):
            if argv[0] == "/usr/bin/curl": return subprocess.CompletedProcess(argv,0,b"503 0.1 0.15 0.2 0.3",b"")
            return original(argv, **kw)
        self.ctx.runner=bad
        with self.assertRaises(Failure): main.http_probe(self.ctx,"[200::1]:80")

    @logged
    def test_shared_context_threads_lock(self):
        errors=[]
        @logged
        def worker():
            try: telemetry.collect(self.ctx)
            except BaseException as exc: errors.append(exc)
        threads=[threading.Thread(target=worker) for _ in range(4)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual(errors,[])
        self.assertEqual(len(telemetry.rows(self.ctx)),4)

    @logged
    def test_success_transaction_and_preview_contracts(self):
        @logged
        def ok(): return None
        path=self.paths.etc/"mode"
        management.transaction(self.ctx,{path:"tunnel\n"},ok,ok)
        self.assertEqual(read_regular(path),b"tunnel\n")
        self.assertFalse((self.paths.state/"transaction.json").exists())
        self.assertEqual(len(list(self.paths.state.glob("transaction-*.json"))),1)
        with self.assertRaises(Failure):
            main.dispatch(self.ctx,main.argparse.Namespace(command="collect",args=["oops"],apply=False,force=False,full=False,recipient=None))

    @logged
    def test_archive_duplicate_and_hash_mismatch(self):
        data=recovery.archive(recovery.members(self.ctx))
        buf=io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(data),mode="r:gz") as src, tarfile.open(fileobj=buf,mode="w:gz") as out:
            for member in src:
                payload=src.extractfile(member).read()
                if member.name=="config/mode":payload=b"wrong\n";member.size=len(payload)
                out.addfile(member,io.BytesIO(payload))
        with self.assertRaises(Failure): recovery.inspect_archive(buf.getvalue())
        buf=io.BytesIO()
        with tarfile.open(fileobj=buf,mode="w:gz") as out:
            for _ in range(2):out.addfile(tarfile.TarInfo("config/mode"),io.BytesIO())
        with self.assertRaises(Failure): recovery.inspect_archive(buf.getvalue())

    @logged
    def test_reject_fifo_without_blocking(self):
        fifo = self.paths.state / "untrusted.fifo"
        os.mkfifo(fifo)
        code = "import sys; sys.path.insert(0, sys.argv[1]); from core import read_regular, Failure; " \
               "read_regular(sys.argv[2])"
        result = bounded_process(["/usr/bin/python3", "-B", "-c", code, str(Path(__file__).resolve().parent), str(fifo)], timeout=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"not_regular_file", result.stderr)

    @logged
    def test_reject_archive_schema_shapes(self):
        payloads = ([], "bad", {"schema": 1, "keys": False, "sha256": []},
                    {"schema": 1, "keys": False, "sha256": "bad"},
                    {"schema": 1, "keys": "false", "sha256": {}},
                    {"schema": 1, "keys": False, "sha256": {"config/mode": []}})
        for manifest in payloads:
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
                raw = json.dumps(manifest).encode()
                info = tarfile.TarInfo("manifest.json"); info.size = len(raw)
                tar.addfile(info, io.BytesIO(raw))
            with self.subTest(shape=type(manifest).__name__), self.assertRaises(Failure):
                recovery.inspect_archive(buffer.getvalue())

    @logged
    def test_graph_bins_cover_requested_window(self):
        import datetime as dt
        now = dt.datetime(2026, 10, 13, 19, 0, tzinfo=dt.timezone.utc)
        sample = {"ts": (now-dt.timedelta(minutes=1)).isoformat(), "up": 1, "errors": [],
                  "peers": [{"r": URI, "up": True, "rtt": 1}]}
        atomic(self.paths.state/"metrics.jsonl", json.dumps(sample)+"\n")
        clock = unittest.mock.Mock(wraps=dt.datetime)
        clock.now.return_value = now
        capture = io.StringIO()
        with patch.object(telemetry.dt, "datetime", clock), contextlib.redirect_stdout(capture):
            telemetry.stats(self.ctx, hours=1, graph=True)
        graph = next(line for line in capture.getvalue().splitlines() if len(line)==60 and set(line)<=set("?.#"))
        self.assertEqual(graph, "?"*59+"#")

    @logged
    def test_remote_tree_and_retired_dht_contract(self):
        args = main.argparse.Namespace(command="debug-remote", args=["tree", PIN],
                                       apply=False, force=False, full=False, recipient=None)
        main.dispatch(self.ctx, args)
        self.assertEqual(self.calls[-1][3], "debug_remotegettree")
        args.args = ["dht", PIN]
        previous = len(self.calls)
        with self.assertRaisesRegex(Failure, "remote_dht_not_supported"):
            main.dispatch(self.ctx, args)
        self.assertEqual(len(self.calls), previous)

    @logged
    def test_recovery_journal_schema_rejected(self):
        for value in ([], "bad", {"old": []}, {"old": {"/etc/passwd": "fixture"}}):
            atomic(self.paths.state/"transaction.json", json.dumps(value))
            with self.assertRaisesRegex(Failure, "invalid_recovery_journal"):
                management.recover_transaction(self.ctx, apply=True)
            self.assertTrue((self.paths.state/"transaction.json").exists())

    @logged
    def test_unittest_failure_method_not_shadowed(self):
        with self.assertRaises(AssertionError): self.assertEqual(1, 2)

    @logged
    def test_remote_own_key_rejected_without_mesh_call(self):
        self.responses["getSelf"] = {"key": PIN.upper()}
        for command, argv in (("nodeinfo", [PIN]), ("whois", [PIN]),
                              *( ("debug-remote", [kind, PIN]) for kind in ("self", "peers", "tree") )):
            self.calls.clear()
            args = main.argparse.Namespace(command=command, args=argv,
                                           apply=False, force=False, full=False, recipient=None)
            with self.assertRaisesRegex(Failure, "remote_target_is_local"):
                main.dispatch(self.ctx, args)
            self.assertEqual([c[3] for c in self.calls if c[0] == self.paths.ctl], ["getSelf"])
        for value in ({}, {"key": []}, {"key": "invalid"}):
            self.responses["getSelf"] = value
            with self.assertRaisesRegex(Failure, "admin_invalid_self_key"):
                main.remote_key(self.ctx, PIN)
        self.calls.clear()
        with self.assertRaisesRegex(Failure, "expected_public_key"):
            main.remote_key(self.ctx, "invalid")
        self.assertEqual(self.calls, [])

    @logged
    def test_http_failure_metrics_do_not_fake_stage_or_log_stderr(self):
        original = self.ctx.runner
        @logged
        def timeout(argv, **kw):
            if argv[0] == "/usr/bin/curl":
                return subprocess.CompletedProcess(argv, 28, b"000 0 5.001 5.001 5.001", b"Proxy connection timed out SECRET_DO_NOT_LOG")
            return original(argv, **kw)
        self.ctx.runner = timeout
        capture = io.StringIO()
        with patch("core.event") as log, contextlib.redirect_stdout(capture):
            with self.assertRaisesRegex(Failure, "diagnostic=proxy_connect_timeout") as error:
                main.http_probe(self.ctx, "[200::1]:80")
        self.assertIn("curl_rc=28 HTTP=000", capture.getvalue())
        self.assertNotIn("SECRET", capture.getvalue()+str(error.exception)+str(log.call_args_list))

    @logged
    def test_http_metrics_unknown_timeout_and_untrusted_values(self):
        original = self.ctx.runner
        for payload, rc, expected in ((b"000 0 5 5 5", 28, "timeout_stage_unknown"),
                                       (b"200 nan 0 0 0", 0, "invalid_metrics"),
                                       (b"200 inf 0 0 0", 0, "invalid_metrics"),
                                       (b"200 -1 0 0 0", 0, "invalid_metrics"),
                                       (b"200 0 0 0 18", 0, "invalid_metrics"),
                                       (b"200 SECRET 0 0 0", 0, "invalid_metrics"),
                                       (b"200 0 0 0", 0, "invalid_metrics")):
            @logged
            def response(argv, **kw):
                if argv[0] == "/usr/bin/curl": return subprocess.CompletedProcess(argv, rc, payload, b"SECRET")
                return original(argv, **kw)
            self.ctx.runner = response
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(Failure, expected):
                main.http_probe(self.ctx, "[200::1]:80")


@logged
def run_suite():
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ConsoleTests)
    print(f"[1/1] offline regressions total={suite.countTestCases()} remaining={suite.countTestCases()}")
    start=time.monotonic()
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    print(f"processed={result.testsRun} errors={len(result.errors)+len(result.failures)} remaining=0 elapsed={time.monotonic()-start:.2f}s")
    if not result.wasSuccessful(): raise Failure("offline_selftest_failed")


if __name__ == "__main__": run_suite()
