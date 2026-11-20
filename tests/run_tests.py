#!/usr/bin/env python3
"""Isolated stock-SuperCollider tests for VisualsQuark.

The launcher never reads user startup files, never uses the renderer default port,
and terminates only the sclang process it started.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import argparse
import socket
import struct
import subprocess
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parents[1]
SCLANG = Path("/Applications/SuperCollider.app/Contents/MacOS/sclang")
STOCK = Path("/Applications/SuperCollider.app/Contents/Resources/SCClassLibrary")
UPSTREAM = "ef806c0c38bbeb4bb1f4a975166a9a70714f5442"


def reserve_udp() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    if port == 33333:
        return reserve_udp()
    return port


def write_config(owned: Path, extra: list[Path]) -> Path:
    overwrite = owned / "SystemOverwrites"
    overwrite.mkdir(parents=True)
    (overwrite / "extPlatform.sc").write_text("+ Platform { loadStartupFiles { ^this } }\n")
    config = owned / "sclang_conf.yaml"
    paths = [STOCK, ROOT, *extra, overwrite]
    config.write_text(
        "includePaths:\n" + "".join(f"  - {json.dumps(str(path))}\n" for path in paths)
        + "excludePaths: []\npostInlineWarnings: false\n"
    )
    return config


def run_sclang(owned: Path, script: str, extra: list[Path] | None = None, timeout: float = 20.0) -> dict:
    owned.mkdir(parents=True, exist_ok=True)
    runner = owned / "runner.scd"
    runner.write_text(script)
    config = write_config(owned, extra or [])
    port = reserve_udp()
    command = [str(SCLANG), "-a", "-l", str(config), "-D", "-u", str(port), "-i", "none", str(runner)]
    env = {**os.environ, "XDG_CONFIG_HOME": str(owned / "config"), "XDG_DATA_HOME": str(owned / "data")}
    before = source_hashes()
    process = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    timed_out = False
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.terminate()
        try:
            output, _ = process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate(timeout=3)
    after = source_hashes()
    receipt = {
        "pid": process.pid,
        "return_code": process.returncode,
        "timed_out": timed_out,
        "language_port": port,
        "command": command,
        "source_before": before,
        "source_after": after,
        "source_stable": before == after,
        "output": output,
    }
    (owned / "sclang.log").write_text(output)
    (owned / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if timed_out or process.returncode != 0 or before != after:
        raise AssertionError(f"owned sclang failed (pid={process.pid}, port={port})\n{output}")
    return receipt


def source_hashes() -> dict[str, str]:
    return {
        path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(ROOT.rglob("*.sc"))
        if ".git" not in path.parts
    }


def osc_string(data: bytes, offset: int) -> tuple[str, int]:
    end = data.index(0, offset)
    text = data[offset:end].decode("utf-8")
    return text, (end + 4) & ~3


def decode_message(data: bytes) -> tuple[str, str, list[object]]:
    address, offset = osc_string(data, 0)
    tags, offset = osc_string(data, offset)
    values: list[object] = []
    for tag in tags[1:]:
        if tag == "i":
            values.append(struct.unpack_from(">i", data, offset)[0]); offset += 4
        elif tag == "f":
            values.append(struct.unpack_from(">f", data, offset)[0]); offset += 4
        elif tag in "sS":
            value, offset = osc_string(data, offset); values.append(value)
        elif tag == "T":
            values.append(True)
        elif tag == "F":
            values.append(False)
        elif tag == "N":
            values.append(None)
        else:
            raise AssertionError(f"unsupported OSC tag in test oracle: {tag!r}")
    if offset != len(data):
        raise AssertionError(f"trailing OSC bytes for {address}: {len(data) - offset}")
    return address, tags, values


def decode_packet(data: bytes) -> list[tuple[str, str, list[object], bytes]]:
    if not data.startswith(b"#bundle\x00"):
        address, tags, values = decode_message(data)
        return [(address, tags, values, data)]
    if data[8:16] != b"\x00\x00\x00\x00\x00\x00\x00\x01":
        raise AssertionError("replay bundle is not immediate")
    out = []
    offset = 16
    while offset < len(data):
        size = struct.unpack_from(">I", data, offset)[0]; offset += 4
        item = data[offset:offset + size]; offset += size
        address, tags, values = decode_message(item)
        out.append((address, tags, values, item))
    if offset != len(data):
        raise AssertionError("bundle element size mismatch")
    return out


def pack_string(value: str) -> bytes:
    data = value.encode() + b"\x00"
    return data + b"\x00" * ((-len(data)) % 4)


def reply_packet(token: str, status: str, frame: int, detail: str) -> bytes:
    return (pack_string("/scene/replay/result") + pack_string(",ssis")
            + pack_string(token) + pack_string(status) + struct.pack(">i", frame) + pack_string(detail))


class UDPCollector:
    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(0.1)
        self.port = self.socket.getsockname()[1]
        self.packets: list[tuple[bytes, tuple[str, int]]] = []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self) -> "UDPCollector":
        self.thread.start(); return self

    def __exit__(self, *_: object) -> None:
        self.stop.set(); self.thread.join(2); self.socket.close()

    def _run(self) -> None:
        while not self.stop.is_set():
            try:
                self.packets.append(self.socket.recvfrom(65535))
            except socket.timeout:
                pass


def legacy_differential(root: Path) -> dict:
    baseline_dir = root / "baseline"
    baseline_dir.mkdir()
    original = subprocess.run(
        ["git", "show", f"{UPSTREAM}:OSCVisuals.sc"], cwd=ROOT,
        check=True, capture_output=True, text=True,
    ).stdout
    if not original.startswith("OSCVisuals {"):
        raise AssertionError("frozen upstream class header changed")
    (baseline_dir / "BaselineOSCVisuals.sc").write_text(original.replace("OSCVisuals {", "BaselineOSCVisuals {", 1))
    with UDPCollector() as collector:
        script = f'''(
var baseline = BaselineOSCVisuals("127.0.0.1", {collector.port}, false);
var enhanced = OSCVisuals("127.0.0.1", {collector.port}, false);
var baselineReset, enhancedReset, dictionary, values;
if(baseline.net.port != {collector.port} or: {{ enhanced.net.port != {collector.port} }}) {{ Error("endpoint mismatch").throw }};
if(baseline.sendRaw("/legacy/raw", -2147483648, 2147483647, -0.0, "raw") !== baseline) {{ Error("baseline raw return").throw }};
if(enhanced.sendRaw("/legacy/raw", -2147483648, 2147483647, -0.0, "raw") !== enhanced) {{ Error("enhanced raw return").throw }};
dictionary = Dictionary["alpha" -> 1, "beta" -> [2, nil, true, false]];
if(baseline.send("/legacy/string", "line\\n\\t", \\symbol) !== baseline) {{ Error("baseline send return").throw }};
if(enhanced.send("/legacy/string", "line\\n\\t", \\symbol) !== enhanced) {{ Error("enhanced send return").throw }};
baseline.send("/legacy/collections", [1, "two", nil, true, false, inf, -inf, Float.from32Bits(16r7FC00000)], List[3, 4], dictionary);
enhanced.send("/legacy/collections", [1, "two", nil, true, false, inf, -inf, Float.from32Bits(16r7FC00000)], List[3, 4], dictionary);
baseline.send("/legacy/fallback", [Point(1, 2)]);
enhanced.send("/legacy/fallback", [Point(1, 2)]);
values = ["control\\n\\t", \\symbol, [1, "two", nil, true, false, inf, -inf, Float.from32Bits(16r7FC00000)], List[1, 2], dictionary, nil, true, false, 1, 1.25, inf, -inf, Float.from32Bits(16r7FC00000), Point(1, 2)];
values.do {{ |value, index|
    var left = baseline.prStringify(value), right = enhanced.prStringify(value);
    if(left != right) {{ Error("prStringify mismatch at " ++ index ++ ": " ++ left ++ " != " ++ right).throw }};
}};
if(enhanced.prStringify(nil) != "null" or: {{ enhanced.prStringify(true) != "true" or: {{ enhanced.prStringify(false) != "false" }} }}) {{ Error("literal stringify drift").throw }};
baselineReset = BaselineOSCVisuals("127.0.0.1", {collector.port}, true);
enhancedReset = OSCVisuals("127.0.0.1", {collector.port}, true);
if(baselineReset.net === enhancedReset.net) {{ Error("independent net identity expected").throw }};
SystemClock.sched(0.2, {{ "LEGACY_DIFFERENTIAL_OK".postln; 0.exit; nil }});
)'''
        receipt = run_sclang(root / "legacy", script, [baseline_dir])
        time.sleep(0.2)
    packets = [packet for packet, _ in collector.packets]
    if len(packets) != 14:
        raise AssertionError(f"expected 4 packet pairs and 1 upstream/5 enhanced reset packets, got {len(packets)}\n{receipt['output']}")
    for index in range(0, 8, 2):
        if packets[index] != packets[index + 1]:
            left = decode_packet(packets[index]); right = decode_packet(packets[index + 1])
            raise AssertionError(f"legacy packet pair {index // 2} differs: {left} != {right}")
    upstream_reset = decode_packet(packets[8])[0]
    if upstream_reset[:3] != ("/layers/reset", ",", []):
        raise AssertionError(f"unexpected frozen upstream reset: {upstream_reset}")
    reset_sequence = [decode_packet(packet)[0][:3] for packet in packets[9:]]
    expected_reset = [
        ("/cam/reset", ",", []),
        ("/layers/reset", ",", []),
        ("/layers/layout", ",s", ["stack"]),
        ("/shading", ",s", [""]),
        ("/shading/passes", ",", []),
    ]
    if reset_sequence != expected_reset:
        raise AssertionError(f"installed reset behavior changed: {reset_sequence} != {expected_reset}")
    if packets[8] != packets[10]:
        raise AssertionError("layer reset wire behavior differs from upstream")
    if "LEGACY_DIFFERENTIAL_OK" not in receipt["output"]:
        raise AssertionError(receipt["output"])
    return {"packet_pairs": 4, "reset_sequence": reset_sequence,
            "upstream": UPSTREAM, "receipt": "legacy/receipt.json"}


def replay_case(root: Path, status: str, *, default_timeout: bool = False) -> dict:
    label = f"{status}-default15" if default_timeout else status
    case = root / f"replay-{label}"
    scene = case / "scene"
    assets = scene / "assets"
    assets.mkdir(parents=True)
    (assets / "a.frag").write_text("#version 410\nvoid main() {}\n")
    (assets / "a.png").write_bytes(b"not decoded by preflight")
    callback_status = "unknown" if status == "unknown" else status
    timeout_keyword = "" if default_timeout else ", replyTimeout: 0.25"
    exit_delay = 15.4 if default_timeout else 0.55
    with UDPCollector() as collector:
        script = f'''(
var visuals = OSCVisuals("127.0.0.1", {collector.port});
var retained, caught = 0, callbackCount = 0, callbackStatus, vector = [1.0, 2.0, 3.0];
var uniform = [1.401298464e-45], mutableAddress = "/layer/pos".copy;
var asset = "assets/a.frag".copy, expression = "sin(t)".copy;
try {{ visuals.replay({{ |rec| retained = rec; rec.sendRaw("/layers/reset", 0, "stack"); Error("body failure").throw }}, "{scene}", 640, 480, replyTimeout: 0.2) }} {{ caught = caught + 1 }};
try {{ retained.sendRaw("/layers/reset", 0, "stack") }} {{ caught = caught + 1 }};
try {{ visuals.replay({{ |rec| rec.sendRaw("/layers/reset", 0, "stack"); rec.replay({{ |nested| nested.sendRaw("/layers/reset", 0, "stack") }}, "{scene}", 640, 480) }}, "{scene}", 640, 480, replyTimeout: 0.2) }} {{ |error| if(error.errorString.contains("nested replay").not) {{ error.throw }}; caught = caught + 1 }};
try {{ visuals.replay({{ |rec| rec.sendRaw("/layers/reset", 0, "stack"); visuals.replay({{ |nested| nested.sendRaw("/layers/reset", 0, "stack") }}, "{scene}", 640, 480) }}, "{scene}", 640, 480, replyTimeout: 0.2) }} {{ |error| if(error.errorString.contains("nested replay").not) {{ error.throw }}; caught = caught + 1 }};
try {{ visuals.replay({{ |rec| rec.sendRaw("/layers/reset", [0, "stack"]) }}, "{scene}", 640, 480, replyTimeout: 0.2) }} {{ caught = caught + 1 }};
try {{ visuals.replay({{ |rec| rec.sendRaw("/layers/reset", 0, "stack") }}, "{scene}", 63, 480, replyTimeout: 0.2) }} {{ caught = caught + 1 }};
try {{ visuals.replay({{ |rec| rec.sendRaw("/layer/pos", 0, 1.0, 2.0, 3.0) }}, "{scene}", 640, 480, replyTimeout: 0.2) }} {{ caught = caught + 1 }};
if(caught != 7) {{ Error("guard/preflight corpus did not throw: " ++ caught).throw }};
visuals.replay({{ |rec|
    if(rec.class != OSCVisualsReplayRecorder or: {{ rec.net !== visuals.net }}) {{ Error("recorder identity mismatch").throw }};
    retained = rec;
    if(rec.sendRaw("/layers/reset", 1, "stack") !== rec) {{ Error("recorder sendRaw return mismatch").throw }};
    if(rec.send("/shader", 0, asset) !== rec) {{ Error("recorder send return mismatch").throw }};
    rec.send("/tex", 0, "assets/a.png");
    rec.send("/shader/var", 0, "subnormal", uniform);
    rec.sendRaw("/shader/var", 0, "minInt", -2147483648);
    rec.sendRaw("/shader/var", 0, "maxInt", 2147483647);
    rec.sendRaw("/shader/var", 0, "negZero", -0.0);
    rec.send(mutableAddress, 0, vector);
    rec.send("/layer/rot", 0, [expression, 0.0, 0.0]);
    mutableAddress[1] = $x; vector[0] = 99.0; uniform[0] = 9.0; asset[0] = $X; expression[0] = $X;
}}, "{scene}", 640, 480, rendererRoot: "/renderer"{timeout_keyword}, onComplete: {{ |replyStatus, frame, detail|
    callbackCount = callbackCount + 1; callbackStatus = replyStatus;
    if("{status}" == "applied") {{ Error("intentional callback error").throw }};
}});
try {{ retained.send("/layers/reset", 0, "stack") }} {{ caught = caught + 1 }};
try {{ retained.sendRaw("/layers/reset", 0, "stack") }} {{ caught = caught + 1 }};
visuals.sendRaw("/ordinary", 7);
SystemClock.sched({exit_delay}, {{
    if(caught != 9) {{ Error("expired recorder guards failed: " ++ caught).throw }};
    if(callbackCount != 1 or: {{ callbackStatus.asString != "{callback_status}" }}) {{ Error("completion mismatch: " ++ callbackCount ++ " " ++ callbackStatus).throw }};
    "REPLAY_CASE_OK {label}".postln; 0.exit; nil
}});
)'''

        reply_errors: list[BaseException] = []
        replied = threading.Event()

        def responder() -> None:
            try:
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline and not replied.is_set():
                    for packet, sender in list(collector.packets):
                        if packet.startswith(b"#bundle\x00"):
                            messages = decode_packet(packet)
                            reset = messages[0]
                            token, reply_port = reset[2][0], reset[2][1]
                            if status != "unknown":
                                payload = reply_packet(str(token), status, 42 if status == "applied" else -1, "test-detail")
                                # Native VOSC replies from an ephemeral socket, not its OSC listener.
                                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reply_socket:
                                    reply_socket.bind(("127.0.0.1", 0))
                                    if reply_socket.getsockname()[1] == collector.port:
                                        raise AssertionError("reply fixture must use a distinct source port")
                                    reply_socket.sendto(payload, (sender[0], int(reply_port)))
                                    reply_socket.sendto(payload, (sender[0], int(reply_port)))
                            replied.set(); return
                    time.sleep(0.01)
                raise AssertionError("did not observe replay bundle before deadline")
            except BaseException as error:
                reply_errors.append(error); replied.set()

        thread = threading.Thread(target=responder, daemon=True); thread.start()
        receipt = run_sclang(case / "owned", script, timeout=22.0 if default_timeout else 20.0)
        thread.join(2); time.sleep(0.1)
        if reply_errors:
            raise reply_errors[0]
    bundles = [packet for packet, _ in collector.packets if packet.startswith(b"#bundle\x00")]
    ordinary = [decode_packet(packet)[0] for packet, _ in collector.packets if not packet.startswith(b"#bundle\x00")]
    if len(bundles) != 1:
        raise AssertionError(f"invalid cases leaked or replay resent: {len(bundles)} bundles\n{receipt['output']}")
    if ordinary != [("/ordinary", ",i", [7], ordinary[0][3])]:
        # Compare only decoded fields; the fourth tuple member is the original datagram.
        if [(item[0], item[1], item[2]) for item in ordinary] != [("/ordinary", ",i", [7])]:
            raise AssertionError(f"live receiver unusable after replay: {ordinary}")
    messages = decode_packet(bundles[0])
    expected_addresses = ["/scene/reset"] + ["/scene/command"] * 9 + ["/scene/replay/end"]
    if [item[0] for item in messages] != expected_addresses:
        raise AssertionError(f"wrapper order mismatch: {[item[0] for item in messages]}")
    commands = [item[2][2:] for item in messages[1:-1]]
    expected = [
        ["/layers/reset", 1, "stack"],
        ["/shader", 0, "/renderer/assets/a.frag"],
        ["/tex", 0, "/renderer/assets/a.png"],
        ["/shader/var", 0, "subnormal", struct.unpack(">f", b"\x00\x00\x00\x01")[0]],
        ["/shader/var", 0, "minInt", -2147483648],
        ["/shader/var", 0, "maxInt", 2147483647],
        ["/shader/var", 0, "negZero", -0.0],
        ["/layer/pos", 0, 1.0, 2.0, 3.0],
        ["/layer/rot", 0, "sin(t)", 0.0, 0.0],
    ]
    if commands != expected:
        raise AssertionError(f"typed/snapshot command mismatch:\n{commands}\n!=\n{expected}")
    if math.copysign(1.0, commands[6][-1]) != -1.0:
        raise AssertionError("negative zero sign was not preserved")
    tags = [item[1] for item in messages]
    if tags != [",siii", ",sisis", ",sisis", ",sisis", ",sisisf", ",sisisi", ",sisisi", ",sisisf", ",sisifff", ",sisisff", ",siii"]:
        raise AssertionError(f"OSC typetag/order mismatch: {tags}")
    if f"REPLAY_CASE_OK {label}" not in receipt["output"]:
        raise AssertionError(receipt["output"])
    if status == "applied" and "OSCVisuals replay completion callback failed" not in receipt["output"]:
        raise AssertionError("throwing completion callback was not locally reported")
    return {"status": callback_status, "default_timeout": default_timeout, "bundle_sha256": hashlib.sha256(bundles[0]).hexdigest(), "receipt": f"replay-{label}/owned/receipt.json"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        help="new, non-existing directory for persistent test receipts",
    )
    args = parser.parse_args()
    if not SCLANG.is_file():
        raise SystemExit(f"SuperCollider is unavailable: {SCLANG}")
    configured_output = args.output or (
        Path(os.environ["VISUALS_QUARK_TEST_RECEIPTS"])
        if "VISUALS_QUARK_TEST_RECEIPTS" in os.environ else None
    )
    if configured_output is None:
        receipt_root = Path(tempfile.mkdtemp(prefix="visuals-quark-test-receipts-"))
    else:
        receipt_root = configured_output.expanduser().resolve()
        if receipt_root.exists():
            raise SystemExit(f"refusing to replace existing receipt path: {receipt_root}")
        receipt_root.mkdir(parents=True)
    results = {
        "legacy": legacy_differential(receipt_root),
        "replay": [replay_case(receipt_root, status) for status in ("applied", "failed", "unknown")]
            + [replay_case(receipt_root, "unknown", default_timeout=True)],
        "sources": source_hashes(),
    }
    (receipt_root / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
    print("VISUALS_QUARK_TESTS_OK")
    print(f"VISUALS_QUARK_TEST_RECEIPTS={receipt_root}")
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
