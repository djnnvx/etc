#!/usr/bin/env python3
"""
DoIP / UDS fuzzer. One-shot cases on a fresh connection each time.

  ./doipfuzz.py health
  ./doipfuzz.py fuzz --stage hdr -n 500
  ./doipfuzz.py fuzz --stage all -n 5000 --seed 1234
  ./doipfuzz.py replay cases/000123.bin

Never emits UDS 0x2E, 0x31, 0x11, 0x34, 0x35, 0x36, 0x37, 0x85, 0x28, or 0x27
with subfunction 02. Those write, reset, or route. --unsafe lifts it.
"""
import argparse, collections, json, os, random, socket, struct, sys, time

V = 0x03
TESTER = 0x0EF4
TARGET_TA = 0x0010
WRITE_SERVICES = {0x2E, 0x31, 0x11, 0x34, 0x35, 0x36, 0x37, 0x85, 0x28}

NACK = {0x00: 'incorrect pattern', 0x01: 'unknown payload type', 0x02: 'message too large',
        0x03: 'out of memory', 0x04: 'invalid payload length'}

PT_NAMES = {0x0000: 'GenericNack', 0x0001: 'VIR', 0x0004: 'VehicleAnnounce',
            0x0005: 'RoutingActReq', 0x0006: 'RoutingActResp', 0x0007: 'AliveReq',
            0x0008: 'AliveResp', 0x4001: 'EntityStatusReq', 0x4002: 'EntityStatusResp',
            0x4003: 'PowerReq', 0x4004: 'PowerResp', 0x8001: 'DiagMsg',
            0x8002: 'DiagAck', 0x8003: 'DiagNack'}


def hdr(ptype, payload=b'', ver=V, inv=None, length=None):
    inv = (0xFF ^ ver) if inv is None else inv
    ln = len(payload) if length is None else length
    return struct.pack('>BBHI', ver, inv, ptype, ln) + payload


def udp_once(host, payload, timeout=2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(payload, (host, 13400))
        d, _ = s.recvfrom(4096)
        return d
    except socket.timeout:
        return None
    finally:
        s.close()


class Health:
    def __init__(self, host, timeout=3.0):
        self.host, self.timeout = host, timeout
        self.base = None

    def sample(self):
        out = {}
        r = udp_once(self.host, hdr(0x0001), self.timeout)
        out['vir'] = r.hex() if r else None
        r = udp_once(self.host, hdr(0x4001), self.timeout)
        # byte 10 is the open-socket count, which our own connections move
        if r and len(r) >= 11:
            r = bytearray(r); r[10] = 0; r = bytes(r)
        out['status'] = r.hex() if r else None
        try:
            t = socket.create_connection((self.host, 13400), self.timeout)
            t.settimeout(self.timeout)
            t.sendall(hdr(0x0005, struct.pack('>HB', TESTER, 0) + b'\0' * 4))
            act = t.recv(4096)
            out['routing'] = act.hex() if act else None
            t.sendall(hdr(0x8001, struct.pack('>HH', TESTER, TARGET_TA) + b'\x22\xf1\x86'))
            got = b''
            end = time.time() + self.timeout
            while time.time() < end:
                try:
                    d = t.recv(4096)
                except socket.timeout:
                    break
                if not d:
                    break
                got += d
                if b'\x62\xf1\x86' in got:
                    break
            out['uds'] = got.hex() if got else None
            t.close()
        except OSError as e:
            out['routing'] = out['uds'] = f'ERR:{type(e).__name__}'
        return out

    def baseline(self):
        self.base = self.sample()
        return self.base

    def check(self):
        now = self.sample()
        diffs = []
        for k in ('vir', 'status', 'routing', 'uds'):
            if now.get(k) != self.base.get(k):
                diffs.append(f'{k}: {self.base.get(k)} -> {now.get(k)}')
        return diffs, now


def gen_hdr_cases(rnd):
    body = struct.pack('>HB', TESTER, 0) + b'\0' * 4
    yield 'ver_bad', hdr(0x0005, body, ver=rnd.choice([0x00, 0x01, 0x02, 0x04, 0xFE, 0xFF]))
    yield 'inv_mismatch', hdr(0x0005, body, inv=rnd.randrange(256))
    yield 'len_over', hdr(0x0005, body, length=rnd.choice([0xFFFFFFFF, 0x7FFFFFFF, 0x10000, len(body) + 1000]))
    yield 'len_under', hdr(0x0005, body, length=rnd.randrange(0, len(body)))
    yield 'len_zero_typed', hdr(0x0005, b'', length=0)
    yield 'ptype_unknown', hdr(rnd.randrange(0x10000), bytes(rnd.randrange(0, 64)))
    yield 'ptype_reserved', hdr(rnd.choice([0x0002, 0x0003, 0x0009, 0x4000, 0x8004, 0xF000]), bytes(8))
    n = rnd.choice([1, 2, 3, 7])
    yield 'truncated', hdr(0x4001)[:n]
    yield 'hdr_only_huge', hdr(0x8001, b'', length=0xFFFFFF)
    yield 'oversize_body', hdr(0x8001, struct.pack('>HH', TESTER, TARGET_TA) + bytes(rnd.randrange(16384, 40000)))


def gen_routing_cases(rnd):
    yield 'act_type_sweep', hdr(0x0005, struct.pack('>HB', TESTER, rnd.randrange(256)) + b'\0' * 4)
    yield 'sa_sweep', hdr(0x0005, struct.pack('>HB', rnd.randrange(0x10000), 0) + b'\0' * 4)
    yield 'act_short', hdr(0x0005, struct.pack('>HB', TESTER, 0)[:rnd.randrange(1, 3)])
    yield 'act_long', hdr(0x0005, struct.pack('>HB', TESTER, 0) + bytes(rnd.randrange(4, 200)))
    yield 'act_oem', hdr(0x0005, struct.pack('>HB', TESTER, 0) + b'\0' * 4 + os.urandom(4))


def gen_uds_cases(rnd, unsafe):
    def diag(pl, sa=TESTER, ta=TARGET_TA):
        return hdr(0x8001, struct.pack('>HH', sa, ta) + pl)
    svc = rnd.randrange(256)
    if not unsafe and svc in WRITE_SERVICES:
        svc = 0x22
    yield 'uds_svc_sweep', diag(bytes([svc]) + bytes(rnd.randrange(0, 6)))
    yield 'uds_did_sweep', diag(b'\x22' + struct.pack('>H', rnd.randrange(0x10000)))
    yield 'uds_did_many', diag(b'\x22' + b''.join(struct.pack('>H', rnd.randrange(0x10000))
                                                  for _ in range(rnd.randrange(2, 300))))
    yield 'uds_trunc', diag(b'\x22\xf1')
    yield 'uds_empty', diag(b'')
    yield 'uds_dtc_mask', diag(bytes([0x19, rnd.randrange(0x20), rnd.randrange(256)]))
    yield 'uds_addr_swap', diag(b'\x3e\x00', sa=rnd.randrange(0x10000), ta=rnd.randrange(0x10000))
    yield 'uds_huge_did', diag(b'\x22' + os.urandom(rnd.randrange(200, 4096)))
    yield 'uds_before_routing', None   # sent without routing activation


STAGES = {'hdr': gen_hdr_cases, 'routing': gen_routing_cases, 'uds': lambda r: gen_uds_cases(r, False)}


def send_case(host, data, pre_routing=True, timeout=3.0):
    try:
        t = socket.create_connection((host, 13400), timeout)
    except OSError as e:
        return f'CONNECT_FAIL:{type(e).__name__}'
    t.settimeout(timeout)
    try:
        if pre_routing:
            t.sendall(hdr(0x0005, struct.pack('>HB', TESTER, 0) + b'\0' * 4))
            try:
                t.recv(4096)
            except socket.timeout:
                return 'NO_ROUTING_RESP'
        t.sendall(data)
        got = b''
        try:
            while True:
                d = t.recv(4096)
                if not d:
                    break
                got += d
                if len(got) > 65536:
                    break
        except socket.timeout:
            pass
        except ConnectionResetError:
            if len(got) >= 9 and struct.unpack('>H', got[2:4])[0] == 0x0000:
                return f'NACK:{NACK.get(got[8], got[8])}'
            return 'RST_NO_REJECT' + (f' after {len(got)}B' if got else '')
        if not got:
            return 'SILENT'
        pt = struct.unpack('>H', got[2:4])[0] if len(got) >= 4 else -1
        if pt == 0x0000 and len(got) >= 9:
            return f'NACK:{NACK.get(got[8], got[8])}'
        return f'{PT_NAMES.get(pt, hex(pt))} {len(got)}B'
    except BrokenPipeError:
        return 'BROKEN_PIPE'
    except OSError as e:
        return f'ERR:{type(e).__name__}'
    finally:
        try:
            t.close()
        except OSError:
            pass


def main():
    a = argparse.ArgumentParser()
    a.add_argument('cmd', choices=['health', 'fuzz', 'replay'])
    a.add_argument('arg', nargs='?')
    a.add_argument('-t', '--target', default='127.0.0.1')
    a.add_argument('-n', '--count', type=int, default=200)
    a.add_argument('--stage', default='all', choices=['hdr', 'routing', 'uds', 'all'])
    a.add_argument('--seed', type=int, default=None)
    a.add_argument('--outdir', default='fuzz-cases')
    a.add_argument('--delay', type=float, default=0.05)
    a.add_argument('--check-every', type=int, default=25)
    a.add_argument('--unsafe', action='store_true')
    o = a.parse_args()

    h = Health(o.target)

    if o.cmd == 'health':
        b = h.baseline()
        for k, v in b.items():
            print(f'  {k:8} {v}')
        return 0

    if o.cmd == 'replay':
        data = open(o.arg, 'rb').read()
        print(f'[*] baseline'); h.baseline()
        print(f'[*] replaying {o.arg} ({len(data)}B): {data.hex()}')
        print(f'    verdict: {send_case(o.target, data)}')
        diffs, _ = h.check()
        print('    health: ' + ('OK' if not diffs else 'CHANGED -> ' + '; '.join(diffs)))
        return 0

    seed = o.seed if o.seed is not None else random.randrange(1 << 30)
    rnd = random.Random(seed)
    os.makedirs(o.outdir, exist_ok=True)
    print(f'[*] seed {seed}, stage {o.stage}, {o.count} cases, target {o.target}')

    print('[*] baseline')
    base = h.baseline()
    if not base.get('vir'):
        print('[!] no VehicleIdentificationResponse at baseline. Fix the link first.')
        return 1
    for k, v in base.items():
        print(f'    {k:8} {(v or "")[:70]}')

    gens = list(STAGES.values()) if o.stage == 'all' else [STAGES[o.stage]]
    anomalies = 0
    seen = collections.Counter()
    # health runs every --check-every cases, so the case that broke it is
    # usually not the one in hand when the change is noticed
    recent = collections.deque(maxlen=max(200, o.check_every * 4))
    for i in range(o.count):
        g = rnd.choice(gens)
        cases = [c for c in g(rnd) if c[1] is not None]
        name, data = rnd.choice(cases)
        verdict = send_case(o.target, data, pre_routing=(name != 'uds_before_routing'))
        recent.append({'i': i, 'case': name, 'hex': data.hex(), 'verdict': verdict})

        benign = verdict.startswith('NACK:') or (verdict == 'SILENT' and name == 'truncated')
        interesting = (not benign) and verdict.startswith(
            ('CONNECT_FAIL', 'RST_NO_REJECT', 'SILENT', 'BROKEN_PIPE', 'ERR', 'NO_ROUTING'))
        if interesting:
            anomalies += 1
            key = (name, verdict.split(' after ')[0])
            seen[key] += 1
            if seen[key] == 1:
                path = os.path.join(o.outdir, f'{i:06d}_{name}.bin')
                open(path, 'wb').write(data)
                with open(os.path.join(o.outdir, 'log.jsonl'), 'a') as f:
                    f.write(json.dumps({'i': i, 'seed': seed, 'case': name,
                                        'verdict': verdict, 'hex': data.hex(),
                                        'file': path}) + '\n')
                print(f'  [{i}] NEW {name:20} {verdict:28} saved {path}')

        if i and i % o.check_every == 0:
            diffs, now = h.check()
            if diffs:
                time.sleep(3)
                diffs2, now2 = h.check()
                state = 'PERSISTED' if diffs2 else 'RECOVERED'
                print(f'  [{i}] HEALTH CHANGED after {name} -> {state}')
                for d in diffs:
                    print(f'        {d}')
                with open(os.path.join(o.outdir, 'health.jsonl'), 'a') as f:
                    f.write(json.dumps({'i': i, 'seed': seed, 'after_case': name,
                                        'case_hex': data.hex(), 'diffs': diffs,
                                        'recheck': state, 'diffs_after_3s': diffs2,
                                        'now': now2 if diffs2 else now}) + '\n')
                open(os.path.join(o.outdir, f'{i:06d}_HEALTH_{state}_{name}.bin'), 'wb').write(data)
                win = os.path.join(o.outdir, f'{i:06d}_WINDOW_{state}.jsonl')
                with open(win, 'w') as f:
                    for r in recent:
                        f.write(json.dumps(r) + '\n')
                print(f'        {len(recent)} preceding cases -> {win}')
                h.baseline()
        time.sleep(o.delay)

    print(f'[*] done. {anomalies} transport anomalies, {len(seen)} distinct.')
    for (nm, vd), c in seen.most_common():
        print(f'    {c:7d}  {nm:20} {vd}')
    print(f'[*] check {o.outdir}/health.jsonl first, that is the real signal.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
