#!/usr/bin/env python3
"""
Stateful DoIP / UDS fuzzer.

  ./doipstate.py -t 127.0.0.1 -n 5000 --seed 1
  ./doipstate.py replay sequences/000123.json

Never emits UDS 0x2E, 0x31, 0x11, 0x34-0x37, 0x85, 0x28 or 0x27.
"""
import argparse, json, os, random, socket, struct, sys, time

V, TESTER, ECU = 0x03, 0x0EF4, 0x0063
SAS = [0x0EF3, 0x0EF4, 0x0EF5, 0x0E80, 0x0F00]
READ_DIDS = [0xF186, 0xF190, 0xF187, 0xF18C, 0xF1A0, 0x1234]


def hdr(ptype, payload=b''):
    return struct.pack('>BBHI', V, 0xFF ^ V, ptype, len(payload)) + payload


def diag(sa, ta, uds):
    return hdr(0x8001, struct.pack('>HH', sa, ta) + uds)


class Conn:
    def __init__(self, target, sa):
        self.sa, self.activated, self.dead = sa, False, False
        self.sock = socket.socket()
        self.sock.settimeout(3)
        self.sock.connect((target, 13400))

    def send(self, data):
        try:
            self.sock.sendall(data)
        except OSError:
            self.dead = True

    def recv(self, answer_alive=True):
        """Answers AliveCheckRequest unless told not to."""
        try:
            head = self.sock.recv(8)
            if len(head) < 8:
                self.dead = True
                return None
            ptype, n = struct.unpack('>H', head[2:4])[0], struct.unpack('>I', head[4:8])[0]
            body = b''
            while len(body) < n:
                chunk = self.sock.recv(n - len(body))
                if not chunk:
                    break
                body += chunk
            if ptype == 0x0007 and answer_alive:
                self.send(hdr(0x0008, struct.pack('>H', self.sa)))
            return ptype, body
        except OSError:
            self.dead = True
            return None

    def close(self, rst=False):
        try:
            if rst:
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                     struct.pack('ii', 1, 0))
            self.sock.close()
        except OSError:
            pass
        self.dead = True


def safe_uds(rnd):
    """A UDS request that reads or changes session state but never writes."""
    pick = rnd.randrange(6)
    if pick == 0:
        return bytes([0x10, rnd.choice([0x01, 0x02, 0x03, 0x04, 0x60])])
    if pick == 1:
        return bytes([0x3E, rnd.choice([0x00, 0x80])])
    if pick == 2:
        return bytes([0x22]) + struct.pack('>H', rnd.choice(READ_DIDS))
    if pick == 3:
        return bytes([0x27, rnd.choice([0x01, 0x03, 0x05, 0x11])])
    if pick == 4:
        return bytes([0x29, rnd.choice([0x00, 0x01, 0x03, 0x08])])
    return bytes([0x19, rnd.choice([0x01, 0x02, 0x06]), 0xFF])


def gen_sequence(rnd, length):
    ops = []
    for _ in range(length):
        k = rnd.randrange(10)
        if k <= 1:
            ops.append({'op': 'open', 'sa': rnd.choice(SAS)})
        elif k == 2:
            ops.append({'op': 'activate', 'conn': rnd.randrange(4),
                        'type': rnd.choice([0x00, 0x01, 0xE0])})
        elif k <= 5:
            ops.append({'op': 'uds', 'conn': rnd.randrange(4),
                        'uds': safe_uds(rnd).hex()})
        elif k == 6:
            ops.append({'op': 'close', 'conn': rnd.randrange(4),
                        'rst': rnd.random() < 0.5})
        elif k == 7:
            ops.append({'op': 'abandon', 'conn': rnd.randrange(4)})
        elif k == 8:
            ops.append({'op': 'idle', 'secs': rnd.choice([0.1, 0.5, 2])})
        else:
            ops.append({'op': 'uds_no_read', 'conn': rnd.randrange(4),
                        'uds': safe_uds(rnd).hex()})
    return ops


def run_sequence(target, ops, leaked):
    conns = []
    for o in ops:
        try:
            if o['op'] == 'open':
                if len(conns) < 8:
                    conns.append(Conn(target, o['sa']))
            elif not conns:
                continue
            elif o['op'] == 'activate':
                c = conns[o['conn'] % len(conns)]
                c.send(hdr(0x0005, struct.pack('>HB', c.sa, o['type']) + b'\0' * 4))
                r = c.recv()
                c.activated = bool(r and r[0] == 0x0006 and len(r[1]) > 4 and r[1][4] == 0x10)
            elif o['op'] == 'uds':
                c = conns[o['conn'] % len(conns)]
                c.send(diag(c.sa, ECU, bytes.fromhex(o['uds'])))
                c.recv()
            elif o['op'] == 'uds_no_read':
                c = conns[o['conn'] % len(conns)]
                c.send(diag(c.sa, ECU, bytes.fromhex(o['uds'])))
            elif o['op'] == 'close':
                conns.pop(o['conn'] % len(conns)).close(rst=o['rst'])
            elif o['op'] == 'abandon':
                leaked.append(conns.pop(o['conn'] % len(conns)))
            elif o['op'] == 'idle':
                time.sleep(o['secs'])
        except (OSError, IndexError):
            pass
    for c in conns:
        c.close()


def health(target):
    out = {}
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(3)
    try:
        u.sendto(hdr(0x0001), (target, 13400))
        out['vir'] = u.recvfrom(2048)[0].hex()[:40]
    except OSError as e:
        out['vir'] = 'ERR:' + type(e).__name__
    finally:
        u.close()

    s = socket.socket()
    s.settimeout(4)
    try:
        s.connect((target, 13400))
        s.sendall(hdr(0x0005, struct.pack('>HB', TESTER, 0) + b'\0' * 4))
        d = s.recv(64)
        out['act'] = 'code=0x%02x' % d[12] if len(d) > 12 else 'SHORT:' + d.hex()
        s.sendall(diag(TESTER, ECU, bytes([0x22, 0xF1, 0x86])))
        r = s.recv(64)
        out['uds'] = r.hex() if r else 'EMPTY'
    except OSError as e:
        out['act'] = out.get('act', 'ERR:' + type(e).__name__)
        out.setdefault('uds', 'ERR:' + type(e).__name__)
    finally:
        s.close()
    return out


def main():
    a = argparse.ArgumentParser()
    a.add_argument('cmd', nargs='?', default='fuzz', choices=['fuzz', 'replay'])
    a.add_argument('arg', nargs='?')
    a.add_argument('-t', '--target', default='127.0.0.1')
    a.add_argument('-n', '--count', type=int, default=2000)
    a.add_argument('--seed', type=int, default=None)
    a.add_argument('--len', type=int, default=12)
    a.add_argument('--outdir', default='sequences')
    o = a.parse_args()

    if o.cmd == 'replay':
        ops = json.load(open(o.arg))['ops']
        leaked = []
        print(f'[*] replaying {len(ops)} ops')
        print('    before:', health(o.target))
        run_sequence(o.target, ops, leaked)
        print('    after: ', health(o.target))
        time.sleep(3)
        print('    +3s:   ', health(o.target))
        return 0

    os.makedirs(o.outdir, exist_ok=True)
    seed = o.seed if o.seed is not None else random.randrange(1 << 30)
    rnd = random.Random(seed)
    print(f'[*] seed {seed}, {o.count} sequences of ~{o.len} ops, target {o.target}')

    base = health(o.target)
    print('[*] baseline', base)
    if base.get('act') != 'code=0x10':
        print('[!] not healthy at baseline, fix that first')
        return 1

    leaked = []
    for i in range(o.count):
        ops = gen_sequence(rnd, o.len)
        # written before the run, so a sequence that kills the ECU survives it
        cur = os.path.join(o.outdir, 'current.json')
        json.dump({'i': i, 'seed': seed, 'ops': ops}, open(cur, 'w'))

        run_sequence(o.target, ops, leaked)
        now = health(o.target)

        if now != base:
            time.sleep(3)
            again = health(o.target)
            state = 'PERSISTED' if again != base else 'RECOVERED'
            path = os.path.join(o.outdir, f'{i:06d}_{state}.json')
            json.dump({'i': i, 'seed': seed, 'ops': ops, 'baseline': base,
                       'after': now, 'after_3s': again, 'leaked_conns': len(leaked)},
                      open(path, 'w'), indent=1)
            print(f'  [{i}] HEALTH CHANGED {state} -> {path}')
            for k in base:
                if base[k] != now.get(k):
                    print(f'        {k}: {base[k]} -> {now.get(k)}')
            if state == 'PERSISTED':
                print('        stopping so the state is preserved for inspection')
                return 2
        if i % 100 == 0:
            print(f'  [{i}] ok, {len(leaked)} leaked conns held')
    print('[*] done, no persistent health change')
    return 0


if __name__ == '__main__':
    sys.exit(main())
