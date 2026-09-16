#!/usr/bin/env python3
"""
Minimal DoIP / UDS client (ISO 13400, ISO 14229).

  ./doip.py discover
  ./doip.py info
  ./doip.py send 22 F1 90
  ./doip.py scan
  ./doip.py shell

In shell: type hex to send UDS, .ta <addr> to retarget an ECU behind the
gateway, .scan to enumerate them, .info, .q to quit.
Raw hex is raw. 0x11 resets, 0x2E writes, 0x31 runs routines.
"""
import argparse, socket, struct, sys

V = 0x03
ACT = {0x00: 'unknown source address', 0x01: 'all sockets active', 0x02: 'SA differs from activated',
       0x03: 'SA registered elsewhere', 0x04: 'missing authentication', 0x05: 'rejected confirmation',
       0x06: 'unsupported activation type', 0x07: 'encrypted link required',
       0x10: 'activated', 0x11: 'confirmation required'}
NRC = {0x10: 'generalReject', 0x11: 'serviceNotSupported', 0x12: 'subFunctionNotSupported',
       0x13: 'incorrectMessageLengthOrInvalidFormat', 0x14: 'responseTooLong', 0x21: 'busyRepeatRequest',
       0x22: 'conditionsNotCorrect', 0x24: 'requestSequenceError', 0x25: 'noResponseFromSubnetComponent',
       0x31: 'requestOutOfRange', 0x33: 'securityAccessDenied', 0x34: 'authenticationRequired',
       0x35: 'invalidKey', 0x36: 'exceedNumberOfAttempts', 0x37: 'requiredTimeDelayNotExpired',
       0x70: 'uploadDownloadNotAccepted', 0x72: 'generalProgrammingFailure', 0x78: 'responsePending',
       0x7E: 'subFunctionNotSupportedInActiveSession', 0x7F: 'serviceNotSupportedInActiveSession'}
DIDS = {0xF190: 'VIN', 0xF191: 'vehicleManufacturerECUHardwareNumber', 0xF193: 'hardwareVersion',
        0xF194: 'softwareIdentification', 0xF195: 'softwareVersion', 0xF197: 'systemNameOrEngineType',
        0xF18C: 'ECUSerialNumber', 0xF1A0: 'vehicleManufacturerSpecific', 0xF186: 'activeDiagnosticSession'}


def hdr(pt, pl=b''):
    return struct.pack('>BBHI', V, 0xFF ^ V, pt, len(pl)) + pl


def rd(sock):
    h = sock.recv(8)
    if len(h) < 8:
        return None, b''
    _, _, pt, ln = struct.unpack('>BBHI', h)
    b = b''
    while len(b) < ln:
        c = sock.recv(ln - len(b))
        if not c:
            break
        b += c
    return pt, b


def udp(target, ptype, timeout=3):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.sendto(hdr(ptype), (target, 13400))
    try:
        d, a = s.recvfrom(4096)
    except socket.timeout:
        return None, b'', None
    _, _, pt, ln = struct.unpack('>BBHI', d[:8])
    return pt, d[8:8 + ln], a[0]


def discover(bcast):
    pt, b, ip = udp(bcast, 0x0001)
    if pt != 0x0004:
        print('no vehicle announcement'); return None
    print(f'entity          : {ip}')
    print(f'VIN             : {b[0:17].decode("ascii", "replace")}')
    print(f'logical address : 0x{int.from_bytes(b[17:19], "big"):04X}')
    print(f'EID / GID       : {b[19:25].hex(":")} / {b[25:31].hex(":")}')
    fa = b[31]
    print(f'further action  : 0x{fa:02X}' + (' (routing activation required)' if fa else ' (none)'))
    return ip


def info(target):
    for pt, name in ((0x4001, 'entity status'), (0x4003, 'power mode')):
        rt, b, _ = udp(target, pt)
        print(f'{name:15} : {b.hex() if b else "(no reply)"}')
        if rt == 0x4002 and len(b) >= 7:
            print(f'                  node_type=0x{b[0]:02X} max_sockets={b[1]} open={b[2]} '
                  f'max_data={int.from_bytes(b[3:7], "big")}')


class Conn:
    def __init__(self, target, sa, timeout):
        self.sa, self.timeout = sa, timeout
        self.s = socket.create_connection((target, 13400), timeout)
        self.s.settimeout(timeout)
        self.s.sendall(hdr(0x0005, struct.pack('>HB', sa, 0) + b'\x00\x00\x00\x00'))
        pt, b = rd(self.s)
        if pt != 0x0006 or len(b) < 5:
            raise SystemExit(f'routing activation failed: ptype=0x{pt:04x} {b.hex()}')
        ta, ea, code = struct.unpack('>HHB', b[:5])
        print(f'[+] routing activation: tester=0x{ta:04X} entity=0x{ea:04X} code=0x{code:02X} ({ACT.get(code, "?")})')
        if code != 0x10:
            raise SystemExit('not activated')

    def uds(self, ta, payload, quiet=False):
        self.s.sendall(hdr(0x8001, struct.pack('>HH', self.sa, ta) + payload))
        while True:
            try:
                pt, b = rd(self.s)
            except socket.timeout:
                return None
            if pt == 0x0007:                      # AliveCheckRequest
                self.s.sendall(hdr(0x0008, struct.pack('>H', self.sa)))
                continue
            if pt == 0x8002:
                continue
            if pt == 0x8003:
                if not quiet:
                    print(f'    diag NACK 0x{b[4]:02X}' if len(b) > 4 else f'    diag NACK {b.hex()}')
                return None
            if pt != 0x8001:
                if not quiet:
                    print(f'    ptype=0x{pt:04x} {b.hex()}')
                return None
            r = b[4:]
            if len(r) >= 3 and r[0] == 0x7F and r[2] == 0x78:
                continue
            return r


def show(r):
    if r is None:
        print('    (no response)')
    elif len(r) >= 3 and r[0] == 0x7F:
        print(f'    NEGATIVE svc=0x{r[1]:02X} nrc=0x{r[2]:02X} {NRC.get(r[2], "?")}')
    else:
        txt = ''.join(chr(c) if 32 <= c < 127 else '.' for c in r)
        print(f'    {r.hex()}\n    "{txt}"')


def scan(c, lo=0x0000, hi=0x0FFF):
    """Pipelined: blast a window of TesterPresent then drain."""
    print(f'[*] scanning 0x{lo:04X}-0x{hi:04X} with 3E00 (TesterPresent)')
    found = set()
    for base in range(lo, hi + 1, 64):
        for ta in range(base, min(base + 64, hi + 1)):
            c.s.sendall(hdr(0x8001, struct.pack('>HH', c.sa, ta) + b'\x3e\x00'))
        c.s.settimeout(0.6)
        while True:
            try:
                pt, b = rd(c.s)
            except socket.timeout:
                break
            if pt == 0x8001 and len(b) >= 5:
                src, r = int.from_bytes(b[0:2], 'big'), b[4:]
                if r[:1] == b'\x7e':
                    found.add((src, 'positive'))
                elif r[:1] == b'\x7f':
                    found.add((src, f'nrc=0x{r[2]:02X} {NRC.get(r[2], "?")}'))
    c.s.settimeout(c.timeout)
    print(f'[+] {len(found)} responding logical addresses:')
    for a, k in sorted(found):
        print(f'   0x{a:04X}  {k}')
    return [a for a, _ in sorted(found)]


def ident(c, addrs):
    for ta in addrs:
        print(f'\n=== ECU 0x{ta:04X}')
        for d, n in DIDS.items():
            r = c.uds(ta, b'\x22' + struct.pack('>H', d), quiet=True)
            if r and r[0] == 0x62:
                v = r[3:]
                t = ''.join(chr(x) if 32 <= x < 127 else '.' for x in v)
                print(f'  {d:04X} {n:34} "{t[:48]}"')


def main():
    a = argparse.ArgumentParser()
    a.add_argument('cmd', choices=['discover', 'info', 'send', 'scan', 'ident', 'shell'])
    a.add_argument('data', nargs='*')
    a.add_argument('-t', '--target', default='127.0.0.1')
    a.add_argument('-b', '--broadcast', default='169.254.255.255')
    a.add_argument('-s', '--sa', default='0x0EF4')
    a.add_argument('-d', '--ta', default='0x0010')
    a.add_argument('--timeout', type=float, default=4.0)
    o = a.parse_args()
    sa, ta = int(o.sa, 0), int(o.ta, 0)

    if o.cmd == 'discover':
        discover(o.broadcast); return
    if o.cmd == 'info':
        info(o.target); return

    c = Conn(o.target, sa, o.timeout)
    if o.cmd == 'send':
        show(c.uds(ta, bytes.fromhex(''.join(o.data))))
    elif o.cmd == 'scan':
        scan(c)
    elif o.cmd == 'ident':
        ident(c, [int(x, 0) for x in o.data] or scan(c))
    else:
        print('hex to send, .ta <addr>, .scan, .ident, .info, .dids, .q')
        while True:
            try:
                line = input(f'0x{ta:04X}> ').strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not line:
                continue
            if line in ('.q', '.quit'):
                break
            if line.startswith('.ta'):
                ta = int(line.split()[1], 0); continue
            if line == '.scan':
                scan(c); continue
            if line == '.ident':
                ident(c, [ta]); continue
            if line == '.info':
                info(o.target); continue
            if line == '.dids':
                for d, n in DIDS.items():
                    r = c.uds(ta, b'\x22' + struct.pack('>H', d), quiet=True)
                    if r and r[0] == 0x62:
                        v = r[3:]
                        txt = ''.join(chr(x) if 32 <= x < 127 else '.' for x in v)
                        print(f'  {d:04X} {n:42} {txt}')
                continue
            try:
                show(c.uds(ta, bytes.fromhex(line.replace(' ', ''))))
            except ValueError:
                print('  not hex')


if __name__ == '__main__':
    sys.exit(main())
