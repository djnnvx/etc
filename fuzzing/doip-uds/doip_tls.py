#!/usr/bin/env python3
"""
DoIP over TLS client (ISO 13400 assigns port 3496). Does not verify the server
chain. Use `map` to compare the UDS request filter against plaintext 13400.

  ./doip_tls.py info
  ./doip_tls.py map
  ./doip_tls.py send 22 F1 86
"""
import argparse, socket, ssl, struct, sys

V = 0x03
NRC = {0x10: 'generalReject', 0x11: 'serviceNotSupported', 0x12: 'subFunctionNotSupported',
       0x13: 'incorrectMessageLength', 0x22: 'conditionsNotCorrect', 0x24: 'requestSequenceError',
       0x31: 'requestOutOfRange', 0x33: 'securityAccessDenied', 0x34: 'authenticationRequired',
       0x35: 'invalidKey', 0x36: 'exceedNumberOfAttempts', 0x37: 'requiredTimeDelayNotExpired',
       0x70: 'uploadDownloadNotAccepted', 0x7E: 'subFuncNotSupportedInSession',
       0x7F: 'serviceNotSupportedInSession', 0xF0: 'vendor-specific'}
NAMES = {0x10: 'DiagnosticSessionControl', 0x11: 'ECUReset', 0x14: 'ClearDiagnosticInformation',
         0x19: 'ReadDTCInformation', 0x22: 'ReadDataByIdentifier', 0x23: 'ReadMemoryByAddress',
         0x27: 'SecurityAccess', 0x28: 'CommunicationControl', 0x29: 'Authentication',
         0x2E: 'WriteDataByIdentifier', 0x2F: 'InputOutputControlByIdentifier',
         0x31: 'RoutineControl', 0x34: 'RequestDownload', 0x35: 'RequestUpload',
         0x36: 'TransferData', 0x37: 'RequestTransferExit', 0x3D: 'WriteMemoryByAddress',
         0x3E: 'TesterPresent', 0x85: 'ControlDTCSetting', 0x87: 'LinkControl'}


def hdr(pt, pl=b''):
    return struct.pack('>BBHI', V, 0xFF ^ V, pt, len(pl)) + pl


class TlsDoIP:
    def __init__(self, host, port, sa, ta, timeout=6.0):
        self.sa, self.ta = sa, ta
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, port), timeout)
        self.s = ctx.wrap_socket(raw, server_hostname=None)
        self.s.settimeout(timeout)
        c = self.s.getpeercert(binary_form=False)
        print(f'[+] TLS {self.s.version()} {self.s.cipher()[0]}')
        self.peercert = c

    def _rd(self):
        h = self.s.recv(8)
        if len(h) < 8:
            return None, b''
        _, _, pt, ln = struct.unpack('>BBHI', h)
        b = b''
        while len(b) < ln:
            c = self.s.recv(ln - len(b))
            if not c:
                break
            b += c
        return pt, b

    def activate(self):
        self.s.sendall(hdr(0x0005, struct.pack('>HB', self.sa, 0) + b'\0' * 4))
        pt, b = self._rd()
        if pt == 0x0006 and len(b) >= 5:
            ta, ea, code = struct.unpack('>HHB', b[:5])
            print(f'[+] routing activation over TLS: entity=0x{ea:04X} code=0x{code:02X}'
                  + ('  ACTIVATED' if code == 0x10 else ''))
            return code == 0x10
        print(f'[-] routing activation failed: ptype={pt} {b.hex()}')
        return False

    def uds(self, payload):
        self.s.sendall(hdr(0x8001, struct.pack('>HH', self.sa, self.ta) + payload))
        while True:
            try:
                pt, b = self._rd()
            except (socket.timeout, ssl.SSLError):
                return None
            if pt == 0x0007:                      # AliveCheckRequest
                self.s.sendall(hdr(0x0008, struct.pack('>H', self.sa)))
                continue
            if pt == 0x8002:
                continue
            if pt == 0x8003 or pt is None:
                return None
            if pt != 0x8001:
                continue
            r = b[4:]
            if len(r) >= 3 and r[0] == 0x7F and r[2] == 0x78:
                continue
            return r


def show(r):
    if r is None:
        print('    (no response)')
    elif len(r) >= 3 and r[0] == 0x7F:
        print(f'    NEG svc=0x{r[1]:02X} nrc=0x{r[2]:02X} {NRC.get(r[2], "?")}')
    else:
        t = ''.join(chr(c) if 32 <= c < 127 else '.' for c in r)
        print(f'    POS {r.hex()}  "{t}"')


def main():
    a = argparse.ArgumentParser()
    a.add_argument('cmd', choices=['info', 'map', 'send'])
    a.add_argument('data', nargs='*')
    a.add_argument('-t', '--target', default='127.0.0.1')
    a.add_argument('-p', '--port', type=int, default=3496)
    a.add_argument('-s', '--sa', default='0x0EF4')
    a.add_argument('-d', '--ta', default='0x0010')
    o = a.parse_args()

    c = TlsDoIP(o.target, o.port, int(o.sa, 0), int(o.ta, 0))
    if o.cmd == 'info':
        return 0
    if not c.activate():
        print('[-] cannot proceed without routing activation')
        return 1

    if o.cmd == 'send':
        show(c.uds(bytes.fromhex(''.join(o.data))))
        return 0

    print('\n[*] bare-SID sweep over TLS, compare against plaintext 13400')
    inter = []
    for sid in range(0x100):
        r = c.uds(bytes([sid]))
        if r is None:
            continue
        if r[0] == 0x7F and len(r) >= 3 and r[2] == 0xF0:
            continue                                  # 0xF0: vendor filter
        inter.append(sid)
        if r[0] == 0x7F:
            print(f'  0x{sid:02X} {NAMES.get(sid, ""):30} NEG 0x{r[2]:02X} {NRC.get(r[2], "?")}')
        else:
            print(f'  0x{sid:02X} {NAMES.get(sid, ""):30} POS {r.hex()[:40]}')
    print(f'\n[*] {len(inter)} services bypass the filter over TLS: '
          + ' '.join(f'{x:02X}' for x in inter))
    print('    plaintext 13400 gave exactly three: 29 36 37')
    return 0


if __name__ == '__main__':
    sys.exit(main())
