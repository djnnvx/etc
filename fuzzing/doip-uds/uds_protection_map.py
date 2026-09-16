#!/usr/bin/env python3
"""
  0x33 securityAccessDenied          -> SecurityAccess 0x27
  0x34 authenticationRequired        -> Authentication 0x29
  0x7F serviceNotSupportedInSession  -> session gated
  0x7E subFunctionNotSupportedInSess -> session gated (subfunction)
  0x13 incorrectMessageLength        -> REACHABLE, no gate hit
  0x22 conditionsNotCorrect          -> reached handler, precondition unmet
  0x11 serviceNotSupported           -> not implemented
  non-standard codes                 -> vendor filter, never reaches the handler

  sudo ./uds_protection_map.py -t 127.0.0.1
  sudo ./uds_protection_map.py -t 127.0.0.1 --ta 0x0040 --all-sessions
"""
import argparse, socket, struct, sys

V = 0x03
GATE = {
    0x33: ('SecurityAccess 0x27', 'gated'),
    0x34: ('Authentication 0x29', 'gated'),
    0x7F: ('session', 'gated'),
    0x7E: ('session (subfunction)', 'gated'),
    0x13: ('none, reachable', 'OPEN'),
    0x12: ('none, subfunc invalid', 'OPEN'),
    0x31: ('none, out of range', 'OPEN'),
    0x22: ('precondition', 'reached'),
    0x24: ('request sequence', 'reached'),
    0x11: ('not implemented', 'absent'),
    0xF0: ('vendor-specific', 'FILTERED'),
}
NAMES = {0x10: 'DiagnosticSessionControl', 0x11: 'ECUReset', 0x14: 'ClearDiagnosticInformation',
         0x19: 'ReadDTCInformation', 0x22: 'ReadDataByIdentifier', 0x23: 'ReadMemoryByAddress',
         0x24: 'ReadScalingDataByIdentifier', 0x27: 'SecurityAccess', 0x28: 'CommunicationControl',
         0x29: 'Authentication', 0x2A: 'ReadDataByPeriodicIdentifier',
         0x2C: 'DynamicallyDefineDataIdentifier', 0x2E: 'WriteDataByIdentifier',
         0x2F: 'InputOutputControlByIdentifier', 0x31: 'RoutineControl', 0x34: 'RequestDownload',
         0x35: 'RequestUpload', 0x36: 'TransferData', 0x37: 'RequestTransferExit',
         0x38: 'RequestFileTransfer', 0x3D: 'WriteMemoryByAddress', 0x3E: 'TesterPresent',
         0x83: 'AccessTimingParameter', 0x84: 'SecuredDataTransmission',
         0x85: 'ControlDTCSetting', 0x86: 'ResponseOnEvent', 0x87: 'LinkControl'}


class Session:
    def __init__(self, host, sa, ta, timeout):
        self.sa, self.ta, self.timeout = sa, ta, timeout
        self.s = socket.create_connection((host, 13400), timeout)
        self.s.settimeout(timeout)
        self.s.sendall(self._h(0x0005, struct.pack('>HB', sa, 0) + b'\0' * 4))
        self.s.recv(4096)

    @staticmethod
    def _h(pt, pl=b''):
        return struct.pack('>BBHI', V, 0xFF ^ V, pt, len(pl)) + pl

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

    def uds(self, payload):
        self.s.sendall(self._h(0x8001, struct.pack('>HH', self.sa, self.ta) + payload))
        while True:
            try:
                pt, b = self._rd()
            except socket.timeout:
                return None
            if pt == 0x0007:                      # AliveCheckRequest
                self.s.sendall(self._h(0x0008, struct.pack('>H', self.sa)))
                continue
            if pt == 0x8002:
                continue
            if pt == 0x8003:
                return None
            if pt != 0x8001:
                continue
            r = b[4:]
            if len(r) >= 3 and r[0] == 0x7F and r[2] == 0x78:
                continue
            return r


def sweep(sess, label):
    print(f'\n=== {label}')
    print(f'  {"SID":5} {"service":34} {"NRC":5} {"verdict":10} gate')
    buckets = {}
    for sid in range(0x100):
        r = sess.uds(bytes([sid]))
        if r is None:
            continue
        if r[0] == 0x7F and len(r) >= 3:
            nrc = r[2]
            gate, verdict = GATE.get(nrc, (f'unknown 0x{nrc:02X}', '?'))
        else:
            nrc, gate, verdict = 0, 'accepted bare SID', 'OPEN'
        if verdict == 'absent':
            continue
        buckets.setdefault(verdict, []).append(sid)
        print(f'  0x{sid:02X}  {NAMES.get(sid, ""):34} 0x{nrc:02X}  {verdict:10} {gate}')
    print(f'\n  summary for {label}:')
    for v in ('OPEN', 'reached', 'gated', 'FILTERED'):
        if v in buckets:
            print(f'    {v:9} {len(buckets[v]):3}  ' + ' '.join(f'{x:02X}' for x in buckets[v]))
    return buckets


def main():
    a = argparse.ArgumentParser()
    a.add_argument('-t', '--target', default='127.0.0.1')
    a.add_argument('-s', '--sa', default='0x0EF4')
    a.add_argument('-d', '--ta', default='0x0010')
    a.add_argument('--timeout', type=float, default=3.0)
    a.add_argument('--all-sessions', action='store_true', help='also probe in extended session')
    o = a.parse_args()

    sess = Session(o.target, int(o.sa, 0), int(o.ta, 0), o.timeout)
    print(f'[*] target {o.target} ta={o.ta}, bare-SID probe (always invalid length, never executes)')
    sweep(sess, 'default session (10 01)')

    if o.all_sessions:
        r = sess.uds(b'\x10\x03')
        if r and r[0] == 0x50:
            sweep(sess, 'extended session (10 03)')
            sess.uds(b'\x10\x01')
        else:
            print('\n[-] could not enter extended session')
    return 0


if __name__ == '__main__':
    sys.exit(main())
