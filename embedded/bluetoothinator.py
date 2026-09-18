!/usr/bin/env python3
"""Connect to a Bluetooth device and get a shell to poke at it.

Commands:
  sdp                 browse services
  rfcomm <ch> [hex]   open a channel, read, optionally send bytes first
  l2cap <psm>         try an L2CAP connect
  scan                classic inquiry
  info                bond and connection state
  name                remote name request
  class [hex]         show or set our class of device
  myname [str]        show or set our name
  myaddr [addr]       show or set our BD_ADDR
  fresh               take a new random BD_ADDR
  id                  show our full identity
  reset               restore the adapter identity we started with
  pair | unpair
  raw <cmd...>        run a bluetoothctl command
  q
"""
import argparse, ctypes, errno, os, random, re, select, shlex, socket, struct, subprocess, sys, time

try:
    import readline
except ImportError:  # free-threaded builds ship without it
    readline = None

AF_BLUETOOTH, RFCOMM, L2CAP = 31, 3, 0
HCI = "hci0"
CMDS = "sdp rfcomm l2cap scan info name class myname myaddr fresh id reset pair unpair raw q".split()
HISTFILE = os.path.expanduser("~/.bluetoothinator_history")
libc = ctypes.CDLL("libc.so.6", use_errno=True)


def sh(cmd, t=90):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
        return re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return "<timeout>"


def ident():
    cfg = sh(f"hciconfig -a {HCI}")
    g = lambda r: (re.search(r, cfg) or [None, "?"])[1]
    return g(r"BD Address: (\S+)"), g(r"Name: '(.*)'"), g(r"Class: (0x[0-9a-f]+)"), g(r"Device Class: (.+)")


def idline():
    return "{} '{}' {} {}".format(*ident())


def hexeq(a, b):
    try:
        return int(a, 16) == int(b, 16)
    except ValueError:
        return False


def rname(bd):
    return sh(f"hcitool -i {HCI} name {bd}", 15) or "no name response"


def up():
    for _ in range(10):
        if "UP RUNNING" in sh(f"hciconfig {HCI}"):
            return True
        sh(f"hciconfig {HCI} up")
        time.sleep(0.5)
    return False


def set_addr(addr, cod):
    """Must start from an adapter that is up. Cycling a down adapter drops the
    pending address and the controller comes back on its factory one."""
    if not up():
        return "adapter will not come up, refusing to touch the address"
    idx = re.sub(r"\D", "", HCI) or "0"
    last = ""
    for _ in range(3):
        # ponytail: sleeps tuned against MediaTek, stretch them if a slower dongle races
        last = sh(f"hciconfig {HCI} reset; sleep 3; hciconfig {HCI} down; sleep 1; "
                  f"btmgmt --index {idx} public-addr {addr}; hciconfig {HCI} up; sleep 2", 40)
        if ident()[0].upper() == addr.upper():
            up()
            if cod and cod != "?":
                sh(f"hciconfig {HCI} class {cod}")
            # bluetoothd re-init can silently put the factory address back.
            time.sleep(3)
            if ident()[0].upper() != addr.upper():
                continue
            return f"{addr} ok"
    up()
    return f"failed to set {addr}, now {ident()[0]} ({last})"


def bdbytes(bd):
    return bytes(int(x, 16) for x in reversed(bd.split(":")))


def connect(sock, sa, t):
    buf = ctypes.create_string_buffer(sa, len(sa))
    if libc.connect(sock.fileno(), buf, len(sa)) != 0:
        e = ctypes.get_errno()
        if e != errno.EINPROGRESS:
            return errno.errorcode.get(e, str(e))
        if not select.select([], [sock], [], t)[1]:
            return "TIMEOUT"
        if (err := sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)):
            return errno.errorcode.get(err, str(err))
    return "OPEN"


def dump(data):
    for i in range(0, len(data), 16):
        c = data[i:i + 16]
        txt = "".join(chr(b) if 32 <= b < 127 else "." for b in c)
        print(f"    {i:04x}  {c.hex(' '):<47}  {txt}")


def rfcomm(bd, ch, send=b"", t=8.0):
    s = socket.socket(AF_BLUETOOTH, socket.SOCK_STREAM, RFCOMM)
    s.setblocking(False)
    try:
        r = connect(s, struct.pack("<H6sBx", AF_BLUETOOTH, bdbytes(bd), ch), t)
        print(f"  connect: {r}")
        if r != "OPEN":
            return
        if send:
            s.setblocking(True)
            s.send(send)
            s.setblocking(False)
            print(f"  sent {len(send)}B")
        data, end = b"", time.time() + 4
        while time.time() < end:
            if not select.select([s], [], [], max(0, end - time.time()))[0]:
                break
            d = s.recv(4096)
            if not d:
                break
            data += d
        print(f"  got {len(data)}B")
        if data:
            dump(data)
    except OSError as e:
        print(f"  {e}")
    finally:
        s.close()


def l2cap(bd, psm, t=5.0):
    s = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, L2CAP)
    s.setblocking(False)
    try:
        print(f"  connect: {connect(s, struct.pack('<HH6sHB', AF_BLUETOOTH, psm, bdbytes(bd), 0, 0), t)}")
    finally:
        s.close()


def history():
    if not readline:
        return
    try:
        readline.read_history_file(HISTFILE)
    except OSError:
        pass
    readline.set_completer(lambda t, i: ([c for c in CMDS if c.startswith(t)] + [None])[i])
    readline.parse_and_bind("tab: complete")



def main():
    global HCI
    a = argparse.ArgumentParser()
    a.add_argument("bdaddr", nargs="?")
    a.add_argument("--class", dest="cod", default="0x240418")
    a.add_argument("--name")
    a.add_argument("--addr")
    a.add_argument("--dev", default="hci0")
    o = a.parse_args()
    if not o.bdaddr:
        a.error("bdaddr required")
    HCI = o.dev
    bd = o.bdaddr
    orig = ident()

    if o.addr:
        print(set_addr(o.addr, o.cod))
    if o.name:
        sh(f"bluetoothctl system-alias {shlex.quote(o.name)}")
    sh(f"hciconfig {HCI} class {o.cod}")
    time.sleep(1)
    addr, name, got, dev = ident()
    if not hexeq(got, o.cod):
        print(f"warning: class is {got}, not {o.cod}")

    print(__doc__)
    print(f"us     {addr}  '{name}'  {got} {dev}")
    print(f"target {bd}  {rname(bd)}\n")
    history()

    while True:
        try:
            line = input(f"{bd}> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        cmd, *args = line.split()

        if cmd in ("q", "quit", "exit"):
            break
        elif cmd == "sdp":
            out = sh(f"sdptool -i {HCI} browse {bd}")
            for m in re.finditer(r"Service Name: (.+)|Channel: (\d+)|PSM: (\d+)", out):
                print("  " + m.group(0))
        elif cmd == "rfcomm" and args:
            rfcomm(bd, int(args[0]), bytes.fromhex(args[1]) if len(args) > 1 else b"")
        elif cmd == "l2cap" and args:
            l2cap(bd, int(args[0], 0))
        elif cmd == "scan":
            print(sh(f"hcitool -i {HCI} scan --flush", 40) or "  nothing found")
        elif cmd == "info":
            print(sh(f"bluetoothctl info {bd}"))
        elif cmd == "name":
            print(f"  {rname(bd)}")
        elif cmd == "class":
            if args:
                sh(f"hciconfig {HCI} class {args[0]}")
            print("  " + sh(f"hciconfig -a {HCI} | grep -E 'Class:|Device Class:'"))
        elif cmd == "myname":
            if args:
                sh(f"bluetoothctl system-alias {shlex.quote(' '.join(args))}")
            print(f"  {ident()[1]}")
        elif cmd == "myaddr":
            if args:
                print("  " + set_addr(args[0], ident()[2]))
            print(f"  {ident()[0]}")
        elif cmd == "fresh":
            new = "DE:AD:" + ":".join(f"{random.randrange(256):02X}" for _ in range(4))
            print("  " + set_addr(new, ident()[2]))
            print(f"  {ident()[0]}")
        elif cmd == "id":
            print("  " + idline())
        elif cmd == "reset":
            if ident()[0] != orig[0]:
                set_addr(orig[0], orig[2])
            sh("bluetoothctl reset-alias")
            sh(f"hciconfig {HCI} class {orig[2]}")
            time.sleep(1)
            print("  " + idline())
        elif cmd == "pair":
            print(sh(f"bluetoothctl --timeout 25 -- pair {bd}", 40))
        elif cmd == "unpair":
            print(sh(f"bluetoothctl remove {bd}"))
        elif cmd == "raw" and args:
            print(sh(f"bluetoothctl {' '.join(args)}"))
        else:
            print("  ?")

    if readline:
        try:
            readline.write_history_file(HISTFILE)
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
