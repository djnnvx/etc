#!/usr/bin/env python3
"""
gen_corpus.py — generate structured USB/IP protocol seed corpus.

Produces 80+ binary seeds in ./corpus/, covering:
  1. op_common_valid       — well-formed protocol headers
  2. op_common_malformed   — bad version / unknown op code
  3. devlist_replies       — device-list reply bodies (ndev variations)
  4. import_requests       — busid field edge cases
  5. urb_submit            — CVE-2016-3955 class (length field variations)
  6. urb_unlink            — unlink command edge cases
  7. raw_boundary          — size boundary seeds (empty, 1 byte, max)
"""

import os
import struct
import itertools
import hashlib

OUT = os.path.join(os.path.dirname(__file__), "corpus")
os.makedirs(OUT, exist_ok=True)

written = 0

def seed(name: str, data: bytes):
    global written
    safe = name.replace("/", "_").replace("\x00", "")
    path = os.path.join(OUT, safe)
    with open(path, "wb") as f:
        f.write(data)
    written += 1


# ── constants ─────────────────────────────────────────────────────────────

USBIP_VERSION   = 0x0111
OP_REQ_DEVLIST  = 0x8005
OP_REP_DEVLIST  = 0x0005
OP_REQ_IMPORT   = 0x8003
OP_REP_IMPORT   = 0x0003

CMD_SUBMIT      = 0x00000001
CMD_UNLINK      = 0x00000002
RET_SUBMIT      = 0x00000003
RET_UNLINK      = 0x00000004

STATUS_OK       = 0x00000000
STATUS_ERROR    = 0x00000001

SYSFS_BUS_ID    = 32    # bytes

def op_common(code: int, status: int = STATUS_OK, version: int = USBIP_VERSION) -> bytes:
    return struct.pack(">HHI", version, code, status)

def usbip_usb_device() -> bytes:
    """Minimal valid usbip_usb_device struct (312 bytes, all fields safe)."""
    path       = b"/sys/devices/pci0000:00/0000:00:01.2/usb1/1-1\x00"
    path      += b"\x00" * (256 - len(path))
    busid      = b"1-1\x00" + b"\x00" * (SYSFS_BUS_ID - 4)
    busnum     = struct.pack(">I", 1)
    devnum     = struct.pack(">I", 1)
    speed      = struct.pack(">I", 3)       # USB_SPEED_HIGH
    idvendor   = struct.pack(">H", 0x1234)
    idproduct  = struct.pack(">H", 0x5678)
    bcddevice  = struct.pack(">H", 0x0100)
    devclass   = struct.pack(">B", 0)
    subclass   = struct.pack(">B", 0)
    protocol   = struct.pack(">B", 0)
    cfg        = struct.pack(">B", 1)
    bNumConfs  = struct.pack(">B", 1)
    bNumIfaces = struct.pack(">B", 1)
    return (path + busid + busnum + devnum + speed +
            idvendor + idproduct + bcddevice +
            devclass + subclass + protocol +
            cfg + bNumConfs + bNumIfaces)

def usbip_usb_interface() -> bytes:
    """Minimal usbip_usb_interface struct."""
    return struct.pack(">BBBB", 0, 0, 0, 0)


# ══════════════════════════════════════════════════════════════════════════════
# 1. op_common valid
# ══════════════════════════════════════════════════════════════════════════════

seed("op_common_req_devlist",   op_common(OP_REQ_DEVLIST))
seed("op_common_rep_devlist",   op_common(OP_REP_DEVLIST))
seed("op_common_req_import",    op_common(OP_REQ_IMPORT))
seed("op_common_rep_import",    op_common(OP_REP_IMPORT))
seed("op_common_status_error",  op_common(OP_REP_DEVLIST, STATUS_ERROR))

# With payload after the header (exercises remainder of the stream)
seed("op_common_devlist_ndev0",
     op_common(OP_REP_DEVLIST) + struct.pack(">I", 0))
seed("op_common_devlist_ndev1",
     op_common(OP_REP_DEVLIST) + struct.pack(">I", 1) + usbip_usb_device() + usbip_usb_interface())
seed("op_common_import_with_dev",
     op_common(OP_REP_IMPORT) + struct.pack(">I", STATUS_OK) + usbip_usb_device())


# ══════════════════════════════════════════════════════════════════════════════
# 2. op_common malformed
# ══════════════════════════════════════════════════════════════════════════════

seed("op_bad_version_0000",     struct.pack(">HHHI", 0x0000, OP_REQ_DEVLIST, STATUS_OK, 0))
seed("op_bad_version_ffff",     struct.pack(">HHHI", 0xFFFF, OP_REQ_DEVLIST, STATUS_OK, 0))
seed("op_bad_version_0100",     struct.pack(">HHHI", 0x0100, OP_REQ_DEVLIST, STATUS_OK, 0))
seed("op_bad_version_0200",     struct.pack(">HHHI", 0x0200, OP_REQ_DEVLIST, STATUS_OK, 0))
seed("op_unknown_code_0001",    op_common(0x0001))
seed("op_unknown_code_0000",    op_common(0x0000))
seed("op_unknown_code_ffff",    op_common(0xFFFF))
seed("op_unknown_code_7fff",    op_common(0x7FFF))
seed("op_unknown_code_8000",    op_common(0x8000))
seed("op_status_max",           op_common(OP_REQ_DEVLIST, 0xFFFFFFFF))
seed("op_status_neg1",          struct.pack(">HHi", USBIP_VERSION, OP_REQ_DEVLIST, -1))
seed("op_all_zeros",            b"\x00" * 8)
seed("op_all_ff",               b"\xff" * 8)
seed("op_just_version",         struct.pack(">H", USBIP_VERSION))  # truncated
seed("op_7_bytes",              op_common(OP_REQ_DEVLIST)[:7])     # one byte short


# ══════════════════════════════════════════════════════════════════════════════
# 3. devlist reply bodies
# ══════════════════════════════════════════════════════════════════════════════

for ndev in [0, 1, 2, 4, 8, 16, 32, 64, 255, 256, 65535, 0xFFFFFFFF]:
    name = f"devlist_ndev_{ndev}"
    body = struct.pack(">I", ndev)
    if ndev <= 2:
        for _ in range(min(ndev, 2)):
            body += usbip_usb_device() + usbip_usb_interface()
    seed(name, body)

# Device with multiple interfaces
multi_iface = usbip_usb_device()
# Patch bNumInterfaces to 3 (last byte of the struct)
multi_iface = multi_iface[:-1] + b"\x03"
multi_body = struct.pack(">I", 1) + multi_iface
for _ in range(3):
    multi_body += usbip_usb_interface()
seed("devlist_multi_iface", multi_body)

# Truncated device struct
seed("devlist_truncated_dev", struct.pack(">I", 1) + usbip_usb_device()[:64])

# Device struct with all-ff fields
seed("devlist_dev_all_ff", struct.pack(">I", 1) + b"\xff" * len(usbip_usb_device()))


# ══════════════════════════════════════════════════════════════════════════════
# 4. import requests / replies (busid edge cases)
# ══════════════════════════════════════════════════════════════════════════════

def import_input(busid: bytes, extra: bytes = b"") -> bytes:
    """Pack busid to exactly 32 bytes (no forced NUL — let fuzzer explore)."""
    bid = busid[:SYSFS_BUS_ID]
    bid = bid + b"\x00" * (SYSFS_BUS_ID - len(bid))
    return bid + extra

seed("import_valid_busid",       import_input(b"1-1"))
seed("import_valid_busid_2_1",   import_input(b"2-1"))
seed("import_no_null",           import_input(b"A" * SYSFS_BUS_ID))
seed("import_path_traversal",    import_input(b"../../../etc/passwd"))
seed("import_path_traversal2",   import_input(b"../../proc/self/mem"))
seed("import_format_string",     import_input(b"%s%s%s%s%n%n"))
seed("import_null_bytes",        import_input(b"\x00\x00\x00\x00"))
seed("import_unicode_like",      import_input(b"\xc0\xaf\xc0\xaf\xc0\xaf"))
seed("import_long_busid",        import_input(b"1" * SYSFS_BUS_ID))
seed("import_busid_with_reply",  import_input(b"1-1") + struct.pack(">I", STATUS_OK) + usbip_usb_device())
seed("import_reply_status_err",  import_input(b"1-1") + struct.pack(">I", STATUS_ERROR))
seed("import_reply_truncated",   import_input(b"1-1") + struct.pack(">I", STATUS_OK) + usbip_usb_device()[:32])
seed("import_dev_all_ff",        import_input(b"1-1") + struct.pack(">I", STATUS_OK) + b"\xff" * len(usbip_usb_device()))
seed("import_empty_busid",       import_input(b""))
seed("import_slash_busid",       import_input(b"///" * 10))
seed("import_colon_busid",       import_input(b"0:0"))
seed("import_large_devnum",      import_input(b"255-255"))
seed("import_symbolic_link",     import_input(b"1-1 -> /etc/passwd\x00"))


# ══════════════════════════════════════════════════════════════════════════════
# 5. URB submit (CVE-2016-3955 class)
# ══════════════════════════════════════════════════════════════════════════════

def urb_header(command, seqnum=1, devid=0x10001, direction=0, ep=0,
               transfer_flags=0, transfer_buffer_length=0, start_frame=0,
               number_of_packets=0, interval=0, setup=b"\x00"*8) -> bytes:
    base = struct.pack(">IIIII", command, seqnum, devid, direction, ep)
    submit = struct.pack(">IiiiI", transfer_flags, transfer_buffer_length,
                         start_frame, number_of_packets, interval)
    return base + submit + setup[:8]

# Normal submit
seed("urb_submit_empty",        urb_header(CMD_SUBMIT, transfer_buffer_length=0))
seed("urb_submit_64b",          urb_header(CMD_SUBMIT, transfer_buffer_length=64) + b"\xaa"*64)
seed("urb_submit_512b",         urb_header(CMD_SUBMIT, transfer_buffer_length=512) + b"\xbb"*512)

# Length mismatches — CVE-2016-3955 pattern
seed("urb_ret_actual_gt_alloc", urb_header(RET_SUBMIT, transfer_buffer_length=64) + b"\xcc"*512)
seed("urb_ret_len_neg1",        urb_header(RET_SUBMIT, transfer_buffer_length=-1))
seed("urb_ret_len_intmin",      urb_header(RET_SUBMIT, transfer_buffer_length=-2147483648))
seed("urb_ret_len_max",         urb_header(RET_SUBMIT, transfer_buffer_length=65536))
seed("urb_ret_len_overflow",    urb_header(RET_SUBMIT, transfer_buffer_length=0x7FFFFFFF))

# number_of_packets edge cases (ISO transfers)
seed("urb_iso_packets_0",       urb_header(CMD_SUBMIT, number_of_packets=0))
seed("urb_iso_packets_max",     urb_header(CMD_SUBMIT, number_of_packets=0x7FFFFFFF))
seed("urb_iso_packets_neg",     urb_header(CMD_SUBMIT, number_of_packets=-1))

# Invalid endpoint / direction
seed("urb_ep_15",               urb_header(CMD_SUBMIT, ep=15))
seed("urb_ep_overflow",         urb_header(CMD_SUBMIT, ep=0xFFFFFFFF))
seed("urb_dir_in",              urb_header(CMD_SUBMIT, direction=1))
seed("urb_dir_bad",             urb_header(CMD_SUBMIT, direction=0xFFFFFFFF))

# setup packet edge cases (control transfers)
seed("urb_setup_all_ff",        urb_header(CMD_SUBMIT, setup=b"\xff"*8))
seed("urb_setup_req_clear",     urb_header(CMD_SUBMIT, setup=bytes([0x02,0x01,0x00,0x00,0x00,0x00,0x00,0x00])))
seed("urb_setup_get_descriptor",urb_header(CMD_SUBMIT, setup=bytes([0x80,0x06,0x00,0x01,0x00,0x00,0xFF,0x00])))


# ══════════════════════════════════════════════════════════════════════════════
# 6. URB unlink
# ══════════════════════════════════════════════════════════════════════════════

def urb_unlink(seqnum=1, devid=0x10001, direction=0, ep=0, unlink_seqnum=0) -> bytes:
    base    = struct.pack(">IIIII", CMD_UNLINK, seqnum, devid, direction, ep)
    payload = struct.pack(">I", unlink_seqnum) + b"\x00" * 24  # padding to match size
    return base + payload

seed("urb_unlink_seq0",         urb_unlink(unlink_seqnum=0))
seed("urb_unlink_seq1",         urb_unlink(seqnum=1, unlink_seqnum=1))
seed("urb_unlink_seq_max",      urb_unlink(unlink_seqnum=0xFFFFFFFF))
seed("urb_unlink_seq_neg",      struct.pack(">IiIII", CMD_UNLINK, -1, 0, 0, 0) + b"\x00"*24)
seed("urb_ret_unlink_ok",       urb_header(RET_UNLINK))
seed("urb_all_zeros",           b"\x00" * 48)
seed("urb_all_ff",              b"\xff" * 48)
seed("urb_truncated",           b"\x00" * 20)  # just basic header, no cmd_submit


# ══════════════════════════════════════════════════════════════════════════════
# 7. Raw boundary seeds
# ══════════════════════════════════════════════════════════════════════════════

seed("raw_empty",               b"")
seed("raw_1byte",               b"\x01")
seed("raw_7bytes",              b"\x01\x11\x80\x05\x00\x00\x00")
seed("raw_8bytes_op_common",    op_common(OP_REQ_DEVLIST))
seed("raw_max_size",            b"\x01\x11\x80\x05\x00\x00\x00\x00" + b"\xde\xad\xbe\xef" * (65536 // 4))


# ══════════════════════════════════════════════════════════════════════════════
# Done
# ══════════════════════════════════════════════════════════════════════════════

print(f"[+] Generated {written} seeds in {OUT}/")
