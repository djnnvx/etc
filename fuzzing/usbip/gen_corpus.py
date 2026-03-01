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
# stub_rx.c: kmalloc(number_of_packets * sizeof(struct usbip_iso_packet_descriptor))
# iso_descriptor is 16 bytes; overflow threshold: n > 0x0fffffff
seed("urb_iso_packets_0",           urb_header(CMD_SUBMIT, number_of_packets=0))
seed("urb_iso_packets_max",         urb_header(CMD_SUBMIT, number_of_packets=0x7FFFFFFF))
seed("urb_iso_packets_neg",         urb_header(CMD_SUBMIT, number_of_packets=-1))
seed("urb_iso_wrap_u32",            urb_header(CMD_SUBMIT, number_of_packets=0x10000000))   # n*16 == 0
seed("urb_iso_wrap_u32p1",          urb_header(CMD_SUBMIT, number_of_packets=0x10000001))   # n*16 == 16
seed("urb_iso_wrap_s32",            urb_header(CMD_SUBMIT, number_of_packets=0x08000000))   # n*16 wraps s32

# transfer_buffer_length near overflow boundaries
seed("urb_tbl_uint_max",            urb_header(CMD_SUBMIT, transfer_buffer_length=0x7FFFFFFF))
seed("urb_tbl_wrap_s32",            urb_header(CMD_SUBMIT, transfer_buffer_length=-2147483648))

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
# 7. vhci-hcd server-side seeds (for fuzz_vhci_server — two-sided fuzzer)
#
# Each seed is the 28-byte ret_submit union that fuzz_vhci_server overlays onto
# USBIP_RET_SUBMIT responses.  Fields: status(4) actual_length(4) start_frame(4)
# number_of_packets(4) error_count(4) + 8 bytes padding.
# ══════════════════════════════════════════════════════════════════════════════

def ret_submit_fields(status=0, actual_length=0, start_frame=0,
                      number_of_packets=0, error_count=0) -> bytes:
    return struct.pack(">iiiii", status, actual_length, start_frame,
                       number_of_packets, error_count) + b"\x00" * 8

INT_MIN = -0x80000000
INT_MAX =  0x7fffffff

# Normal / status variants
seed("vhci_ret_ok",                    ret_submit_fields(status=0, actual_length=64))
seed("vhci_ret_status_error",          ret_submit_fields(status=-22))   # -EINVAL
seed("vhci_ret_status_epipe",          ret_submit_fields(status=-32))   # -EPIPE
seed("vhci_ret_status_enodev",         ret_submit_fields(status=-19))   # -ENODEV

# CVE-2016-3955 class: actual_length > transfer_buffer_length
# fuzz_vhci_server will send this as the server's response to any CMD_SUBMIT
seed("vhci_actual_len_overflow",       ret_submit_fields(actual_length=INT_MAX))
seed("vhci_actual_len_intmin",         ret_submit_fields(actual_length=INT_MIN))
seed("vhci_actual_len_neg1",           ret_submit_fields(actual_length=-1))
seed("vhci_actual_len_64k",           ret_submit_fields(actual_length=65536))
seed("vhci_actual_len_64k_plus1",     ret_submit_fields(actual_length=65537))
seed("vhci_actual_len_zero",          ret_submit_fields(actual_length=0))

# ISO path: number_of_packets > 0 triggers usbip_recv_iso code path
seed("vhci_iso_one_pkt",              ret_submit_fields(actual_length=16, number_of_packets=1))
seed("vhci_iso_many_pkts",            ret_submit_fields(actual_length=0,  number_of_packets=255))
seed("vhci_iso_max_pkts",             ret_submit_fields(number_of_packets=INT_MAX))
seed("vhci_iso_neg_pkts",             ret_submit_fields(number_of_packets=-1))
seed("vhci_iso_overflow",             ret_submit_fields(actual_length=INT_MAX, number_of_packets=INT_MAX))

# error_count / start_frame edge cases
seed("vhci_start_frame_intmin",       ret_submit_fields(start_frame=INT_MIN))
seed("vhci_error_count_max",          ret_submit_fields(error_count=INT_MAX))
seed("vhci_all_ff",                   b"\xff" * 28)
seed("vhci_all_zeros",                b"\x00" * 28)

# Integer overflow in kmalloc size calculation:
#   usbip_recv_iso: kmalloc(number_of_packets * sizeof(struct usbip_iso_packet_descriptor))
#   sizeof(usbip_iso_packet_descriptor) == 16 bytes on kernel side
#   Overflow threshold: n * 16 wraps u32 when n > 0x0fffffff (268435455)
#   These values cause the allocated buffer to be smaller than the data being received.
ISO_DESC_SIZE = 16
WRAP_U32 = (1 << 32) // ISO_DESC_SIZE       # 0x10000000 — exactly wraps to 0
WRAP_U32_PLUS1 = WRAP_U32 + 1               # 0x10000001 — wraps to 16 bytes allocated
WRAP_S32 = (1 << 31) // ISO_DESC_SIZE       # 0x08000000 — wraps signed to negative
# WRAP_U32=0x10000000: n*16 == 0x100000000 which wraps to 0 in u32 → kmalloc(0)
# WRAP_U32_PLUS1:      n*16 == 0x100000010 which wraps to 16 → 16-byte alloc but n*16 bytes used
seed("vhci_iso_wrap_u32",     ret_submit_fields(number_of_packets=WRAP_U32,      actual_length=64))
seed("vhci_iso_wrap_u32p1",   ret_submit_fields(number_of_packets=WRAP_U32_PLUS1, actual_length=64))
seed("vhci_iso_wrap_s32",     ret_submit_fields(number_of_packets=WRAP_S32,      actual_length=64))

# Compound: both actual_length overflow AND iso multiplication overflow
seed("vhci_double_overflow",  ret_submit_fields(actual_length=INT_MAX, number_of_packets=WRAP_U32_PLUS1))

# actual_length near UINT_MAX (unsigned interpretation — some code paths treat it unsigned)
seed("vhci_actual_uint_max",  struct.pack(">iIiii", 0, 0xFFFFFFFF, 0, 0, 0) + b"\x00" * 8)

# Borderline: actual_length == transfer_buffer_length (exactly equal — off-by-one test)
# fuzz_vhci_server always sends the response regardless of the original request's tbl,
# but these seed values help AFL++ discover the boundary condition faster.
for tbl in [0, 1, 63, 64, 127, 128, 255, 256, 4095, 4096]:
    seed(f"vhci_actual_eq_tbl_{tbl}", ret_submit_fields(actual_length=tbl))

# ── ISO overflow: targeted values matching the three unpatched kernel bugs ──────
#
# usbip_recv_iso() bug: int size = np * sizeof(*iso)  where sizeof(*iso)==16
#   np=0x08000001 → 0x08000001*16 = 0x80000010 → overflows int32 → -2147483632
#   np=0x10000001 → 0x10000001*16 = 0x100000010 → truncated uint32 = 0x10 = 16
#   np=0x7FFFFFFF/16+1 = 0x08000000 → edge case at INT_MAX/16
#
# With fuzz_vhci_server's ISO descriptor mirroring, the server sends exactly
# the overflowed number of bytes and the kernel's loop reads OOB → KASAN hit.
#
# Seeds named with explicit overflow semantics for clarity in AFL++ crash reports.
seed("vhci_iso_np_overflow_08",
     ret_submit_fields(actual_length=64, number_of_packets=0x08000001))
seed("vhci_iso_np_overflow_10",
     ret_submit_fields(actual_length=64, number_of_packets=0x10000001))
seed("vhci_iso_np_overflow_7f",
     ret_submit_fields(actual_length=64, number_of_packets=0x7FFFFFFF // 16 + 1))

# usbip_pad_iso() bug: actualoffset underflow → memmove with negative offset
# Trigger: ISO packet with actual_length > accumulated offset in the packet array.
# We send actual_length=0 per ISO packet but a large total actual_length header,
# forcing pad_iso to compute a negative offset for memmove().
# Represent as: number_of_packets=8 (valid), actual_length=INT_MAX (large total)
seed("vhci_iso_pad_underflow",
     ret_submit_fields(actual_length=INT_MAX, number_of_packets=8))

# Per-packet ISO descriptor corruption seeds → usbip_pad_iso() memmove underflow.
#
# struct usbip_iso_packet_descriptor layout (16 bytes each):
#   offset(4BE) actual_length(4BE) status(4BE) padding(4BE)
#
# When the per-packet actual_length inside the ISO descriptor array is corrupted
# to a huge value, usbip_pad_iso() computes a negative actualoffset for its
# memmove(), causing a kernel heap underwrite.  These seeds exercise that path
# directly — prior seeds only corrupted the header-level actual_length field.
for _np in [1, 2, 4, 8]:
    for _bad in [0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]:
        _iso_desc = struct.pack(">II", 0, _bad) + b"\x00" * 8  # 16 bytes
        seed(f"vhci_iso_pkt_corrupt_np{_np}_{hex(_bad)}",
             ret_submit_fields(actual_length=0, number_of_packets=_np) + _iso_desc * _np)

# Stub-side sgl_alloc() boundary seeds (for fuzz_stub_client / corpus/stub/).
#
# stub_recv_cmd_submit() calls sgl_alloc(transfer_buffer_length) with no upper
# bound check.  Values at and above SG_MAX_SINGLE_ALLOC (128 pages = 512 KB on
# x86) exercise the fallback scatter-gather allocation path.  IN transfers
# (direction=1) trigger the alloc without needing the client to send payload.
for _tbl in [0x80000, 0x1000000, 0x40000000, 0x7FFFFFFF, -1]:
    seed(f"stub_tbl_in_{hex(_tbl & 0xFFFFFFFF)}",
         urb_header(CMD_SUBMIT, direction=1, transfer_buffer_length=_tbl))

# OUT direction: stub also allocates for the receive path, so exercise that too.
for _tbl in [0x80000, 0x1000000]:
    seed(f"stub_tbl_out_{hex(_tbl)}",
         urb_header(CMD_SUBMIT, direction=0, transfer_buffer_length=_tbl))


# ══════════════════════════════════════════════════════════════════════════════
# 8. Raw boundary seeds
# ══════════════════════════════════════════════════════════════════════════════

seed("raw_empty",               b"")
seed("raw_1byte",               b"\x01")
seed("raw_7bytes",              b"\x01\x11\x80\x05\x00\x00\x00")
seed("raw_8bytes_op_common",    op_common(OP_REQ_DEVLIST))
seed("raw_max_size",            b"\x01\x11\x80\x05\x00\x00\x00\x00" + b"\xde\xad\xbe\xef" * (65536 // 4))


# ══════════════════════════════════════════════════════════════════════════════
# Per-harness subdirs
#
# run-fuzzers.sh points each AFL++ instance at a subdirectory that contains
# only the seeds meaningful for that harness.  This keeps calibration fast and
# map density high from the start.  Cross-pollination between instances still
# happens through the shared output/ directory.
# ══════════════════════════════════════════════════════════════════════════════

import shutil

SUBDIRS = {
    "protocol": lambda n, _: n.startswith("op_common") or n.startswith("raw_8bytes"),
    "devlist":  lambda n, _: "devlist" in n,
    "import":   lambda n, _: "import" in n,
    "urb":      lambda n, _: "urb" in n or "cmd_" in n or "ret_" in n,
    "vhci":     lambda n, _: n.startswith("vhci_"),
    # stub seeds: CMD_SUBMIT headers for fuzz_stub_client
    # Uses URB submit seeds as the base (same 48-byte CMD_SUBMIT format)
    "stub":     lambda n, _: "urb_submit" in n or "urb_iso" in n or "urb_tbl" in n
                             or "urb_ep" in n or "urb_dir" in n or "urb_setup" in n
                             or "urb_all" in n or "urb_ret_len" in n
                             or n.startswith("stub_tbl_"),
}

for subdir, predicate in SUBDIRS.items():
    dest = os.path.join(OUT, subdir)
    os.makedirs(dest, exist_ok=True)
    count = 0
    for fname in os.listdir(OUT):
        src = os.path.join(OUT, fname)
        if os.path.isfile(src) and predicate(fname, src):
            shutil.copy2(src, os.path.join(dest, fname))
            count += 1
    print(f"[+]   corpus/{subdir}/: {count} seeds")

print(f"[+] Generated {written} seeds in {OUT}/")
