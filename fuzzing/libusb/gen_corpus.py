#!/usr/bin/env python3
"""
setup-corpus.sh — generate seed corpus for libusb fuzzing harnesses.

Produces ~90 binary seed files across four subdirectories:
  corpus/descriptor/   config/interface/endpoint chain seeds
  corpus/bos/          BOS descriptor and device capability seeds
  corpus/iad/          IAD two-pass parsing seeds
  corpus/usbfs/        Raw device descriptor blob seeds (linux_usbfs path)
"""

import os
import struct

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CORPUS_DIR = os.path.join(SCRIPT_DIR, "corpus")

def write_seed(subdir, name, data):
    path = os.path.join(CORPUS_DIR, subdir, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    print(f"  {subdir}/{name} ({len(data)} bytes)")

# ─── CONFIG DESCRIPTOR SEEDS ─────────────────────────────────────────────────
# Format: [bLength][bDescriptorType=0x02][wTotalLength LE16][bNumInterfaces]
#         [bConfigurationValue][iConfiguration][bmAttributes][MaxPower]
#         [... interface + endpoint descriptors ...]

def config_header(total_len, num_ifaces=1, value=1):
    return struct.pack("<BBHBBBBB",
        9, 0x02, total_len, num_ifaces, value, 0, 0x80, 50)

def iface_desc(num_eps=1, iface_num=0, alt=0):
    return struct.pack("<BBBBBBBBB",
        9, 0x04, iface_num, alt, num_eps, 0xFF, 0x00, 0x00, 0)

def endpoint_desc(addr=0x81, attrs=0x02, mps=512):
    return struct.pack("<BBBBHB",
        7, 0x05, addr, attrs, mps, 0)

print("[*] Generating descriptor/ seeds...")

# Minimal valid: 9-byte header, zero interfaces, wTotalLength=9
write_seed("descriptor", "config_minimal_valid",
    config_header(9, num_ifaces=0))

# One interface + one endpoint (total = 9+9+7 = 25 bytes)
body = config_header(25, num_ifaces=1) + iface_desc(num_eps=1) + endpoint_desc()
write_seed("descriptor", "config_one_iface_one_ep", body)

# One interface + max endpoints (32 endpoints = 9+9+32*7 = 242 bytes)
eps = b"".join(endpoint_desc(addr=0x80 | i, attrs=i % 4) for i in range(32))
total = 9 + 9 + len(eps)
body = config_header(total, num_ifaces=1) + iface_desc(num_eps=32) + eps
write_seed("descriptor", "config_max_endpoints", body)

# wTotalLength > actual data (triggers short-read path)
write_seed("descriptor", "config_wtotallength_mismatch",
    config_header(0xFFFF, num_ifaces=1) + iface_desc(1) + endpoint_desc())

# wTotalLength = 0
write_seed("descriptor", "config_wtotallength_zero",
    struct.pack("<BBHBBBBB", 9, 0x02, 0, 0, 1, 0, 0x80, 50))

# wTotalLength = 1 (below minimum)
write_seed("descriptor", "config_wtotallength_one",
    struct.pack("<BBHBBBBB", 9, 0x02, 1, 0, 1, 0, 0x80, 50))

# bNumInterfaces = 32 (USB_MAXINTERFACES limit)
ifaces = b"".join(iface_desc(0, i) for i in range(32))
total = 9 + len(ifaces)
write_seed("descriptor", "config_bNumInterfaces_32",
    config_header(total, num_ifaces=32) + ifaces)

# bNumInterfaces = 255 (over-max, exercises the > USB_MAXINTERFACES check)
write_seed("descriptor", "config_bNumInterfaces_255",
    struct.pack("<BBHBBBBB", 9, 0x02, 9, 255, 1, 0, 0x80, 50))

# bLength = 1 (below LIBUSB_DT_CONFIG_SIZE=9)
write_seed("descriptor", "config_bLength_1",
    struct.pack("<BB", 1, 0x02) + b"\x00" * 16)

# bLength = 2 (just a header)
write_seed("descriptor", "config_bLength_2",
    struct.pack("<BB", 2, 0x02) + b"\x00" * 16)

# Truncated at various offsets
for n in [0, 1, 4, 8]:
    write_seed("descriptor", f"config_truncated_{n}", b"\x09\x02" + b"\x20\x00" + b"\x00" * n)

# All 0xFF bytes
write_seed("descriptor", "config_all_ff", b"\xff" * 64)

# All 0x00 bytes (hits multiple early-return paths)
write_seed("descriptor", "config_all_zeros", b"\x00" * 32)

# Class-specific descriptor before interface (bDescriptorType=0x24)
class_desc = struct.pack("<BBB", 4, 0x24, 0x01)  # 4-byte class desc
total = 9 + len(class_desc) + 9 + 7
body = config_header(total) + class_desc + iface_desc(1) + endpoint_desc()
write_seed("descriptor", "config_class_desc_before_iface", body)

# Two interfaces, two alt settings each
alts = iface_desc(1, 0, 0) + iface_desc(1, 0, 1) + iface_desc(1, 1, 0) + iface_desc(1, 1, 1)
eps2 = endpoint_desc() * 4
total = 9 + len(alts) + len(eps2)
write_seed("descriptor", "config_two_ifaces_two_alts",
    config_header(total, num_ifaces=2) + alts + eps2)

# Audio endpoint (bLength=9 for synch fields)
audio_ep = struct.pack("<BBBBHBBB", 9, 0x05, 0x81, 0x05, 256, 1, 0, 0)
total = 9 + 9 + len(audio_ep)
write_seed("descriptor", "config_audio_endpoint",
    config_header(total) + iface_desc(1) + audio_ep)

# ─── BOS DESCRIPTOR SEEDS ────────────────────────────────────────────────────
# Format: [bLength=5][bDescriptorType=0x0F][wTotalLength LE16][bNumDeviceCaps]
#         [capability descriptors...]

def bos_header(total_len, num_caps):
    return struct.pack("<BBHB", 5, 0x0F, total_len, num_caps)

def cap_usb20_ext():
    # bLength=7, bDescriptorType=0x10, bDevCapabilityType=0x02, bmAttributes=LE32
    return struct.pack("<BBB I", 7, 0x10, 0x02, 0x00000002)

def cap_ss():
    # bLength=10, type=0x10, captype=0x03, bmAttr, wSpeedsSupported, bFuncSupport, bU1, bU2
    return struct.pack("<BBB B H B B B", 10, 0x10, 0x03, 0, 0x000E, 1, 10, 40)

def cap_container_id():
    # bLength=20, type=0x10, captype=0x04, bReserved=0, ContainerID[16]
    return struct.pack("<BBB B", 20, 0x10, 0x04, 0) + b"\xDE\xAD\xBE\xEF" * 4

def cap_ssplus(num_sublinks):
    # bLength = 12 + 4*num_sublinks
    # bmAttr lower nibble = (num_sublinks - 1) for sublinks count
    blen = 12 + 4 * num_sublinks
    bmattr = struct.pack("<I", (num_sublinks - 1) & 0xF)
    sublinks = struct.pack("<I", 0x000A4000) * num_sublinks  # lane speed attr
    return struct.pack("<BBB", blen, 0x10, 0x0A) + bmattr + struct.pack("<HBB", 0, 0, 0) + sublinks

def cap_platform(cap_data_len):
    # bLength = 3 + 1 + 16 + cap_data_len = 20 + cap_data_len
    blen = 20 + cap_data_len
    uuid = b"\x38\xB6\x08\xBF\xD0\xBB\x3D\x4B\x87\xC0\x52\x0E\x3B\x8F\xE8\xB7"  # WinUSB UUID
    return struct.pack("<BBB B", blen, 0x10, 0x05, 0) + uuid + b"\x00" * cap_data_len

print("[*] Generating bos/ seeds...")

# Minimal BOS: 5-byte header, no capabilities
write_seed("bos", "bos_minimal", bos_header(5, 0))

# One USB 2.0 extension capability
c = cap_usb20_ext()
write_seed("bos", "bos_one_usb20_ext", bos_header(5 + len(c), 1) + c)

# One SuperSpeed capability
c = cap_ss()
write_seed("bos", "bos_one_ss_cap", bos_header(5 + len(c), 1) + c)

# One Container ID capability
c = cap_container_id()
write_seed("bos", "bos_one_container_id", bos_header(5 + len(c), 1) + c)

# SSPlus with 1 sublink (minimum, triggers sublink loop)
c = cap_ssplus(1)
write_seed("bos", "bos_ssplus_1_sublink", bos_header(5 + len(c), 1) + c)

# SSPlus with 15 sublinks (high sublink count, stresses OOB path at line 1115)
c = cap_ssplus(15)
write_seed("bos", "bos_ssplus_15_sublinks", bos_header(5 + len(c), 1) + c)

# Platform with 0 cap_data bytes (bLength=20, minimum, edge case for underflow)
c = cap_platform(0)
write_seed("bos", "bos_platform_cap_data_0", bos_header(5 + len(c), 1) + c)

# Platform with 4 cap_data bytes (bLength=24, normal)
c = cap_platform(4)
write_seed("bos", "bos_platform_cap_data_4", bos_header(5 + len(c), 1) + c)

# Platform with bLength manually set to 19 (below MIN=20, triggers check)
raw = bytearray(cap_platform(0))
raw[0] = 19
write_seed("bos", "bos_platform_blen_19", bos_header(5 + 19, 1) + bytes(raw[:19]))

# Platform with bLength=18 (well below minimum)
raw[0] = 18
write_seed("bos", "bos_platform_blen_18", bos_header(5 + 18, 1) + bytes(raw[:18]))

# All 5 capability types in one BOS
caps = cap_usb20_ext() + cap_ss() + cap_container_id() + cap_ssplus(2) + cap_platform(2)
write_seed("bos", "bos_all_five_caps", bos_header(5 + len(caps), 5) + caps)

# bNumDeviceCaps=255 with truncated data (tests allocation vs actual caps)
write_seed("bos", "bos_bNumCaps_255_truncated",
    bos_header(5 + 7, 255) + cap_usb20_ext())

# wTotalLength=0xFFFF
write_seed("bos", "bos_wtotal_max",
    struct.pack("<BBHB", 5, 0x0F, 0xFFFF, 1) + cap_usb20_ext())

# All zeros
write_seed("bos", "bos_all_zeros", b"\x00" * 16)

# Truncated BOS (4 bytes — below LIBUSB_DT_BOS_SIZE=5)
write_seed("bos", "bos_truncated_4", b"\x05\x0f\x05\x00")

# Unknown capability type (bDevCapabilityType=0xFF)
c = struct.pack("<BBB I", 7, 0x10, 0xFF, 0xDEADBEEF)
write_seed("bos", "bos_unknown_cap_type", bos_header(5 + len(c), 1) + c)

# Capability with bLength=2 (below 3-byte minimum)
c = struct.pack("<BB", 2, 0x10) + b"\xFF" * 5
write_seed("bos", "bos_cap_blen_2", bos_header(5 + 2, 1) + c[:2])

# SSPlus bmAttributes sublink count = 0 (no sublink speed attrs)
c = struct.pack("<BBB I H B B", 12, 0x10, 0x0A, 0, 0, 0, 0)
write_seed("bos", "bos_ssplus_0_sublinks", bos_header(5 + len(c), 1) + c)

# ─── IAD SEEDS ───────────────────────────────────────────────────────────────
# IAD embedded within a config descriptor
# [config header 9B][IAD 8B each][interface descriptors 9B each]

def iad_desc(first_iface=0, count=2, func_class=0xEF):
    return struct.pack("<BBBBBBBB",
        8, 0x0B, first_iface, count, func_class, 0x02, 0x01, 0)

print("[*] Generating iad/ seeds...")

# No IADs (just a valid config)
body = config_header(9, 0)
write_seed("iad", "iad_none", body)

# One IAD + two interfaces
iad = iad_desc(0, 2)
ifaces = iface_desc(1, 0) + iface_desc(1, 1)
total = 9 + len(iad) + len(ifaces) + 7 * 2
body = config_header(total, 2) + iad + ifaces + endpoint_desc() + endpoint_desc(0x02)
write_seed("iad", "iad_one", body)

# Two IADs with non-overlapping interface ranges
iad1 = iad_desc(0, 2)
iad2 = iad_desc(2, 2)
ifaces = b"".join(iface_desc(0, i) for i in range(4))
total = 9 + len(iad1) + len(iad2) + len(ifaces)
write_seed("iad", "iad_two_sequential",
    config_header(total, 4) + iad1 + iad2 + ifaces)

# Two IADs with overlapping interface ranges
iad_overlap1 = iad_desc(0, 3)
iad_overlap2 = iad_desc(1, 3)
ifaces = b"".join(iface_desc(0, i) for i in range(4))
total = 9 + len(iad_overlap1) + len(iad_overlap2) + len(ifaces)
write_seed("iad", "iad_two_overlapping",
    config_header(total, 4) + iad_overlap1 + iad_overlap2 + ifaces)

# bInterfaceCount = 0
iad_zero = struct.pack("<BBBBBBBB", 8, 0x0B, 0, 0, 0xEF, 0x02, 0x01, 0)
write_seed("iad", "iad_bInterfaceCount_0",
    config_header(9 + 8, 0) + iad_zero)

# bInterfaceCount = 255
iad_max = struct.pack("<BBBBBBBB", 8, 0x0B, 0, 255, 0xEF, 0x02, 0x01, 0)
write_seed("iad", "iad_bInterfaceCount_255",
    config_header(9 + 8, 0) + iad_max)

# IAD bLength = 2 (minimum header — too short for IAD but passes header check)
iad_short = struct.pack("<BB", 2, 0x0B) + b"\xFF" * 6
write_seed("iad", "iad_bLength_2",
    config_header(9 + 2, 0) + iad_short[:2])

# IAD bLength = 7 (one below standard 8)
iad_7 = struct.pack("<BBBBBBB", 7, 0x0B, 0, 2, 0xEF, 0x02, 0x01)
write_seed("iad", "iad_bLength_7",
    config_header(9 + 7, 0) + iad_7)

# Many IADs (tests uint8_t count field — 32 IADs)
iads_32 = b"".join(iad_desc(i * 2, 2) for i in range(32))
total = 9 + len(iads_32)
write_seed("iad", "iad_32_entries",
    config_header(total, 0) + iads_32)

# IAD after interface (not at start of config data)
iface_first = iface_desc(0, 0)
iad_after = iad_desc(1, 1)
iface_second = iface_desc(0, 1)
total = 9 + len(iface_first) + len(iad_after) + len(iface_second)
write_seed("iad", "iad_after_interface",
    config_header(total, 2) + iface_first + iad_after + iface_second)

# All zeros (hits early-return paths in both passes)
write_seed("iad", "iad_all_zeros", b"\x00" * 32)

# ─── USBFS SEEDS ─────────────────────────────────────────────────────────────
# Format: [18-byte device descriptor][config descriptor(s)]
# The device descriptor's bNumConfigurations controls how many configs are expected.

def device_desc(num_configs=1, vendor=0x0483, product=0x5740):
    return struct.pack("<BBHBBBBHHHBBBB",
        18, 0x01,   # bLength, bDescriptorType
        0x0200,     # bcdUSB (USB 2.0)
        0x00,       # bDeviceClass
        0x00,       # bDeviceSubClass
        0x00,       # bDeviceProtocol
        64,         # bMaxPacketSize0
        vendor,     # idVendor
        product,    # idProduct
        0x0100,     # bcdDevice
        1, 2, 3,    # iManufacturer, iProduct, iSerialNumber
        num_configs)

print("[*] Generating usbfs/ seeds...")

# Valid 1-config device
dev = device_desc(1)
cfg = config_header(25) + iface_desc(1) + endpoint_desc()
write_seed("usbfs", "usbfs_valid_1config", dev + cfg)

# Valid 2-config device
dev = device_desc(2)
cfg1 = config_header(18, 1, value=1) + iface_desc(0)
cfg2 = config_header(18, 1, value=2) + iface_desc(0)
write_seed("usbfs", "usbfs_valid_2configs", dev + cfg1 + cfg2)

# bNumConfigurations = 0 (should return immediately)
write_seed("usbfs", "usbfs_bNumConfigs_0", device_desc(0))

# bNumConfigurations = 255 with no config data (only device desc)
write_seed("usbfs", "usbfs_bNumConfigs_255_no_data", device_desc(255))

# bNumConfigurations = 255 with one small config (loop runs until remaining exhausted)
write_seed("usbfs", "usbfs_bNumConfigs_255_one_config",
    device_desc(255) + config_header(9, 0))

# wTotalLength > remaining (truncation path)
dev = device_desc(1)
cfg = struct.pack("<BBHBBBBB", 9, 0x02, 0xFFFF, 0, 1, 0, 0x80, 50)
write_seed("usbfs", "usbfs_wtotallength_overflow", dev + cfg)

# Device descriptor only (no config data)
write_seed("usbfs", "usbfs_device_desc_only", device_desc(1))

# All zeros (18+ bytes — hits bDescriptorType != LIBUSB_DT_CONFIG check)
write_seed("usbfs", "usbfs_all_zeros", b"\x00" * 32)

# Short descriptor (17 bytes — below LIBUSB_DT_DEVICE_SIZE=18, harness skips)
write_seed("usbfs", "usbfs_short_17", b"\x12\x01" + b"\x00" * 15)

# Device descriptor + config with bLength < LIBUSB_DT_CONFIG_SIZE (bad config)
dev = device_desc(1)
bad_cfg = struct.pack("<BB", 1, 0x02) + b"\x00" * 20
write_seed("usbfs", "usbfs_config_blen_too_short", dev + bad_cfg)

# Normal device + config where bDescriptorType != 0x02 (not a config desc)
dev = device_desc(1)
not_cfg = struct.pack("<BBHBBBBB", 9, 0x04, 9, 0, 1, 0, 0x80, 50)  # type=interface
write_seed("usbfs", "usbfs_wrong_config_type", dev + not_cfg)

# wTotalLength = 0 (below minimum)
dev = device_desc(1)
zero_len = struct.pack("<BBHBBBBB", 9, 0x02, 0, 0, 1, 0, 0x80, 50)
write_seed("usbfs", "usbfs_wtotallength_0", dev + zero_len)

# ─── EXTRA / ENDPOINT COMPANION SEEDS ───────────────────────────────────────
# Seeds for fuzz_extra.c: config + endpoint with SS companion extra data.
# LIBUSB_DT_SS_ENDPOINT_COMPANION = 0x30, size = 6 bytes.

def ss_companion(blen=6, bulk_max_burst=15, bmAttr=0, wBytesPerInterval=0):
    return struct.pack("<BBBBH", blen, 0x30, bulk_max_burst, bmAttr, wBytesPerInterval)

print("[*] Generating extra/ seeds...")

# Valid endpoint + SS companion (6 bytes)
comp = ss_companion(6)
ep = endpoint_desc(0x81, 0x02, 512)  # bulk-in
total = 9 + 9 + len(ep) + len(comp)
body = config_header(total) + iface_desc(1) + ep + comp
write_seed("extra", "extra_ep_with_companion", body)

# Endpoint + companion with bLength=5 (below LIBUSB_DT_SS_ENDPOINT_COMPANION_SIZE=6)
comp_short = ss_companion(5)
total = 9 + 9 + len(ep) + 5
body = config_header(total) + iface_desc(1) + ep + comp_short[:5]
write_seed("extra", "extra_companion_blen_5", body)

# Endpoint + companion with bLength=2 (minimum header only)
total = 9 + 9 + len(ep) + 2
body = config_header(total) + iface_desc(1) + ep + b"\x02\x30"
write_seed("extra", "extra_companion_blen_2", body)

# Endpoint + companion with bLength=0 (zero — hits bLength < 2 guard)
total = 9 + 9 + len(ep) + 2
body = config_header(total) + iface_desc(1) + ep + b"\x00\x30"
write_seed("extra", "extra_companion_blen_0", body)

# Multiple endpoints each with a companion
eps_with_comp = b""
for i in range(4):
    eps_with_comp += endpoint_desc(0x80 | (i + 1), 0x02, 512) + ss_companion(6, i, 0, 0)
total = 9 + 9 + len(eps_with_comp)
body = config_header(total) + iface_desc(4) + eps_with_comp
write_seed("extra", "extra_four_eps_with_companions", body)

# Endpoint with class-specific extra data (not a companion) before the companion
class_extra = struct.pack("<BBB", 3, 0x24, 0x01)
comp = ss_companion(6)
total = 9 + 9 + len(ep) + len(class_extra) + len(comp)
body = config_header(total) + iface_desc(1) + ep + class_extra + comp
write_seed("extra", "extra_class_desc_then_companion", body)

# No endpoints (nothing to walk)
write_seed("extra", "extra_no_endpoints",
    config_header(9, 0))

# Many class-specific descriptors between interfaces (seeds config->extra_length int accumulation)
# 30 interfaces, each preceded by several 3-byte class-specific descriptors
class_blobs = struct.pack("<BBB", 3, 0x24, 0xFF) * 30
ifaces_many = b""
for i in range(30):
    ifaces_many += class_blobs + iface_desc(0, i)
total = 9 + len(ifaces_many)
body = config_header(total, 30) + ifaces_many
write_seed("extra", "extra_class_desc_accumulation", body)

# ─── ADDITIONAL DESCRIPTOR SEEDS ─────────────────────────────────────────────
# Extra seeds to stress config->extra_length signed int accumulation.

print("[*] Generating additional descriptor/ seeds...")

# Config with many interfaces each with large class-specific blobs (bLength=0xFF)
# Accumulates config->extra_length toward INT_MAX with enough mutations
big_class = struct.pack("<BB", 0xFF, 0x24) + b"\x42" * 253  # 255-byte class desc
ifaces_with_big_class = b""
for i in range(8):
    ifaces_with_big_class += big_class + iface_desc(0, i)
total = 9 + len(ifaces_with_big_class)
body = config_header(total, 8) + ifaces_with_big_class
write_seed("descriptor", "config_large_class_descs", body)

# Config where every byte after the header is a class-specific descriptor type
class_chain = b""
for _ in range(50):
    class_chain += struct.pack("<BBB", 3, 0x25, 0x00)  # 3-byte class desc, type 0x25
total = 9 + len(class_chain) + 9  # one interface at the end
body = config_header(total, 1) + class_chain + iface_desc(0)
write_seed("descriptor", "config_class_desc_chain", body)

print(f"\n[+] Corpus generated in {CORPUS_DIR}/")
for d in ["descriptor", "bos", "iad", "usbfs", "extra"]:
    path = os.path.join(CORPUS_DIR, d)
    if os.path.isdir(path):
        n = len(os.listdir(path))
        print(f"    {d}/: {n} seeds")
