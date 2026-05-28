#!/bin/bash
# gen_corpus.sh - mint XDR-shaped seeds for each harness.
#
# libnfs reply bytes are XDR (Sun RPC variant) encodings of nested structs.
# Easiest path for real seeds: run rpcinfo/showmount/nfs-ls against an actual
# NFS server and capture replies with tcpdump. Without that, this script
# writes a handful of minimal-but-valid synthetic encodings so AFL has
# something better than /dev/urandom to mutate from.
#
# Seeds are intentionally tiny - the goal is to stake out the boundaries of
# each procedure's accepted-vs-rejected tag and let AFL grow them.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${0}")" && pwd)"
cd "${SCRIPT_DIR}"

mkdir -p corpus/nfs3 corpus/nfs4 corpus/mount corpus/pdu

w32() { printf '%08x' "$1" | xxd -r -p; }   # 32-bit big-endian write

# --- NFSv3 GETATTR3res (NFS3_OK + a small fattr3) ---
# First byte of fuzz input picks the decoder; seed 0x0c = GETATTR3res table idx
# (counts from the fuzz_nfs3.c order; FSINFO is index 18, READ is 5, etc.)
#
# fattr3 layout (per RFC1813): ftype(u32) mode(u32) nlink(u32) uid(u32) gid(u32)
# size(u64) used(u64) rdev(specdata3=u64) fsid(u64) fileid(u64)
# atime(nfstime3=u64) mtime ctime  = 80 bytes.
#
# GETATTR3res = status(u32=0 OK) + fattr3
{
    printf '\x0c'                   # idx=12 (GETATTR3res)
    w32 0                           # NFS3_OK
    w32 1                           # NF3REG
    w32 33188                       # mode = 0100644 octal
    w32 1                           # nlink
    w32 1000                        # uid
    w32 1000                        # gid
    printf '\x00\x00\x00\x00\x00\x00\x00\x10'  # size=16
    printf '\x00\x00\x00\x00\x00\x00\x00\x20'  # used=32
    printf '\x00\x00\x00\x00\x00\x00\x00\x00'  # rdev
    printf '\x00\x00\x00\x00\x00\x00\x00\x01'  # fsid
    printf '\x00\x00\x00\x00\x00\x00\x00\x42'  # fileid
    printf '\x00\x00\x00\x00\x00\x00\x00\x00'  # atime
    printf '\x00\x00\x00\x00\x00\x00\x00\x00'  # mtime
    printf '\x00\x00\x00\x00\x00\x00\x00\x00'  # ctime
} > corpus/nfs3/getattr3_ok.bin

# NFSv3 READDIR3res failure with post-op-attrs absent
{
    printf '\x0f'                   # idx=15 READDIR3res
    w32 5                           # NFS3ERR_NOENT
    w32 0                           # post_op_attr present=false
} > corpus/nfs3/readdir3_noent.bin

# NFSv3 FSINFO3res success with the standard 1<<20 properties
{
    printf '\x12'                   # idx=18 FSINFO3res
    w32 0                           # NFS3_OK
    w32 0                           # post_op_attr present=false
    w32 1048576                     # rtmax
    w32 1048576                     # rtpref
    w32 4096                        # rtmult
    w32 1048576                     # wtmax
    w32 1048576                     # wtpref
    w32 4096                        # wtmult
    w32 4096                        # dtpref
    printf '\x00\x00\x00\xff\xff\xff\xff\xff'   # maxfilesize
    printf '\x00\x00\x00\x00\x00\x00\x00\x00'   # time_delta seconds
    w32 0                           # time_delta nseconds
    w32 0x1b                        # properties = LINK|SYMLINK|HOMOGENOUS|CANSETTIME
} > corpus/nfs3/fsinfo3.bin

# --- NFSv4 COMPOUND4res: minimal NFS4_OK status, empty tag, zero ops ---
{
    w32 0                           # status NFS4_OK
    w32 0                           # tag length = 0
    w32 0                           # array of resop4: count = 0
} > corpus/nfs4/compound4_empty.bin

# NFSv4 COMPOUND with one PUTROOTFH op
{
    w32 0                           # status NFS4_OK
    w32 0                           # tag length = 0
    w32 1                           # resop count = 1
    w32 24                          # OP_PUTROOTFH = 24
    w32 0                           # NFS4_OK
} > corpus/nfs4/compound4_putrootfh.bin

# --- MOUNT3 mountres3: ok + small file handle + 1 auth flavour (AUTH_SYS=1) ---
{
    printf '\x00'                   # idx=0 mountres3
    w32 0                           # MNT3_OK
    w32 8                           # fhandle3.len = 8
    printf 'ABCDEFGH'               # fhandle bytes
    w32 1                           # auth_flavors.len = 1
    w32 1                           # AUTH_SYS
} > corpus/mount/mountres3_ok.bin

# MOUNT3 exports listing one export with no group restriction
{
    printf '\x01'                   # idx=1 exports
    w32 1                           # 1 entry (XDR optional: present=1)
    w32 5                           # dirpath length = 5
    printf '/data'
    printf '\x00\x00\x00'           # padding to 4-byte boundary
    w32 0                           # groups: empty (present=0)
    w32 0                           # next-entry present=0
} > corpus/mount/exports_one.bin

# --- PDU envelope: an accepted REPLY with SUCCESS body ---
{
    printf '\x00'                   # as_reply (bit 0 = 0)
    w32 0x12345678                  # xid
    w32 1                           # direction = REPLY
    w32 0                           # reply_stat = MSG_ACCEPTED
    w32 0                           # verf flavour = AUTH_NONE
    w32 0                           # verf len = 0
    w32 0                           # accept_stat = SUCCESS
} > corpus/pdu/reply_ok.bin

# A rejected REPLY (RPC_MISMATCH)
{
    printf '\x00'
    w32 0xdeadbeef
    w32 1                           # REPLY
    w32 1                           # MSG_DENIED
    w32 0                           # RPC_MISMATCH
    w32 2 ; w32 2                   # low=2 high=2 (we speak RPCv2)
} > corpus/pdu/reply_denied.bin

# A CALL frame (server side) - PORTMAP NULL
{
    printf '\x01'                   # as_call (bit 0 = 1)
    w32 0xcafebabe
    w32 0                           # direction = CALL
    w32 2                           # rpcvers
    w32 100000                      # program = PORTMAP
    w32 2                           # version
    w32 0                           # procedure NULL
    w32 0 ; w32 0                   # AUTH_NONE cred
    w32 0 ; w32 0                   # AUTH_NONE verf
} > corpus/pdu/call_pmap_null.bin

ls -la corpus/nfs3/ corpus/nfs4/ corpus/mount/ corpus/pdu/
echo "[+] Corpus generated. Drop additional real captures via:"
echo "    sudo tcpdump -i any -w nfs.pcap port 2049"
echo "    then split TCP payloads out (see README.md)."
