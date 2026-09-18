#!/usr/bin/env python3
"""ARM32 static-analysis helper for stripped firmware ELFs. AArch64 sibling: a64dis.py.

Usage (either grammar works, to match a64dis.py):
  armdis.py <elf> dis <hexvaddr> [count]   # disassemble, resolving PLT names and strings
  armdis.py <elf> str <substring>          # find a string, print its file offset and vaddr
  armdis.py <elf> xref <hexvaddr>          # find code that materialises that vaddr
  armdis.py <elf> ptr <hexvaddr>           # find pointers to that vaddr, and name the section
  armdis.py <elf> func <hexvaddr> [span]   # enclosing function: every call and string, in order
  armdis.py <elf> plt [name]               # PLT stub address, or list every stub

Needs capstone and pyelftools.
"""
import re, sys
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from elftools.elf.elffile import ELFFile


class Img:
    def __init__(self, path):
        self.f = open(path, 'rb')
        self.elf = ELFFile(self.f)
        self.secs = [(s['sh_addr'], s['sh_addr'] + s['sh_size'], s.data(), s.name)
                     for s in self.elf.iter_sections()
                     if s['sh_addr'] and s.header['sh_type'] != 'SHT_NOBITS']
        self.plt = {}
        dynsym = self.elf.get_section_by_name('.dynsym')
        rel = self.elf.get_section_by_name('.rel.plt')
        if rel is not None and dynsym is not None:
            base = self.elf.get_section_by_name('.plt')['sh_addr'] + 20
            for i, r in enumerate(rel.iter_relocations()):
                self.plt[base + i * 12] = dynsym.get_symbol(r['r_info_sym']).name

    def va_of(self, file_off):
        for s in self.elf.iter_sections():
            a, o, n = s['sh_addr'], s['sh_offset'], s['sh_size']
            if a and s.header['sh_type'] != 'SHT_NOBITS' and o <= file_off < o + n:
                return file_off - o + a
        return None

    def sec_of(self, file_off):
        for s in self.elf.iter_sections():
            a, o, n = s['sh_addr'], s['sh_offset'], s['sh_size']
            if a and s.header['sh_type'] != 'SHT_NOBITS' and o <= file_off < o + n:
                return s.name
        return '?'

    def read(self, va, n):
        for lo, hi, data, _ in self.secs:
            if lo <= va < hi:
                return data[va - lo: va - lo + n]
        return b''

    def cstr(self, va, n=180):
        b = self.read(va, n)
        if not b:
            return None
        b = b.split(b'\x00')[0]
        if len(b) >= 3 and all(0x20 <= c < 0x7f or c in b'\t\n' for c in b):
            return b.decode('ascii', 'replace')
        return None


LDR_PC = re.compile(r'^(\w+), \[pc, #(-?0x[0-9a-f]+|-?\d+)\]$')
ADD_PC = re.compile(r'^(\w+), pc, (\w+)$')


def run(path, start, count):
    img = Img(path)
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    code = img.read(start, count * 4)
    reg = {}
    for ins in md.disasm(code, start):
        note = ''
        if ins.mnemonic in ('bl', 'blx', 'b') and ins.op_str.startswith('#'):
            t = int(ins.op_str[1:], 0)
            note = f'   -> {img.plt[t]}@plt' if t in img.plt else f'   -> sub_{t:x}'
        elif ins.mnemonic.startswith('ldr') and (m := LDR_PC.match(ins.op_str)):
            raw = img.read(ins.address + 8 + int(m.group(2), 0), 4)
            if len(raw) == 4:
                reg[m.group(1)] = v = int.from_bytes(raw, 'little')
                note = f'   = 0x{v:08x}'
                if (t := img.cstr(v)):
                    note += f'  "{t}"'
        elif ins.mnemonic == 'add' and (m := ADD_PC.match(ins.op_str)):
            if (v := reg.get(m.group(2))) is not None:
                reg[m.group(1)] = a = (v + ins.address + 8) & 0xffffffff
                note = f'   = 0x{a:08x}'
                if (t := img.cstr(a)):
                    note += f'  "{t}"'
        elif ins.mnemonic == 'mov' and ',' in ins.op_str:
            d, srcs = ins.op_str.split(', ', 1)
            reg[d] = reg.get(srcs)
        print(f'{ins.address:08x}  {ins.bytes.hex():<8}  {ins.mnemonic:<8} {ins.op_str}{note}')


def func_start(img, addr, back=0x4000):
    """Scan back for an ARM prologue `push {..., lr}`."""
    for a in range(addr, addr - back, -4):
        w = int.from_bytes(img.read(a, 4), 'little')
        if (w & 0xffff0000) == 0xe92d0000 and (w & 0x4000):
            return a
    return None


def summarise(path, addr, span=0x900):
    img = Img(path)
    start = func_start(img, addr)
    if start is None:
        print('no prologue found')
        return
    print(f'function 0x{start:08x}  (contains 0x{addr:08x})')
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    reg = {}
    for ins in md.disasm(img.read(start, span), start):
        if ins.mnemonic.startswith('ldr') and (m := LDR_PC.match(ins.op_str)):
            raw = img.read(ins.address + 8 + int(m.group(2), 0), 4)
            if len(raw) == 4:
                reg[m.group(1)] = int.from_bytes(raw, 'little')
        elif ins.mnemonic == 'add' and (m := ADD_PC.match(ins.op_str)):
            if (v := reg.get(m.group(2))) is not None:
                a2 = (v + ins.address + 8) & 0xffffffff
                reg[m.group(1)] = a2
                if (t := img.cstr(a2)):
                    print(f'  0x{ins.address:08x}  STR  "{t[:88]}"')
        elif ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
            t = int(ins.op_str[1:], 0)
            print(f'  0x{ins.address:08x}  bl   {img.plt.get(t, f"sub_{t:x}")}')


def xrefs(path, target):
    """Find code that materialises `target` through the PIC pair."""
    img = Img(path)
    lo, _, data, _ = [x for x in img.secs if x[3] == '.text'][0]
    import struct
    hits = []
    for off in range(0, len(data) - 3, 4):
        w = struct.unpack_from('<I', data, off)[0]
        if (w & 0xffff0ff0) != 0xe08f0000:      # add rD, pc, rM
            continue
        rd, rm = (w >> 12) & 0xf, w & 0xf
        if rd != rm:
            continue
        pc = lo + off
        for back in range(4, 96, 4):
            if off - back < 0:
                break
            pw = struct.unpack_from('<I', data, off - back)[0]
            if (pw & 0xffff0000) in (0xe59f0000, 0xe51f0000) and ((pw >> 12) & 0xf) == rd:  # ldr rD,[pc,#+/-imm]
                delta = (pw & 0xfff) if (pw & 0xffff0000) == 0xe59f0000 else -(pw & 0xfff)
                raw = img.read((lo + off - back) + 8 + delta, 4)
                if len(raw) == 4 and (int.from_bytes(raw, 'little') + pc + 8) & 0xffffffff == target:
                    hits.append(pc)
                break
    return hits

SUBCOMMANDS = ('dis', 'str', 'xref', 'ptr', 'func', 'plt')

if __name__ == '__main__':
    if len(sys.argv) > 2 and sys.argv[2] in SUBCOMMANDS:
        sys.argv[2] = '--' + sys.argv[2]
    if len(sys.argv) > 2 and sys.argv[2] == '--dis':
        del sys.argv[2]
    path = sys.argv[1]
    if sys.argv[2] == '--func':
        summarise(path, int(sys.argv[3], 0), int(sys.argv[4], 0) if len(sys.argv) > 4 else 0x900)
        sys.exit()
    if sys.argv[2] == '--xref':
        for a in xrefs(path, int(sys.argv[3], 0)):
            print(f'0x{a:08x}')
        sys.exit()
    if sys.argv[2] == '--str':
        img = Img(path)
        needle = sys.argv[3].encode()
        d = open(path, 'rb').read()
        i = d.find(needle)
        while i >= 0:
            va = img.va_of(i)
            shown = f'0x{va:08x}' if va is not None else '(not mapped)'
            print(f'file 0x{i:x}  vaddr {shown}  {d[i:i+70].split(bytes(1))[0].decode("latin-1")!r}')
            i = d.find(needle, i + 1)
        sys.exit()
    if sys.argv[2] == '--ptr':
        import struct as _s
        img = Img(path)
        d = open(path, 'rb').read()
        needle = _s.pack('<I', int(sys.argv[3], 0))
        i = d.find(needle)
        while i >= 0:
            va = img.va_of(i)
            if va is not None:
                print(f'pointer at file 0x{i:x}  vaddr 0x{va:08x}  section {img.sec_of(i)}')
            i = d.find(needle, i + 1)
        sys.exit()
    if sys.argv[2] == '--plt':
        img = Img(path)
        want = sys.argv[3] if len(sys.argv) > 3 else None
        for a, n in sorted(img.plt.items()):
            if want is None or n == want:
                print(f'0x{a:08x}  {n}')
        sys.exit()
    run(path, int(sys.argv[2], 0), int(sys.argv[3]) if len(sys.argv) > 3 else 60)
