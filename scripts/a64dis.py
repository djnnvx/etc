#!/usr/bin/env python3
"""Minimal AArch64 static-analysis helper for stripped Android ELFs.
Usage:
  a64dis.py <elf> imports                 # dynsym imported funcs
  a64dis.py <elf> str <substring>         # find string + its file vaddr(s)
  a64dis.py <elf> xref <hexvaddr>         # find ADRP+ADD code refs to a vaddr
  a64dis.py <elf> dis <hexvaddr> [count]  # disassemble count insns at vaddr
Addresses are file vaddrs (p_vaddr based), not rebased. Add Ghidra's image base to match.
"""

import sys, struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile

def load(path):
    f=open(path,'rb'); e=ELFFile(f); return f,e

def seg_for(e,va):
    for s in e.iter_segments():
        if s['p_type']=='PT_LOAD' and s['p_vaddr']<=va<s['p_vaddr']+s['p_filesz']:
            return s
    return None

def read_va(e,va,n):
    s=seg_for(e,va)
    if not s: return None
    off=s['p_offset']+(va-s['p_vaddr'])
    e.stream.seek(off); return e.stream.read(n)

def imports(e):
    ds=e.get_section_by_name('.dynsym')
    out=[]
    for sym in ds.iter_symbols():
        if sym.name and sym['st_shndx']=='SHN_UNDEF': out.append(sym.name)
    print('\n'.join(sorted(set(out))))

def find_str(e,sub):
    sub=sub.encode()
    for sec in e.iter_sections():
        if sec['sh_type']=='SHT_NOBITS' or not sec['sh_flags']&0x2: continue
        data=sec.data(); base=sec['sh_addr']
        i=0
        while True:
            j=data.find(sub,i)
            if j<0: break
            k=j
            while k>0 and 0x20<=data[k-1]<0x7f: k-=1
            end=data.find(b'\x00',j)
            s=data[k:end if end>0 else j+len(sub)]
            print(f"0x{base+k:x}  {sec.name}  {s[:80]!r}")
            i=j+len(sub)

def disasm(e,va,count):
    data=read_va(e,va,count*4)
    md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=False
    for ins in md.disasm(data,va):
        print(f"0x{ins.address:x}:  {ins.mnemonic:8s} {ins.op_str}")

def xref(e,target):
    md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
    for s in e.iter_segments():
        if s['p_type']!='PT_LOAD' or not (s['p_flags']&1): continue
        va=s['p_vaddr']; data=s.data()
        adrp={}  # reg -> page base
        for ins in md.disasm(data,va):
            if ins.mnemonic=='adrp':
                try:
                    r,imm=ins.op_str.split(', ')
                    adrp[r]=int(imm,0)
                except: pass
            elif ins.mnemonic in ('add','ldr') and ',' in ins.op_str:
                parts=[p.strip() for p in ins.op_str.split(',')]
                if len(parts)>=3 and parts[1] in adrp and parts[2].startswith('#'):
                    try: val=adrp[parts[1]]+int(parts[2][1:],0)
                    except: continue
                    if val==target:
                        print(f"0x{ins.address:x}: {ins.mnemonic} {ins.op_str}  -> 0x{val:x}")

def main():
    path=sys.argv[1]; cmd=sys.argv[2]; f,e=load(path)
    if cmd=='imports': imports(e)
    elif cmd=='str': find_str(e,sys.argv[3])
    elif cmd=='dis': disasm(e,int(sys.argv[3],0), int(sys.argv[4]) if len(sys.argv)>4 else 40)
    elif cmd=='xref': xref(e,int(sys.argv[3],0))
    else: print(__doc__)

if __name__=='__main__': main()
