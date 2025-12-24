---
title: "pwnable.tw - babystack[250pts]"
date : 2025-12-24 00:00:00 +0900
categories: [Pwnable, Wargame , pwnabletw ,]
tags : [bof, strcpy]
---

## Pwnabletw - babystack[250pts]

## Overview 

babystack: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, stripped

libc_64.so.6: ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=60131540dadc6796cab33388349e6e4e68692053, for GNU/Linux 2.6.32, stripped

protection

Arch:     amd64
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
FORTIFY:    Enabled

## vulnerable

### Login func

```c
void Login(char *get_random)

{
  int iVar1;
  size_t __n;
  char local_88 [128];
  
  printf("Your passowrd :");
  get_input_00100ca0(local_88,127);
  __n = strlen(local_88);
  iVar1 = strncmp(local_88,get_random,__n);
  if (iVar1 == 0) {
    Check_random_00302014 = 1;
    puts("Login Success !");
  }
  else {
    puts("Failed !");
  }
  return;
}
```

get_input_00100ca0

```c
void get_input_00100ca0(void *param_1,uint param_2)

{
  int iVar1;
  ssize_t sVar2;
  
  sVar2 = read(0,param_1,(ulong)param_2);
  iVar1 = (int)sVar2;
  if (iVar1 < 1) {
    puts("read error");
                    /* WARNING: Subroutine does not return */
    _exit(1);
  }
  if (*(char *)((long)param_1 + (long)iVar1 + -1) == '\n') {
    *(undefined1 *)((long)param_1 + (long)iVar1 + -1) = 0;
  }
  return;
}
```

The main function accepts three input options: 1, 2, and 3. When you enter 1, it takes you to the login menu.




choice 3
```c
void choice_3_00100e76(char *param_1_size64)

{
  char local_88 [128];
  
  printf("Copy :");
  get_input_00100ca0(local_88,0x3f);
  strcpy(param_1_size64,local_88);
  puts("It is magic copy !");
  return;
}
```

Since we can control the n parameter in strncmp, setting it to 0 allows us to bypass the login check without actually comparing against the random value generated in main. 

Entering 2 calls exit, while entering 3 checks whether you're logged in before allowing you to perform the "magic copy" operation.

At first glance, there doesn't appear to be any vulnerability, but the use of strcpy (which copies until it encounters a null byte) is immediately suspicious. 

More importantly, the choice_3 and Login functions share the same stack address space for their input data. 

This means we can carefully craft our input in the Login function, then leverage strcpy in choice_3 (where the data from Login persists on the stack) to manipulate both the key value and the return address, ultimately achieving shell execution.

Since the canary check verifies whether the random value has been modified, we need to preserve the key value obtained through brute force when manipulating the return address.

    pay="A"*0x40+key(0x10)+dummy(0x10)+rbp+one_gadget

For leaking addresses, we'll need to use brute force as well. Since we can control the length parameter of strncmp through our input, we can locate the _IO_2_1_stdout_ value on the stack, set the comparison length to reach that point, and brute force the server's libc address byte by byte.

    $cat flag
    FLAG{Its_juS7##########}
    $

