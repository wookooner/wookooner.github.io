---
title: "pwnable.tw - spirited away[300pts]"
date : 2025-12-21 00:00:00 +0900
categories: [Pwnable, Wargame , pwnabletw ,]
tags : [bof, glibc 2.23 , ret overwrite, fake chunk]
---

## Pwnabletw - spirited away[300pts]

## Overview 

file : ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=9e6cd4dbfea6557127f3e9a8d90e2fe46b21f842, not stripped

libc_32.so.6 : GNU C Library (Ubuntu GLIBC 2.23-0ubuntu5) stable release version 2.23, by Roland McGrath et al.


protection

Arch:     i386
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x8048000)
Stripped:   No


## vulnerable 

### main
```c
void main(void)

{
  puts("Thanks for watching Spirited Away!");
  puts("Please leave some comments to help us improve our next movie!");
  fflush(stdout);
  survey();
  return;
}
```

### survey

```c

void survey(void)

{
  char local_ec [56];
  size_t Name_size_0x3c;
  size_t reason_size_0x50;
  undefined1 comment [80];
  undefined4 age;
  void *Name;
  undefined1 reason [80];
  
  Name_size_0x3c = 0x3c;
  reason_size_0x50 = 0x50;
  do {
    memset(comment,0,0x50);
    Name = malloc(0x3c);
    printf("\nPlease enter your name: ");
    fflush(stdout);
    read(0,Name,Name_size_0x3c);
    printf("Please enter your age: ");
    fflush(stdout);
    __isoc99_scanf("%d",&age);
    printf("Why did you came to see this movie? ");
    fflush(stdout);
    read(0,reason,reason_size_0x50);
    fflush(stdout);
    printf("Please enter your comment: ");
    fflush(stdout);
    read(0,comment,Name_size_0x3c);
    cnt = cnt + 1;
    printf("Name: %s\n",Name);
    printf("Age: %d\n",age);
    printf("Reason: %s\n",reason);  // #1
    printf("Comment: %s\n\n",comment);
    fflush(stdout);
    sprintf(local_ec,"%d comment so far. We will review them as soon as we can",cnt); // #2
    puts(local_ec);
    puts("");
    fflush(stdout);
    if (199 < cnt) {
      puts("200 comments is enough!");
      fflush(stdout);
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    while( true ) {
      printf("Would you like to leave another comment? <y/n>: ");
      fflush(stdout);
      read(0,&choice,3);
      if ((choice == 'Y') || (choice == 'y')) break;
      if ((choice == 'N') || (choice == 'n')) {
        puts("Bye!");
        fflush(stdout);
        return;
      }
      puts("Wrong choice.");
      fflush(stdout);
    }
    free(Name);
  } while( true );
}
```


#1 reason의 스택안의 데이터들이 초기화되지않아 스택안의 데이터들까지 연결되어서 출력됨. stack에 _IO_2_1_stdout_주소가 있어 이 주소를 leak.

#2 cnt의 값이 한자리일 경우 local_ec변수의 크기 56에 딱 맞지만 10이 되는 순간부터 값이 57이되어 다음 변수인 next_size를 1byte 덮게되고 100부터 next_size를 2byte 덮게됨.


#1: Uninitialized Stack Data Leak

The data in the `reason` stack variable is not initialized, causing stack contents to be concatenated with the output. This leaks the `_IO_2_1_stdout_` address present on the stack.

#2: Off-by-One via cnt Variable

When `cnt` is a single digit, it fits perfectly within the 56-byte `local_ec` variable. However, once `cnt` reaches 10, the string becomes 57 bytes long, overwriting 1 byte of the adjacent `next_size` variable. When `cnt` reaches 100, it overwrites 2 bytes of `next_size`.

## Exploitation Strategy

Once `cnt` reaches 100, we can set `next_size` to `0x6e`, allowing us to overwrite the `name` pointer. By pointing it to an arbitrary address, we can reallocate and write to that location to achieve code execution.

Since there are almost no protections enabled, we can directly overwrite the return address.

## Additional Notes

This challenge uses glibc 2.23. Initially, the exploit didn't work because the `free()` function performs chunk validation to verify that the freed memory is a legitimate heap chunk. The solution is to craft a fake chunk and overwrite with a one_gadget.

Additionally, the exploit only works if you actually send data with `p.sendline()` to the `read()` function—leaving it empty causes the exploit to fail.


![exploit](/assets/img/posts/pwnabletw_spiritedaway/1.png)