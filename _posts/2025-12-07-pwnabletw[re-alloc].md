---
title: "pwnable.tw - re-alloc[200pts]"
date : 2025-12-07 17:00:00
categoris: [Pwnable, Wargame , pwnabletw]
tags : [tcache , pwn , use after free, pwnabletw , realloc , double free]
---



## Pwnabletw - re-alloc[200pts]

## Overview 


file : libc-9bb401974abeef59efcdd0ae35c5fc0ce63d3e7b.so: ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d561ec515222887a1e004555981169199d841024, for GNU/Linux 3.2.0, stripped


Glibc : GNU C Library (Ubuntu GLIBC 2.29-0ubuntu2) stable release version 2.29.


=protect= 

Arch:       amd64-64-little

RELRO:      Partial RELRO

Stack:      Canary found

NX:         NX enabled

PIE:        No PIE (0x400000)

FORTIFY:    Enabled

Stripped:   No




## vulnerable

```c

void reallocate(void)

{
  ulong index;
  ulong __size;
  void *pvVar1;
  
  printf("Index:");
  index = read_long();
  if ((index < 2) && (*(long *)(heap + index * 8) != 0)) {
    printf("Size:");
    __size = read_long();
    if (__size < 0x79) {
      pvVar1 = realloc(*(void **)(heap + index * 8),__size);     // change before if (pvVar1 == (void *)0x0)
      if (pvVar1 == (void *)0x0) {
        puts("alloc error");
      }
      else {
        *(void **)(heap + index * 8) = pvVar1;
        printf("Data:");
        read_input(*(undefined8 *)(heap + index * 8),__size & 0xffffffff);
      }
    }
    else {
      puts("Too large!");
    }
  }
  else {
    puts("Invalid !");
  }
  return;
}

```


The vulnerability arises because the realloc(*ptr, size) function performs an operation equivalent to free(ptr) if size == 0 && ptr != NULL.


The rfree() function frees the address allocated in the heap (which can store a maximum of two addresses in the allocate function) and initialises heap[idx] to zero. However, due to a verification error in the reallocate function, free(ptr) is possible but the initialisation fails, resulting in an use-after-free vulnerability.



## how to use vuln


```python
allocate(idx = 0 , size = 16 , data = 'a')
reallocate(idx = 0 , size = 0 , data='')   // free(ptr)
reallocate(idx = 0 , size= = 16 , data=0xkkkkkkkk+"A") //free_tcache->fd for attack addr, "A" for tcache-key bypass
```


## leak


```c
longlong read_long(void)

{
  longlong lVar1;
  long in_FS_OFFSET;
  char local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  __read_chk(0,local_28,0x10,0x11);
  lVar1 = atoll(local_28);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return lVar1;
}
```


Overwriting atoll got address to printf() and use fsb for leak libc adrr.

and use one_gadget or system for sehll.


Since we can only modify the &heap[0,1] address, we need to leverage UAF to manipulate the tcache-fd, then resize the UAF and free it to ensure the target chunk doesn't fall into the tcache bin size.


## exploit


![exploit](/assets/img/posts/pwnabletw_re-alloc/1.png)


