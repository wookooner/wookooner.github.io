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


취약점은 realloc(*ptr, size) 함수가 size == 0 && ptr!=NULL 이라면 free(ptr) 과 같은 동작을 수행한다.


rfree()함수에선 &heap(allocate 함수에서 최대 2개의 주소만 저장가능)에 할당받은 주소를 free하면서 heap[idx]를 0으로 초기화하지만 reallocate함수에서 검증 오류로 free(ptr)은 가능하지만 초기화는 되지 않으면서 uaf취약점이 발생한다.


## how to use vuln


```python
allocate(idx = 0 , size = 16 , data = 'a')
reallocate(idx = 0 , size = 0 , data='')   //여기서 free(ptr) 한번
reallocate(idx = 0 , size= = 16 , data=0xkkkkkkkk+"A") //free_tcache->fd 위치에 원하는 주소, "A" 는 tcache-key 검증 우회
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


atoll()함수를 printf()로 조작하면 fsb를 이용하여 라이브러리 주소 leak 가능.

후에 one_gadget이나 system으로 다른 함수를 조작하여 쉘을 얻으면 성공.


&heap[0,1] 두개의 주소밖에 할당하지못해서 uaf를 통해 tcache-fd를 조작후 uaf를 이용해 다른 size로 변경후 free하면서 목표 주소가 담긴 tcache bin size에 청크가 할당되지않도록 조작해야한다.


## exploit


![exploit](/assets/img/posts/pwnabletw_re-alloc/1.png)


