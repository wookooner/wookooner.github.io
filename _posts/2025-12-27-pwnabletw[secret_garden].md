---
title: "pwnable.tw - secret_garden[350pts]"
date : 2025-12-27 00:00:00 +0900
categories: [Pwnable, Wargame , pwnabletw ,]
tags : [dfb , fastbin , unsortedbin , hookoverwrite]
---

## Pwnabletw - secret_garden[350pts]

## Overview 

secretgarden: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=cc989aba681411cb235a53b6c5004923d557ab6a, stripped

libc_64.so.6: ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=60131540dadc6796cab33388349e6e4e68692053, for GNU/Linux 2.6.32, stripped

GNU C Library (Ubuntu GLIBC 2.23-0ubuntu5)

### menu

    ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆
    ☆          Secret Garden          ☆
    ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆ ☆

    1 . Raise a flower
    2 . Visit the garden
    3 . Remove a flower from the garden
    4 . Clean the garden
    5 . Leave the garden

    Your choice :

raise : create flower 
visit : print flower data
remove : delete flower[idx]
clean : clean deleted flower(*flower == 0)
leave : exit

### data struct

    flower_list[100] = flower
    flower = malloc(0x28)
    flower[0](for free,clean) = for check (int)
    flower[1](name space) = malloc(name_len)
    flower[2~4](flower color,) = %23s

## vulnerable

in remove func :
```c
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (flower_count_00302024 == 0) {
    iVar1 = puts("No flower in the garden");
  }
  else {
    __printf_chk(1,"Which flower do you want to remove from the garden:");
    __isoc99_scanf("%d",&idx);
    if ((idx < 100) && ((undefined4 *)(&List_00302040)[idx] != (undefined4 *)0x0)) {
      *(undefined4 *)(&List_00302040)[idx] = 0;
      free(*(void **)((&List_00302040)[idx] + 8));
      iVar1 = puts("Successful");
    }
    else {
      puts("Invalid choice");
      iVar1 = 0;
    }
```

free check &flower_list[i] != 0, dont check for *flower_list[i] != 0

can use double free

leak(use unsorted bin) and use doublefree(fastbin) for overwrite malloc_hook(use 0x7f size for pass fastbin size check) with one_gadget

can use size 0x60~0x6F size chunk

cant use just malloc for exploit(maybe stack enviroment)
trigger double free and call malloc_printerr -> malloc()
can use third one_gadget offset.

## exploit

![exploit](/assets\img\posts\pwntw\1.png)

