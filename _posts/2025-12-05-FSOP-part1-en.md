---
title: "FSOP(File Stream Oriented Programming) - (1)[en]"
date : 2025-12-05 00:00:00 +0900
categories: [Pwnable, Heap, FSOP, ]
tags : [fsop , pwn , glibc , file-structure , stream , IO , vtable]
---


## FSOP
===Part 1=== FIle Structure Analyze

[Part 2 : How to use for attack]


### Overview

The FILE structure describes a file stream within the standard I/O library of Linux systems, containing information necessary for performing input/output operations on files or other I/O resources.

The FILE structure is created and allocated on the heap when a programme executes a function such as fopen(). It is common practice to define a pointer to the FILE structure in order to receive this return value.

```
*Hierarchy of Standard Input and Output
Application Layer
    ↓
Standard I/O Library (stdio) - Buffered I/O
    ↓      (fopen, fread, fwrite, fclose)
System Call Layer - Unbuffered I/O  
    ↓ (open, read, write, close)
Kernel
    ↓
Hardware
```


### struct _IO_FILE

Let us examine the structure of the fundamental _IO_FILE structure.

Let us look at what is defined in libio/bits/types/struct_FILE.h.

```c
struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */

  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
  int _flags2:24;
  /* Fallback buffer to use when malloc fails to allocate one.  */
  char _short_backupbuf[1];
  __off_t _old_offset; /* This used to be _offset but it's too small.  */

  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```

It is said to be for the C++ streambuf protocol, and one can see that it relates to the buffers of stdout and stdin.

There are three buffering modes.

- Line buffered - flushes upon encountering \n, default mode for stdin and stdout.
  
- Fully buffered - flushes when the buffer fills, default mode for file I/O.
  
- Unbuffered - performs immediate system calls, default mode for stderr.


FSOP attacks fundamentally exploit the _IO_FILE structure, the vtable (discussed later), and _IO_strfile (introduced in glibc 2.24 and later to bypass vtable validation) to carry out attacks.

FILE structures are linked via the _chain field to form a linked list (defined by the global variable _IO_list_all), enabling traversal of all FILE structures through this value.

Upon startup, a process automatically creates three FILE streams: stdin (_IO_2_1_stdin_), stdout (_IO_2_1_stdout_), and stderr (_IO_2_1_stderr_) as global variables pre-allocated in the data section of libc.so. File streams created via fopen, etc., are allocated dynamically in heap memory.


### vtable


Examining the structure of _IO_2_1_stdout_ reveals it comprises an _IO_FILE structure and an _IO_FILE_plus structure containing an IO_jump_t *vtable.



```c
/* We always allocate an extra word following an _IO_FILE.
   This contains a pointer to the function jump table used.
   This is for compatibility with C++ streambuf; the word can
   be used to smash to a pointer to a virtual function table. */

struct _IO_FILE_plus
{
  FILE file;
  const struct _IO_jump_t *vtable;
};

_IO_jumpt_t  
    ↓
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
};

```

Let us examine the _IO_file_jumps defined as _IO_jump_t, which are used in the *vtable of the actual _IO_2_1_stdout_, using GDB.

pwndbg> p (struct _IO_jump_t)_IO_file_jumps

```
{
  __dummy = 0,
  __dummy2 = 0,
  __finish = 0x7ffff7c91a40 <_IO_new_file_finish>,
  __overflow = 0x7ffff7c92df0 <_IO_new_file_overflow>,
  __underflow = 0x7ffff7c92640 <_IO_new_file_underflow>,
  __uflow = 0x7ffff7c955a0 <__GI__IO_default_uflow>,
  __pbackfail = 0x7ffff7c96de0 <__GI__IO_default_pbackfail>,
  __xsputn = 0x7ffff7c939e0 <_IO_new_file_xsputn>,
  __xsgetn = 0x7ffff7c93d20 <__GI__IO_file_xsgetn>,
  __seekoff = 0x7ffff7c93160 <_IO_new_file_seekoff>,
  __seekpos = 0x7ffff7c95cc0 <_IO_default_seekpos>,
  __setbuf = 0x7ffff7c92400 <_IO_new_file_setbuf>,
  __sync = 0x7ffff7c93010 <_IO_new_file_sync>,
  __doallocate = 0x7ffff7c85120 <__GI__IO_file_doallocate>,
  __read = 0x7ffff7c938b0 <__GI__IO_file_read>,
  __write = 0x7ffff7c93940 <_IO_new_file_write>,
  __seek = 0x7ffff7c938d0 <__GI__IO_file_seek>,
  __close = 0x7ffff7c93930 <__GI__IO_file_close>,
  __stat = 0x7ffff7c938e0 <__GI__IO_file_stat>,
  __showmanyc = 0x7ffff7c96f90 <_IO_default_showmanyc>,
  __imbue = 0x7ffff7c96fa0 <_IO_default_imbue>
}
```

This structure can be observed.

### Function Call Flow of the FILE Stream

Let us examine how stdout, stdin, stdrr, etc., operate within the programme.

Looking at the puts function, it is defined as follows:

```c
// glibc/libio/ioputs.c

#include "libioP.h"
#include <string.h>
#include <limits.h>
int
_IO_puts (const char *str)
{
  int result = EOF;
  size_t len = strlen (str);
  _IO_acquire_lock (stdout);
  if ((_IO_vtable_offset (stdout) != 0
       || _IO_fwide (stdout, -1) == -1)
      && _IO_sputn (stdout, str, len) == len
      && _IO_putc_unlocked ('\n', stdout) != EOF)
    result = MIN (INT_MAX, len + 1);
  _IO_release_lock (stdout);
  return result;
}
weak_alias (_IO_puts, puts)
libc_hidden_def (_IO_puts)

```

During various verifications, _IO_sputn is called, but _IO_sputn is redefined as _IO_XSPUTN().

#define _IO_sputn(__fp, __s, __n) _IO_XSPUTN (__fp, __s, __n)

```c
/* The 'xsputn' hook writes upto N characters from buffer DATA.
   Returns EOF or the number of character actually written.
   It matches the streambuf::xsputn virtual function. */
typedef size_t (*_IO_xsputn_t) (FILE *FP, const void *DATA,
				    size_t N);
#define _IO_XSPUTN(FP, DATA, N) JUMP2 (__xsputn, FP, DATA, N)

```

Furthermore, this _IO_XSPUTN() function varies slightly depending on the defined FILE type, with the vtable's call functions differing accordingly. It calls the function pointer located at the __xsputn position by referencing the vtable.

The vtables for various other streams can be examined in glibc/libio/libioP.h.html.

They can also be checked via __io_vtables in gdb.

In the structure examined above using GDB, the __IO_2_1_stdout_ stream uses the _IO_file_jumps_ vtable structure. Here, the function corresponding to the __xsputn position is _IO_new_file_xsputn.

```c

_IO_new_file_xsputn (FILE *f, const void *data, size_t n)
{
  const char *s = (const char *) data;
  size_t to_do = n;
  int must_flush = 0;
  size_t count = 0;
  if (n <= 0)
    return 0;
  /* This is an optimized implementation.
     If the amount to be written straddles a block boundary
     (or the filebuf is unbuffered), use sys_write directly. */
  /* First figure out how much space is available in the buffer. */
  if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING)) //[A]
  {
    count = f->_IO_buf_end - f->_IO_write_ptr;
    if (count >= n)
	  {
	    const char *p;
	    for (p = s + n; p > s; )
	    {
	      if (*--p == '\n')
		    {
		      count = p - s + 1;
		      must_flush = 1;
		      break;
		    }
	    }
	  }
  }
  else if (f->_IO_write_end > f->_IO_write_ptr)
    count = f->_IO_write_end - f->_IO_write_ptr; /* Space available. */
  /* Then fill the buffer. */
  if (count > 0)
  {
    if (count > to_do)
	    count = to_do;
    f->_IO_write_ptr = __mempcpy (f->_IO_write_ptr, s, count);
    s += count;
    to_do -= count;
  }
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
  return n - to_do;
}
libc_hidden_ver (_IO_new_file_xsputn, _IO_file_xsputn)

```

Examining xsputn reveals that it undergoes multiple verifications, calling functions such as _IO_OVERFLOW(_IO_new_file_overflow) and new_do_write, validating various conditions, and ultimately invoking a system call.

This seems to be getting rather lengthy... I shall examine it in greater detail later whilst solving the problem.
Fundamentally, functions like write and read are invoked by referencing the vtable within the file structure, ultimately reaching the system call.

To summarise simply:

puts => _IO_puts() => _IO_sputn => _IO_XSPUTN (*vtable -> __xsputn(_IO_new_file_xsputn())) => _IO_OVERFLOW => *vtable -> overflow(_IO_new_file_overflow) => _IO_new_do_write -> new_do_write -> SYSWRITE

The calls proceed in this manner.


### The Core of the FSOP Attack

FSOP attacks this stream's method of referencing the vtable to call functions. By meticulously manipulating _IO_FILE and the vtable to replace vtable->__xsputn and __overflow with system, it becomes possible to call the system function instead of _IO_new_file_xsputn().

The FSOP attack evolved significantly in glibc 2.24+. From this version onwards, new vtable validation logic was introduced to ensure the call originates from a trusted address, necessitating advanced manipulation techniques (such as utilizing the _IO_strfile structure) to bypass these checks.

In Part 2, we will put this knowledge into practice, dissecting an actual challenge to detail the process from address leakage to exploit development through precise manipulation of the FILE structure and its vtable.

