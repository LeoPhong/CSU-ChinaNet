# -*- coding: utf-8 -*-

import sys
import getpass
import argparse
import urllib.request
import urllib.parse
import platform
import os
import re


base = [str(x) for x in range(10)] + [ chr(x) for x in range(ord('A'),ord('A')+6)]

def dec2bin(string_num):
    num = int(string_num)
    mid = []
    while True:
        if num == 0: break
        num,rem = divmod(num, 2)
        mid.append(base[rem])
    result =  ''.join([str(x) for x in mid[::-1]])
    while len(result)<8:
        result = "0"+result
    return result
def dec2hex(string_num):
    num = int(string_num)
    mid = []
    while True:
        if num == 0: break
        num,rem = divmod(num, 16)
        mid.append(base[rem])
    return ''.join([str(x) for x in mid[::-1]])


def encrypted_pwd(pwd):
    n = 118412968095593089696003595256943158860853473161415576733447804842301571568757172298177752975532992898222036246641653221445506569501197901613520593964333398062725892226386301624234776784458736053884120766450015009923516265683635605497451865069151546715184399574358971886504430854133607074276246210978427253829
    e = 65537
    pwd = str(pwd)[::-1]
    pwd_ascii_list = map(lambda x:ord(x),pwd)
    bin_chain_pwd = ''.join(dec2bin(x) for x in pwd_ascii_list)
    return dec2hex(pow(int(bin_chain_pwd,2),e,n)).lower()


def login(user_name, password_encrpyted, brasAddress, userIntranetAddress):
    data = {'accountID' : user_name + "@zndx.inter" , 
            'password' : password_encrpyted,
            'brasAddress' : brasAddress ,
            'userIntranetAddress' : userIntranetAddress}
    # 取得cookie
    response = urllib.request.urlopen('http://61.137.86.87:8080/portalNat444/AccessServices/bas.%s?wlanuserip=%s' %(brasAddress,userIntranetAddress))
    cookie = response.headers.get('Set-Cookie')
    # 登录
    data_urlencode = urllib.parse.urlencode(data)
    req = urllib.request.Request('http://61.137.86.87:8080/portalNat444/AccessServices/login' , data_urlencode.encode() , headers = {'Referer' : 'http://61.137.86.87:8080/portalNat444/index.jsp' , 'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8', 'cache':'false', 'Cookie' : cookie})
    data = eval(urllib.request.urlopen(req).read().decode())

    if data['resultCode'] == '0':
        print('登录成功!')
        # 取得帐号信息
        req = urllib.request.Request('http://61.137.86.87:8080/portalNat444/main2.jsp' , headers = {'Cookie' : cookie})
        html = urllib.request.urlopen(req).read().decode()
        print(re.findall(r'(尊敬的.+用户，您本月截止至.+为止，宽带业务使用情况如下:)' , html)[0])
        print(re.findall(r'(您的账户本月总流量\(公网\):.+MB)' , html)[0])
        print(re.findall(r'(您的账户本月已用流量\(公网\):.+MB)' , html)[0])
        print(re.findall(r'(您的账户本月剩余流量\(公网\):.+MB)' , html)[0])
        print(re.findall(r'(您的账户本月已用流量（校园网\):.+MB)' , html)[0])
        print(re.findall(r'(您宽带账户当前剩余金额:.+元)' , html)[0])
    elif data['resultCode'] == '1':
        if data['resultDescribe'] == None or data['resultDescribe'] == '':
            print('其他原因认证拒绝')
        else:
            print(data['resultDescribe'])
    elif data['resultCode'] == '2':
        print('用户连接已存在')
    elif data['resultCode'] == '3':
        print('接入服务器繁忙, 稍后重试')
    elif data['resultCode'] == '4':
        print('未知错误')
    elif data['resultCode'] == '6':
        print('认证响应超时')
    elif data['resultCode'] == '7':
        print('捕获用户网络地址错误')
    elif data['resultCode'] == '8':
        print('服务器网络连接异常')
    elif data['resultCode'] == '9':
        print('认证服务脚本执行异常')
    elif data['resultCode'] == '10':
        print('校验码错误')
    elif data['resultCode'] == '11':
        print('您的密码相对简单，帐号存在被盗风险，请及时修改成强度高的密码')
    elif data['resultCode'] == '12':
        print('无法获取您的网络地址,请输入任意其它网站从网关处导航至本认证页面')
    elif data['resultCode'] == '13':
        print('无法获取您接入点设备地址，请输入任意其它网站从网关处导航至本认证页面')
    elif data['resultCode'] == '14':
        print('无法获取您套餐信息')
    elif data['resultCode'] == '16':
        print('请输入任意其它网站导航至本认证页面,并按正常PORTAL正常流程认证')
    elif data['resultCode'] == '17':
        print('连接已失效，请输入任意其它网站从网关处导航至本认证页面')
    else:
        print('未知错误')

def logout(brasAddress,userIntranetAddress):
    data = {'brasAddress' : brasAddress ,
            'userIntranetAddress' : userIntranetAddress}
    data_urlencode = urllib.parse.urlencode(data)
    req = urllib.request.Request('http://61.137.86.87:8080/portalNat444/AccessServices/logout?' , data_urlencode.encode() , headers = {'Referer' : 'http://61.137.86.87:8080/portalNat444/main2.jsp'})
    data = eval(urllib.request.urlopen(req).read().decode())
    if data['resultCode'] == '0':
        print('下线成功')
    elif data['resultCode'] == '1':
        print('服务器拒绝请求')
    elif data['resultCode'] == '2':
        print('下线请求执行失败')
    elif data['resultCode'] == '3':
        print('您已经下线')
    elif data['resultCode'] == '4':
        print('服务器响应超时')
    elif data['resultCode'] == '5':
        print('后台网络连接异常')
    elif data['resultCode'] == '6':
        print('服务脚本执行异常')
    elif data['resultCode'] == '7':
        print('无法获取您的网络地址')
    elif data['resultCode'] == '8':
        print('无法获取您接入点设备地址')
    elif data['resultCode'] == '9':
        print('请输入任意其它网站导航至本认证页面,并按正常PORTAL正常流程认证')
    else:
        print('未知错误')

def getIPAddress():
    if 'Linux' in platform.system() or 'Mac' in platform.system():
        ifconfig = os.popen('ifconfig')
        ifconfig = ''.join(ifconfig.readlines())
        if not ifconfig:
            print('获取IP失败!试试sudo执行?')
            sys.exit()
        ip = re.findall(r'(10\.96\.(?!127\.255)(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9]))' , ifconfig)[0][0]
        return ip
    elif 'Windows' in platform.system():
        ipconfig = os.popen('ipconfig')
        ipconfig = ''.join(ipconfig.readlines())
        if not ipconfig:
            print('获取IP失败!试试管理员权限运行?')
            sys.exit()
        ip = re.findall(r'(10\.96\.(?!127\.255)(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9]))' , ipconfig)[0][0]
        return ip
    else:
        print('未知系统,请手动输入IP地址!')




if __name__ == "__main__":
    brasAddress = '59df7586'

    parser = argparse.ArgumentParser(description = '跨平台数字中南客户端')
    parser.add_argument('-u' , '--usr' , help = '用户名')
    parser.add_argument('-p' , '--pas' , help = '密码')
    parser.add_argument('-o' , '--logout' , help = '注销' , action='store_false' , default = True , dest = 'action')
    parser.add_argument('-i' , '--ip' , help = '自定义IP')
    args = parser.parse_args()
    user_ip = args.ip if args.ip else getIPAddress()
    print('获取IP为 : %s' % user_ip)
    if args.action:
        if not args.usr or not args.pas:
            print('请输入用户名和密码!!!')
            sys.exit()
        print('正在登录...')
        user_name = args.usr
        password = '0' + encrypted_pwd(args.pas)
        login(user_name, password, brasAddress,user_ip)
    else:
        print('正在注销...')
        logout(brasAddress,user_ip)
