# -*- coding: utf-8 -*-
#主程序

import NetworkOpt
import time
import getpass
import Encryption


if __name__ == "__main__":
    login_info = tuple()
    logout_info = tuple()
    user_id = input('请输入帐号：')
    user_passwd = '0' + Encryption.encrypted_pwd(getpass.getpass('请输入密码：'))
    connection_status,bras_address,user_ip = NetworkOpt.getConnectionInfo()
    try:
        while(True):
            connection_status,info1,info2 = NetworkOpt.getConnectionInfo()
            if connection_status == 302:
                print('正在登录...')
                login_info = NetworkOpt.login(user_id,user_passwd,bras_address,user_ip)
            elif connection_status == 200:
                print('在线中...')
            else:
                print('异常！')

            for element in login_info:
                print(element)
            time.sleep(5)
    except KeyboardInterrupt as e:
        print('正在登出...')
        logout_info = NetworkOpt.logout(bras_address,user_ip)
        for element in logout_info:
            print(element)
