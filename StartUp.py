# -*- coding: utf-8 -*-
#主程序

import NetworkOpt
import time
import getpass
import Encryption


if __name__ == "__main__":
    user_id = input('请输入帐号：')
    user_passwd = '0' + Encryption.encrypted_pwd(input('请输入密码：'))
    try:
        while(True):
            connection_status,bras_address,user_ip = NetworkOpt.getConnectionInfo()
            if connection_status == 302:
                print('正在登录...')
                NetworkOpt.login(user_id,user_passwd,bras_address,user_ip)
            elif connection_status == 200:
                print('在线中...')
            else:
                print('异常！')

            time.sleep(5)
    except KeyboardInterrupt as e:
        print('正在登出...')
        logout(bras_address,user_ip)
