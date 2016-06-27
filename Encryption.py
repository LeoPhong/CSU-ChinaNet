# -*- coding: utf-8 -*-
#实现了一个RSA加密


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


