# coding: utf-8
import math, time, base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from hashlib import md5
from requests import Session


def cmd5(content: str) -> str:
    return md5(content.encode(encoding='utf-8')).hexdigest()


def setPublicKey(keys: str) -> str:
    head = '-----BEGIN PUBLIC KEY-----'
    end = '-----END PUBLIC KEY-----'
    l: int = 64
    n: int = math.ceil(len(keys) / l)
    k: str = '\n'.join([keys[i * l:(i + 1) * l] for i in range(n)])
    k = f'{head}\n{k}\n{end}'
    return k


def setPrivateKey(keys: str) -> str:
    head = '-----BEGIN PUBLIC KEY-----'
    end = '-----END PUBLIC KEY-----'
    l: int = 64
    n: int = math.ceil(len(keys) / l)
    k: str = '\n'.join([keys[i * l:(i + 1) * l] for i in range(n)])
    k = f'{head}\n{k}\n{end}'
    return k


def rsaEncrypt(key: str, content: str) -> str:
    """
    ras 加密[公钥加密]
    :param key: 无BEGIN PUBLIC KEY头END PUBLIC KEY尾的pem格式key
    :param content:待加密内容
    :return:
    """
    pub_key = setPublicKey(key)
    pub = RSA.import_key(pub_key)
    cipher = PKCS1_v1_5.new(pub)
    encrypt_bytes = cipher.encrypt(content.encode(encoding='utf-8'))
    result = base64.b64encode(encrypt_bytes)
    result = str(result, encoding='utf-8')
    return result


def rsaDecrypt(key: str, content: str) -> str:
    private_key = setPrivateKey(key)
    cipher = PKCS1_v1_5.new(RSA.import_key(private_key))
    back_text = cipher.decrypt(base64.b64decode(content), 0)
    return back_text.decode('utf-8')


def login(user: str, pwd: str):
    url = 'https://passport.ppdai.com/api/passport/versionService/webConfig?appid=1000002866&sourceType=1'
    userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36"
    headers = {
        "Cache-Control": "no-cache",
        "Content-Type": "application/json;charset=UTF-8",
        "Host": "passport.ppdai.com",
        "Origin": "https://account.ppdai.com",
        "Pragma": "no-cache",
        "Referer": "https://account.ppdai.com/",
        "User-Agent": userAgent
    }
    try:
        with Session() as http:
            http.headers = headers
            res = http.get(url=url)
            data = res.json()
            serial_no = data.get('serial_no')
            public_key = data['data'].get('public_key')
            password = rsaEncrypt(public_key, cmd5(pwd))
            userName = rsaEncrypt(public_key, user)
            params = {
                "extraInfo": {
                    "CookieValue": "",
                    "FlashValue": "",
                    "FpCode": "",
                    "_ppdaiWaterMark": "",
                    "FromUrl": "",
                    "UniqueId": "",
                    "UserAgent": userAgent,
                    "sourceId": 'null',
                    "serial_no": serial_no,
                    "currentUrl": "https://account.ppdai.com/pc/login",
                    "ppdSearchEngineUrl": 'null',
                    "ImgValidateCode": "",
                    "ImgValidateToken": ""
                },
                "sourceId": 'null',
                "loginSource": "PcWebLogin",
                "password": password,
                "userName": userName
            }
            url = 'https://passport.ppdai.com/api/passport/pwdLoginService/securityWeb?appid=1000002866'
            res = http.post(url=url, json=params)
        return res.json()
    except Exception as E:
        return {
            'error': str(E.args)
        }


if __name__ == '__main__':
    result = login('phone@paipaidai.com', '123456')
    print(result)
