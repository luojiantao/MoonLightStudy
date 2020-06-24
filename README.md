# MoonLightStudy
解析moonlight流程，（目标实现自己的moonlight服务端）

## 关键流程说明
### 发现网络服务器
### 信令交换
1. 发现主机后连接主机
2. 需要根据客户端提示的验证码，在服务端输入。达到信令交换的目的。
   1. 信令交互一共进行了5次握手
#### 关键代码函数(以windows环境为例)
```c++
//parma[in] appVersion 目标服务器版本 
//parma[in] pin 验证码 
//parma[out] serverCert 服务器证书
NvPairingManager::pair(QString appVersion, QString pin, QSslCertificate& serverCert);
```
1. /pair?devicename=roth&updateState=1&phrase=getservercert&salt=&clientcert=
	- salt
		16位的随机值。
		
	- clientcert
		客户端证书（自己新创建的）
		
	- response
		服务端证书字符串
		
	- 服务端行为描述
	
	  保存salt和证书，根据用户在服务端输入pin值得到aeskey。返回服务端证书
2. /pair?devicename=roth&updateState=1&clientchallenge=

	- clientchallenge
		一串16位随机值加密后的数据。
	
        ```c++
        QByteArray salt = generateRandomBytes(16);
        QByteArray saltedPin = saltPin(salt, pin);
        QByteArray aesKey = QCryptographicHash::hash(saltedPin, hashAlgo).data();
        aesKey.truncate(16);
        QByteArray randomChallenge = generateRandomBytes(16);
        QByteArray encryptedChallenge = encrypt(randomChallenge, aesKey);
        ```
   
	- reponse: challengeresponse

        ```
        QByteArray challengeResponseData = decrypt(m_Http.getXmlStringFromHex(challengeXml, "challengeresponse"), aesKey);
        //hash(randomChallenge + 服务端证书签名 + 证书)
        QByteArray serverResponse(challengeResponseData.data(), hashLength);
        ```
	     
	- 服务端行为描述
	
	     服务点解密得到 randomChallenge并保存. hash + 16位值
3. /pair?devicename=roth&updateState=1&serverchallengeresp=
	
	- serverchallengeresp
	
	  ```
	  QByteArray challengeResponse;
	  challengeResponse.append(challengeResponseData.data() + hashLength, 16);
	  const ASN1_BIT_STRING *asnSignature;
	  X509_get0_signature(&asnSignature, NULL, m_Cert);
	  challengeResponse.append(reinterpret_cast<char*>(asnSignature->data), asnSignature->length);
	  QByteArray clientSecretData = generateRandomBytes(16);
	  challengeResponse.append(clientSecretData);
	  
	  QByteArray paddedHash = QCryptographicHash::hash(challengeResponse, hashAlgo);
	  paddedHash.resize(32);
	  QByteArray encryptedChallengeResponseHash = encrypt(paddedHash, aesKey);
	  ```
	  从代码分析来看。challengeResponseData = hash + 16位值
	  上面代码意思为 challengeResponse = 16为值（服务端返回）+ 证书签名 + 16位客户端随机值
	  paddedHash = hash（challengeResponse）
	  encryptedChallengeResponseHash = AES加密（paddedHash）
	  
	- response:pairingsecret(进行数字)
	
	  ```
	  QByteArray pairingSecret = NvHTTP::getXmlStringFromHex(respXml, "pairingsecret");
	  QByteArray serverSecret = QByteArray(pairingSecret.data(), 16);
	  QByteArray serverSignature = QByteArray(&pairingSecret.data()[16], 256);
	  verifySignature(serverSecret,
	                           serverSignature,
	                           serverCertStr)
	  //进行验证
	  QByteArray expectedResponseData;
	  expectedResponseData.append(randomChallenge);
	  expectedResponseData.append(getSignatureFromPemCert(serverCertStr));
	  expectedResponseData.append(serverSecret);
	  if (QCryptographicHash::hash(expectedResponseData, hashAlgo) != serverResponse)；
	  ```
	  
	- 服务端行为描述
	
	  服务端解密得到 paddedHash(16位值(服务端生成的) + 客户端证书签名 + 16位值客户端生成)保存，等要下一个流程进行校验。  返回签名 值+数字签名。（客户端用服务端证书进行校验），值等于第2次握手返回的服务端生成的值
4. /pair?devicename=roth&updateState=1&clientpairingsecret=
	
	- clientpairingsecret（前面的流程证书已经交换成功，现在进行验证）
	  
	  - 16位随机值 + 这个值的签名
	  
	- 服务端行为描述
	
	  进行数字签名验证（用客户端证书）
5. /pair?devicename=roth&updateState=1&phrase=pairchallenge

  - reponse

  - 服务端行为描述

    确认匹配成功


## 流媒体协商
