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
NvPairingManager::pair(QString appVersion, QString pin, QSslCertificate& serverCert){
    int serverMajorVersion = NvHTTP::parseQuad(appVersion).at(0);
    qInfo() << "Pairing with server generation:" << serverMajorVersion;
	//根据版本确定hash算法
    QCryptographicHash::Algorithm hashAlgo;
    int hashLength;
    if (serverMajorVersion >= 7)
    {
        // Gen 7+ uses SHA-256 hashing
        hashAlgo = QCryptographicHash::Sha256;
        hashLength = 32;
    }
    else
    {
        // Prior to Gen 7 uses SHA-1 hashing
        hashAlgo = QCryptographicHash::Sha1;
        hashLength = 20;
    }
	//生成16位随机数字和验证码pin做拼接位salt
    QByteArray salt = generateRandomBytes(16);
    QByteArray saltedPin = saltPin(salt, pin);
	//salt作一次hash得到一段摘要信息，并保留摘要的前16位
    QByteArray aesKey = QCryptographicHash::hash(saltedPin, hashAlgo).data();
    aesKey.truncate(16);
	//获取服务端证书
    //需要提交的表单包含 salt, 数字签名
    QString getCert = m_Http.openConnectionToString(m_Http.m_BaseUrlHttp,
                                                    "pair",
                                                    "devicename=roth&updateState=1&phrase=getservercert&salt=" +
                                                    salt.toHex() + "&clientcert=" + IdentityManager::get()->getCertificate().toHex(),
                                                    0);
    //解析返回的http状态码（200成功）
    NvHTTP::verifyResponseStatus(getCert);
    //解析返回xml结果中的paired 字段
    if (NvHTTP::getXmlString(getCert, "paired") != "1")
    {
        qCritical() << "Failed pairing at stage #1";
        return PairState::FAILED;
    }
	//== vHTTP::getXmlString(getCert, "plaincert").toLatin1()
    QByteArray serverCertStr = NvHTTP::getXmlStringFromHex(getCert, "plaincert");
    if (serverCertStr == nullptr)
    {
        //代表不匹配，服务端被占用了
        qCritical() << "Server likely already pairing";
        m_Http.openConnectionToString(m_Http.m_BaseUrlHttp, "unpair", nullptr, REQUEST_TIMEOUT_MS);
        return PairState::ALREADY_IN_PROGRESS;
    }

    serverCert = QSslCertificate(serverCertStr);
    if (serverCert.isNull()) {
        Q_ASSERT(!serverCert.isNull());

        qCritical() << "Failed to parse plaincert";
        m_Http.openConnectionToString(m_Http.m_BaseUrlHttp, "unpair", nullptr, REQUEST_TIMEOUT_MS);
        return PairState::FAILED;
    }
	//设置服务端证书
    // Pin this cert for TLS
    m_Http.setServerCert(serverCert);
	//二次发送匹配信息，发送一串数字签名
    QByteArray randomChallenge = generateRandomBytes(16);
    QByteArray encryptedChallenge = encrypt(randomChallenge, aesKey);
    QString challengeXml = m_Http.openConnectionToString(m_Http.m_BaseUrlHttp,
                                                         "pair",
                                                         "devicename=roth&updateState=1&clientchallenge=" +
                                                         encryptedChallenge.toHex(),
                                                         REQUEST_TIMEOUT_MS);
    NvHTTP::verifyResponseStatus(challengeXml);
    if (NvHTTP::getXmlString(challengeXml, "paired") != "1")
    {
        qCritical() << "Failed pairing at stage #2";
        m_Http.openConnectionToString(m_Http.m_BaseUrlHttp, "unpair", nullptr, REQUEST_TIMEOUT_MS);
        return PairState::FAILED;
    }

    QByteArray challengeResponseData = decrypt(m_Http.getXmlStringFromHex(challengeXml, "challengeresponse"), aesKey);
    QByteArray clientSecretData = generateRandomBytes(16);
    QByteArray challengeResponse;
    QByteArray serverResponse(challengeResponseData.data(), hashLength);

#if (OPENSSL_VERSION_NUMBER < 0x10002000L)
    //ASN1_BIT_STRING *asnSignature = m_Cert->signature;
#elif (OPENSSL_VERSION_NUMBER < 0x10100000L)
    //ASN1_BIT_STRING *asnSignature;
    //X509_get0_signature(&asnSignature, NULL, m_Cert);
#else
    const ASN1_BIT_STRING *asnSignature;
    X509_get0_signature(&asnSignature, NULL, m_Cert);
#endif

    challengeResponse.append(challengeResponseData.data() + hashLength, 16);
    challengeResponse.append(reinterpret_cast<char*>(asnSignature->data), asnSignature->length);
    challengeResponse.append(clientSecretData);

    QByteArray paddedHash = QCryptographicHash::hash(challengeResponse, hashAlgo);
    paddedHash.resize(32);
    QByteArray encryptedChallengeResponseHash = encrypt(paddedHash, aesKey);
    QString respXml = m_Http.openConnectionToString(m_Http.m_BaseUrlHttp,
                                                    "pair",
                                                    "devicename=roth&updateState=1&serverchallengeresp=" +
                                                    encryptedChallengeResponseHash.toHex(),
                                                    REQUEST_TIMEOUT_MS);
    NvHTTP::verifyResponseStatus(respXml);
    if (NvHTTP::getXmlString(respXml, "paired") != "1")
    {
        qCritical() << "Failed pairing at stage #3";
        m_Http.openConnectionToString(m_Http.m_BaseUrlHttp, "unpair", nullptr, REQUEST_TIMEOUT_MS);
        return PairState::FAILED;
    }

    QByteArray pairingSecret = NvHTTP::getXmlStringFromHex(respXml, "pairingsecret");
    QByteArray serverSecret = QByteArray(pairingSecret.data(), 16);
    QByteArray serverSignature = QByteArray(&pairingSecret.data()[16], 256);

    if (!verifySignature(serverSecret,
                         serverSignature,
                         serverCertStr))
    {
        qCritical() << "MITM detected";
        m_Http.openConnectionToString(m_Http.m_BaseUrlHttp, "unpair", nullptr, REQUEST_TIMEOUT_MS);
        return PairState::FAILED;
    }

    QByteArray expectedResponseData;
    expectedResponseData.append(randomChallenge);
    expectedResponseData.append(getSignatureFromPemCert(serverCertStr));
    expectedResponseData.append(serverSecret);
    if (QCryptographicHash::hash(expectedResponseData, hashAlgo) != serverResponse)
    {
        qCritical() << "Incorrect PIN";
        m_Http.openConnectionToString(m_Http.m_BaseUrlHttp, "unpair", nullptr, REQUEST_TIMEOUT_MS);
        return PairState::PIN_WRONG;
    }

    QByteArray clientPairingSecret;
    clientPairingSecret.append(clientSecretData);
    clientPairingSecret.append(signMessage(clientSecretData));

    QString secretRespXml = m_Http.openConnectionToString(m_Http.m_BaseUrlHttp,
                                                          "pair",
                                                          "devicename=roth&updateState=1&clientpairingsecret=" +
                                                          clientPairingSecret.toHex(),
                                                          REQUEST_TIMEOUT_MS);
    NvHTTP::verifyResponseStatus(secretRespXml);
    if (NvHTTP::getXmlString(secretRespXml, "paired") != "1")
    {
        qCritical() << "Failed pairing at stage #4";
        m_Http.openConnectionToString(m_Http.m_BaseUrlHttp, "unpair", nullptr, REQUEST_TIMEOUT_MS);
        return PairState::FAILED;
    }

    QString pairChallengeXml = m_Http.openConnectionToString(m_Http.m_BaseUrlHttps,
                                                             "pair",
                                                             "devicename=roth&updateState=1&phrase=pairchallenge",
                                                             REQUEST_TIMEOUT_MS);
    NvHTTP::verifyResponseStatus(pairChallengeXml);
    if (NvHTTP::getXmlString(pairChallengeXml, "paired") != "1")
    {
        qCritical() << "Failed pairing at stage #5";
        m_Http.openConnectionToString(m_Http.m_BaseUrlHttp, "unpair", nullptr, REQUEST_TIMEOUT_MS);
        return PairState::FAILED;
    }

    return PairState::PAIRED;
}
```
1. /pair?devicename=roth&updateState=1&phrase=getservercert&salt=&clientcert=
  - salt
    	16位的随机值。
  
  - clientcert

    客户端证书（自己新创建的）
 - response
 	服务端证书字符串
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
	  ```
	
4. /pair?devicename=roth&updateState=1&clientpairingsecret=
	
	- clientpairingsecret（前面的流程证书已经交换成功，现在进行验证）
	  - 16位随机值 + 这个值的签名
5. /pair?devicename=roth&updateState=1&phrase=pairchallenge
	
	- reponse