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


## 流媒体协商和媒体数据传输

#### 关键代码函数(以windows环境为例)
```C++
void Session::exec(int displayOriginX, int displayOriginY);
```
- 初始化
initialize()
	1. SDL相关初始化
		这个部分先不作分析，主要分析媒体相关。
- m_StreamConfig，LiStartConnection
- LiStartConnection
		1. 配置参数检查
		2. STAGE_NAME_RESOLUTION 验证对端服务器是否可以连接
		3. STAGE_RTSP_HANDSHAKE RTSP握手
		4. STAGE_CONTROL_STREAM_INIT 控制流初始化（TODO）
		5. STAGE_VIDEO_STREAM_INIT 视频流初始化
		6. STAGE_AUDIO_STREAM_INIT 音频流初始化
		7. STAGE_INPUT_STREAM_INIT 输入流初始化
		8. STAGE_CONTROL_STREAM_START 开始监听控制流
		9. STAGE_VIDEO_STREAM_START 开始监听视频流
		10. STAGE_AUDIO_STREAM_START 开始监听音频流
		11. STAGE_INPUT_STREAM_START 开始监听输入流
		12. 触发鼠标摇晃事件数据发送给服务端
- m_InputHandler 处理设备输入事件（鼠标，键盘）
	1. LiSendKeyboardEvent
	2. LiSendMouseMoveEvent

#### 简单的服务端传输一帧视频数据，客户端的流程
1. 初始化流程
	1. initializeVideoStream
	2. renderContext = nullptr
	3. VideoCallbacks.setup
2. 收到数据到解码显示的流程
	1. ReceiveThreadProc
		1. recvUdpSocket 接受到是一个 packet包数据
		2. queuePacket 接受到的数据放入队列中，返回执行状态RTPF_RET_QUEUED
		
	2. DecoderThreadProc
		1. getNextQueuedDecodeUnit 从队列中获取解码单元数据
		
		2. VideoCallbacks.submitDecodeUnit（Session::drSubmitDecodeUnit） 解码
		
		   1. ```
		      FFmpegVideoDecoder(testOnly);
		      ```
		
		3. completeQueuedDecodeUnit 解码完成释放内存资源
		
	3. 解码后的帧交给SDL进行渲染展示（音视频同步）
	
	   1. TODO
#### 发送控制流程（键盘，鼠标，手柄）

#### RTSP握手流程

