# xmldsig

## Overview
XMLファイルに署名／XML署名を検証するJavaプログラム


## Description
XML署名時に、公開鍵情報としてX.509公開鍵証明書を埋め込みます。


### File List
- GenEnveloped.java：XMLファイルに署名
- Validate.java：XML署名を検証
- envelope.xml：サンプルXMLファイル


## Requirements
- OpenSSL 1.0.2p or later
- Java 11.0.1 or later (OpenJDK)


## Installation
`$ javac GenEnveloped.java Validate.java`


## Usages
### GenEnveloped.java
`$ java GenEnveloped [input XML path] [output XML path] [private key path (pk8)] [certificate path]`


### Validate.java
`$ javac Validate.java`


## License
ご自由にお使いください。


## Author
[haru52](https://github.com/haru52)


## References
- [Java XML デジタル署名 API](https://docs.oracle.com/javase/jp/6/technotes/guides/security/xmldsig/XMLDigitalSignature.html)
- [JavaのXMLデジタル署名APIを利用してXML署名 - Qiita](https://qiita.com/KevinFQ/items/4e2484a659b618530e72)
- [JavaのXMLデジタル署名APIを利用してXML署名を検証する。 - Qiita](https://qiita.com/KevinFQ/items/24f484de8d51b1cc0b46)
