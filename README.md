# xmldsig

## Overview

XML ファイルに署名／XML 署名を検証する Java プログラムです。  
XML 署名時に、公開鍵情報として X.509 公開鍵証明書を埋め込みます。

### File List

- GenEnveloped.java：XML ファイルに署名
- Validate.java：XML 署名を検証
- envelope.xml：サンプル XML ファイル

## Requirement

- Java 11.0.1 or later

## Installation

`$ javac GenEnveloped.java Validate.java`

## Usage

### GenEnveloped.java

`$ java GenEnveloped [input XML path] [output XML path] [private key path (pk8)] [certificate path]`

### Validate.java

`$ java Validate [input XML path]`

## Author

[haru52](https://github.com/haru52)

## References

- [Java XML デジタル署名 API](https://docs.oracle.com/javase/jp/6/technotes/guides/security/xmldsig/XMLDigitalSignature.html)
- <https://docs.oracle.com/javase/6/docs/technotes/guides/security/xmldsig/envelope.xml>
- <https://docs.oracle.com/javase/6/docs/technotes/guides/security/xmldsig/GenEnveloped.java>
- <https://docs.oracle.com/javase/6/docs/technotes/guides/security/xmldsig/Validate.java>
- [JavaのXMLデジタル署名APIを利用してXML署名 - Qiita](https://qiita.com/KevinFQ/items/4e2484a659b618530e72)
- [JavaのXMLデジタル署名APIを利用してXML署名を検証する。 - Qiita](https://qiita.com/KevinFQ/items/24f484de8d51b1cc0b46)
