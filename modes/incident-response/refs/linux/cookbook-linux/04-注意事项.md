> 原文来源：Linux-INCIDENT-RESPONSE-COOKBOOK（GPL-3.0），作者 NOP Team，https://github.com/Just-Hack-For-Fun/Linux-INCIDENT-RESPONSE-COOKBOOK ；本节原文抓取自在线版 URL https://book.noptrace.com/linux/4.%E6%B3%A8%E6%84%8F%E4%BA%8B%E9%A1%B9/

# 注意事项


### 0x01 删除文件问题

默认情况下，`rm ./*` 是不会删除以 `.` 开头的文件和文件夹的

<!-- 截图：image-20240714204734466（在线版图片，未随附） -->

所以在删除恶意文件等场景时，需要注意删除方法
