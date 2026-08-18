package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

func PKCS7Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padText...)
}

func xorBytes(data []byte, key []byte) {
	for i := 0; i < len(data); i++ {
		data[i] ^= key[i%len(key)]
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "用法: go run encrypt.go <shellcode.bin>\n")
		os.Exit(1)
	}

	shellcode, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取文件失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "原shellcode长度: %d bytes\n", len(shellcode))

	// --- 第一层：XOR 加密（随机密钥，每次不同） ---
	xorKey := make([]byte, 16)
	rand.Read(xorKey)
	xorKeyStr := hex.EncodeToString(xorKey)
	xorBytes(shellcode, xorKey)

	// --- 第二层：AES-CBC 加密 ---
	// 生成 16 字节随机数，hex 编码后得到 32 字符作为 AES-256 key
	aesRandom := make([]byte, 16)
	rand.Read(aesRandom)
	aesKeyStr := hex.EncodeToString(aesRandom) // 32 字符 hex = AES-256 key
	aesKey := []byte(aesKeyStr)

	block, _ := aes.NewCipher(aesKey)
	padded := PKCS7Padding(shellcode, aes.BlockSize)
	blockMode := cipher.NewCBCEncrypter(block, aesKey[:aes.BlockSize])
	encrypted := make([]byte, len(padded))
	blockMode.CryptBlocks(encrypted, padded)

	fmt.Fprintf(os.Stderr, "XOR密钥: %s\n", xorKeyStr)
	fmt.Fprintf(os.Stderr, "AES密钥: %s\n", aesKeyStr)
	fmt.Fprintf(os.Stderr, "加密后长度: %d bytes\n", len(encrypted))

	// stdout 第一行：加密后的 shellcode（hex 格式）
	for i, b := range encrypted {
		if i > 0 {
			fmt.Print(",")
		}
		fmt.Printf("0x%02x", b)
	}
	fmt.Println()
	// stdout 第二行：AES密钥|XOR密钥
	fmt.Printf("%s|%s\n", aesKeyStr, xorKeyStr)
}
