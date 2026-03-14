package cryptor

import (
    "fmt"
    //"io"
    //"os"
    //"log"
    "crypto/aes"
    "crypto/cipher"
    //"crypto/rand"
    //"crypto/sha256"
    "encoding/base64"
    //"runtime"
    "bytes"
    //"flag"
    //"golang.org/x/sys/unix"
    //"github.com/joho/godotenv"
)

// Добавляет байты, чтобы длина была кратна blockSize (16)
// и не меньше minLen (например, 32)
func PKCS7Padding(data []byte, blockSize int, minLen int) []byte {
    padding := blockSize - (len(data) % blockSize)
    if len(data) + padding < minLen {
        // Добиваем до минимальной длины блоками
        needed := (minLen - len(data)) / blockSize * blockSize
        padding += needed
    }
    padText := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(data, padText...)
}

// Удаляет добавленные байты при расшифровке
func PKCS7Unpadding(data []byte) ([]byte, error) {
    length := len(data)
    if length == 0 {
        return nil, fmt.Errorf("empty data")
    }
    unpadding := int(data[length-1])
    if unpadding > length {
        return nil, fmt.Errorf("invalid padding")
    }
    return data[:(length - unpadding)], nil
}

// Шифрование
func Encrypt(text string, key []byte) (string, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    // Дополняем текст минимум до 32 байт (даст 43-44 символа в base64)
    plainText := PKCS7Padding([]byte(text), aes.BlockSize, 32)
    //plainText := []byte(text)

    bytes := []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}
    cfb := cipher.NewCFBEncrypter(block, bytes)
    cipherText := make([]byte, len(plainText))
    cfb.XORKeyStream(cipherText, plainText)

    return base64.StdEncoding.EncodeToString(cipherText), nil
}

// Расшифровка
func Decrypt(text string, key []byte) (string, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    cipherText, err := base64.StdEncoding.DecodeString(text)
    if err != nil {
        return "", err
    }

    bytes := []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}
    cfb := cipher.NewCFBDecrypter(block, bytes)
    plainText := make([]byte, len(cipherText))
    cfb.XORKeyStream(plainText, cipherText)

    // Убираем дополнение, чтобы получить чистый пароль
    finalText, err := PKCS7Unpadding(plainText)
    if err != nil { 
        return "", err 
    }

    return string(finalText), nil
}