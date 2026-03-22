package cryptor

import (
    "fmt"
    //"io"
    //"os"
    //"log"
    //"crypto/aes"
    //"crypto/cipher"
    //"crypto/rand"
    "crypto/sha256"
    //"encoding/base64"
    "strings"
    //"runtime"
    //"bytes"
    //"flag"
    //"golang.org/x/sys/unix"
    //"github.com/joho/godotenv"
)

const (
    minChar   = 34
    maxChar   = 126
    rangeSize = maxChar - minChar + 1
    targetLen = 30   // Желаемая минимальная длина
    sep       = "|"  // Разделитель пароля и "мусора"
)

func getKeyState(key string, length int) []byte {
    result := make([]byte, length)
    for i := 0; i < length; i++ {
        hash := sha256.Sum256([]byte(fmt.Sprintf("%s%d", key, i)))
        result[i] = hash[0]
    }
    return result
}

func Encrypt(text, key string) string {
    // 1. Дополняем пароль до targetLen, если он короче
    fullText := text + sep
    if len(fullText) < targetLen {
        extra := targetLen - len(fullText)
        // Используем часть хеша ключа для заполнения "хвоста" (имитация шума)
        padding := getKeyState(key+"pad", extra)
        for _, b := range padding {
            fullText += string(byte(int(b)%rangeSize + minChar))
        }
    }

    // 2. Шифруем всю строку
    keyState := getKeyState(key, len(fullText))
    result := make([]byte, len(fullText))
    for i := 0; i < len(fullText); i++ {
        val := int(fullText[i]) - minChar
        shift := int(keyState[i])
        result[i] = byte((val+shift)%rangeSize + minChar)
    }
    return string(result)
}

func Decrypt(cipherText, key string) string {
    keyState := getKeyState(key, len(cipherText))
    decoded := make([]byte, len(cipherText))

    for i := 0; i < len(cipherText); i++ {
        val := int(cipherText[i]) - minChar
        shift := int(keyState[i])
        newVal := (val - (shift % rangeSize) + rangeSize) % rangeSize
        decoded[i] = byte(newVal + minChar)
    }

    // 3. Пытаемся найти разделитель
    resStr := string(decoded)
    if idx := strings.LastIndex(resStr, sep); idx != -1 {
        return resStr[:idx]
    }
    return resStr // Если ключ неверный, разделитель не найдется, вернем всё
}
