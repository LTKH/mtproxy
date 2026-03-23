package cryptor

import (
	"crypto/sha256"
	"encoding/hex" // Добавили для работы с HEX-строкой
	"fmt"
	"strings"
)

const (
	minChar   = 34
	maxChar   = 126
	rangeSize = maxChar - minChar + 1
	targetLen = 30
	sep       = "|"
)

// Изменили логику: теперь принимаем байты ключа, а не строку
func getKeyState(keyBytes []byte, length int) []byte {
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		// Создаем уникальную соль для каждой итерации на основе байтов ключа
		data := append(keyBytes, []byte(fmt.Sprintf("%d", i))...)
		hash := sha256.Sum256(data)
		result[i] = hash[0]
	}
	return result
}

func Encrypt(text, keyHex string) string {
	// Декодируем HEX-строку ключа в байты
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		// Если ключ не HEX, используем его как обычную строку для совместимости
		keyBytes = []byte(keyHex)
	}

	fullText := text + sep
	if len(fullText) < targetLen {
		extra := targetLen - len(fullText)
		// Передаем байты ключа
		padding := getKeyState(append(keyBytes, []byte("pad")...), extra)
		for _, b := range padding {
			fullText += string(byte(int(b)%rangeSize + minChar))
		}
	}

	keyState := getKeyState(keyBytes, len(fullText))
	result := make([]byte, len(fullText))
	for i := 0; i < len(fullText); i++ {
		val := int(fullText[i]) - minChar
		shift := int(keyState[i])
		result[i] = byte((val+shift)%rangeSize + minChar)
	}
	return string(result)
}

func Decrypt(cipherText, keyHex string) string {
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		keyBytes = []byte(keyHex)
	}

	keyState := getKeyState(keyBytes, len(cipherText))
	decoded := make([]byte, len(cipherText))

	for i := 0; i < len(cipherText); i++ {
		val := int(cipherText[i]) - minChar
		shift := int(keyState[i])
		newVal := (val - (shift % rangeSize) + rangeSize) % rangeSize
		decoded[i] = byte(newVal + minChar)
	}

	resStr := string(decoded)
	if idx := strings.LastIndex(resStr, sep); idx != -1 {
		return resStr[:idx]
	}
	return resStr
}
