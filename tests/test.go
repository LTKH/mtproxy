package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

const (
	alphabet    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	minTotalLen = 50 // Всегда не менее 50 символов
)

func getShift(key string, index int) int {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s%d", key, index)))
	// Используем 4 байта хеша для большого диапазона смещения
	return int(hash[0]) | int(hash[1])<<8 | int(hash[2])<<16 | int(hash[3])<<24
}

func Encrypt(password, key string) string {
	n := len(alphabet)
	b64 := base64.RawStdEncoding.EncodeToString([]byte(password))
	bLen := len(b64)

	// 1. Кодируем длину b64 в ДВА символа (база 62)
	// Это позволит поддерживать пароли огромной длины
	lenChar1 := alphabet[bLen/n]
	lenChar2 := alphabet[bLen%n]
	
	fullText := string(lenChar1) + string(lenChar2) + b64
	
	// 2. Добавляем "шум", если строка короче 50
	if len(fullText) < minTotalLen {
		needed := minTotalLen - len(fullText)
		for i := 0; i < needed; i++ {
			shift := getShift(key+"pad", i)
			fullText += string(alphabet[shift%n])
		}
	}

	// 3. Шифруем всё смещением
	result := make([]byte, len(fullText))
	for i := 0; i < len(fullText); i++ {
		origIdx := strings.IndexByte(alphabet, fullText[i])
		if origIdx == -1 { origIdx = 0 }
		shift := getShift(key, i)
		result[i] = alphabet[(origIdx+(shift%n)+n)%n]
	}
	return string(result)
}

func Decrypt(cipherText, key string) string {
	n := len(alphabet)
	if len(cipherText) < 2 { return cipherText }
	
	decodedChars := make([]byte, len(cipherText))
	for i := 0; i < len(cipherText); i++ {
		currIdx := strings.IndexByte(alphabet, cipherText[i])
		if currIdx == -1 { return cipherText }
		shift := getShift(key, i)
		decodedChars[i] = alphabet[(currIdx-(shift%n)+n)%n]
	}

	// 4. Восстанавливаем длину из первых двух символов
	idx1 := strings.IndexByte(alphabet, decodedChars[0])
	idx2 := strings.IndexByte(alphabet, decodedChars[1])
	b64Len := idx1*n + idx2
	
	// Защита от неверного ключа
	if b64Len <= 0 || b64Len > len(decodedChars)-2 {
		return string(decodedChars[2:])
	}

	b64Part := string(decodedChars[2 : b64Len+2])
	res, err := base64.RawStdEncoding.DecodeString(b64Part)
	
	// Если ключ неверный, проверяем результат на "читаемость"
	if err != nil {
		return string(decodedChars[2:])
	}
	for _, b := range res {
		if b < 32 || b > 126 { // Если есть бинарный мусор
			return string(decodedChars[2:])
		}
	}

	return string(res)
}

func main() {
	// Проверка на длинном пароле со спецсимволами
	longPass := "test"
	key := "my-secret-key"

	enc := Encrypt(longPass, key)
	fmt.Printf("Зашифровано (длина %d): %s\n\n", len(enc), enc)

	fmt.Println("Верный ключ:  ", Decrypt(enc, key))
	fmt.Println("Неверный ключ (читаемый шум):", Decrypt(enc, "wrong"))
}
