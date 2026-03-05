package main

import (
    "fmt"
    "io"
    "os"
    "log"
    "crypto/aes"
    "crypto/cipher"
    //"crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "runtime"
    "bytes"
    "flag"
    "golang.org/x/sys/unix"
    "github.com/joho/godotenv"
)

func getParentExePath() (string, error) {
    ppid := os.Getppid()

    switch runtime.GOOS {
    case "linux":
        // На Linux читаем симлинк из /proc
        return os.Readlink(fmt.Sprintf("/proc/%d/exe", ppid))

    case "darwin": // macOS
        // KERN_PROCARGS2 возвращает путь к исполняемому файлу и аргументы
        data, err := unix.SysctlRaw("kern.procargs2", ppid)
        if err != nil {
            return "", err
        }

        if len(data) < 4 {
            return "", fmt.Errorf("ошибка формата данных sysctl")
        }

        // Пропускаем первые 4 байта (argc)
        data = data[4:]

        // Путь заканчивается первым нулевым байтом
        n := bytes.IndexByte(data, 0)
        if n == -1 {
            return "", fmt.Errorf("путь не найден в данных")
        }

        return string(data[:n]), nil

    default:
        return "", fmt.Errorf("the operating system is not supported")
    }
}

func getFileChecksum(filePath string) ([]byte, error) {
    // Открываем файл для чтения
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    // Инициализируем хешер
    hash := sha256.New()

    // Эффективно копируем содержимое файла в хешер
    if _, err := io.Copy(hash, file); err != nil {
        return nil, err
    }

    // Вычисляем финальный хеш
    return hash.Sum(nil), nil
}

// Шифрование
func encrypt(path, name, text string, key []byte) (error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return err
    }
    
    plainText := []byte(text)
    bytes := []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}
    cfb := cipher.NewCFBEncrypter(block, bytes)
    cipherText := make([]byte, len(plainText))
    cfb.XORKeyStream(cipherText, plainText)

    myEnv, err := godotenv.Read(path)
    if err != nil {
        return err
    }

    myEnv[name] = base64.StdEncoding.EncodeToString(cipherText)

    if err := godotenv.Write(myEnv, path); err != nil {
        return err 
    }

    return nil
}

// Расшифровка
func decrypt(path, name string, key []byte) (string, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    myEnv, err := godotenv.Read(path)
    if err != nil {
        return "", err
    }

    if _, ok := myEnv[name]; !ok {
        return "", fmt.Errorf("key not found")
    }

    cipherText, err := base64.StdEncoding.DecodeString(myEnv[name])
    if err != nil {
        return "", err
    }

    bytes := []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}
    cfb := cipher.NewCFBDecrypter(block, bytes)
    plainText := make([]byte, len(cipherText))
    cfb.XORKeyStream(plainText, cipherText)

    return string(plainText), nil
}

func main() {
    path := flag.String("path", "/tmp/passwords", "path")
    name := flag.String("name", "", "name")
    pass := flag.String("password", "", "pass")
    proc := flag.String("proc", "", "proc")
    flag.Parse()

    if *pass != "" {
        if *proc == "" {
            procPath, err := getParentExePath()
            if err != nil {
                log.Fatalf("[error] %v", err)
            }
            *proc = procPath
        }
        
        checksum, err := getFileChecksum(*proc)
        if err != nil {
            log.Fatalf("[error] %v", err)
        }

        err = encrypt(*path, *name, *pass, checksum)
        if err != nil {
            log.Fatalf("[error] %v", err)
        }

        return
    } 

    // Получаем путь до родительского процесса
    procPath, err := getParentExePath()
    if err != nil {
        log.Fatalf("[error] %v", err)
    }

    checksum, err := getFileChecksum(procPath)
    if err != nil {
        log.Fatalf("[error] %v", err)
    }

    text, err := decrypt(*path, *name, checksum)
    if err != nil {
        log.Fatalf("[error] %v", err)
    }
    
    fmt.Printf("%s", text)
}