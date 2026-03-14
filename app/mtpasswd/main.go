package main

import (
    "fmt"
    "io"
    "os"
    "log"
    //"crypto/aes"
    //"crypto/cipher"
    //"crypto/rand"
    "crypto/sha256"
    //"encoding/base64"
    "runtime"
    "bytes"
    //"flag"
    "golang.org/x/sys/unix"
    "github.com/joho/godotenv"
    "github.com/spf13/pflag"
    //"github.com/99designs/keyring"
    "github.com/ltkh/mtproxy/internal/cryptor"
)

func getParentExePath() (string, error) {
    ppid := os.Getppid()

    switch runtime.GOOS {
    case "linux":
        // На Linux читаем симлинк из /proc
        return os.Readlink(fmt.Sprintf("/proc/%d/exe", ppid))

    case "darwin": // macOS
        // Возвращает путь к исполняемому файлу и аргументы
        data, err := unix.SysctlRaw("kern.procargs2", ppid)
        if err != nil {
            return "", err
        }

        if len(data) < 4 {
            return "", fmt.Errorf("sysctl data format error")
        }

        // Пропускаем первые 4 байта (argc)
        data = data[4:]

        // Путь заканчивается первым нулевым байтом
        n := bytes.IndexByte(data, 0)
        if n == -1 {
            return "", fmt.Errorf("path not found in data")
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

func main() {
    fs := pflag.NewFlagSet("mtpasswd", pflag.ContinueOnError)

    path  := fs.String("password-file", "", "The file with encrypted passwords")
    _      = fs.String("key", "", "The file with secret key")
    name  := fs.String("name", "", "Password key identifier")
    pass  := fs.String("password", "", "Password value")
    proc  := fs.String("parent-proc", "", "Parent process path")
    debug := fs.Bool("debug", false, "More detailed error output")

	fs.Usage = func() {
		fmt.Println("usage: mtpasswd <command> --password-file=PASSWORD-FILE [<flags>]")
		fmt.Println("")
        fmt.Println("A command-line tool for encrypt and decrypt passwords.")
        fmt.Println("")
        fmt.Println("Flags:")
        fmt.Println("    --help     Show context-sensitive help")
        fmt.Println("    --debug    More detailed error output")
        fmt.Println("    --password-file=PATH")
        fmt.Println("               The file with encrypted passwords")
        fmt.Println("    --name=NAME")
        fmt.Println("               Password key identifier")
        fmt.Println("    --password=PASSWORD")
        fmt.Println("               Password value")
        fmt.Println("    --parent-proc=PATH")
        fmt.Println("               Parent process path")
        fmt.Println("")
        fmt.Println("Commands:")
        fmt.Println("encrypt --password-file=PASSWORD-FILE --name=NAME --password=PASSWORD [<flags>]")
        fmt.Println("    Encrypt a password")
        fmt.Println("")
        fmt.Println("decrypt --password-file=PASSWORD-FILE")
        fmt.Println("    Decrypt file with passwords and output it to stdout.")
		os.Exit(0)
	}

    err := fs.Parse(os.Args[1:])
    if err != nil {
        log.Fatalf("%v", err)
    }

    args := fs.Args()

    if len(args) < 1 {
		fs.Usage()
	}

    switch args[0] {
	case "encrypt":
		if *proc == "" {
            procPath, err := getParentExePath()
            if err != nil {
                log.Fatalf("[error] getting parent process: %v", err)
            }
            *proc = procPath
        }
        
        checksum, err := getFileChecksum(*proc)
        if err != nil {
            log.Fatalf("[error] getting checksum: %v", err)
        }

        cryptoText, err := cryptor.Encrypt(*pass, checksum)
        if err != nil {
            log.Fatalf("[error] password encryption: %v", err)
        }

        myEnv, err := godotenv.Read(*path)
        if err != nil {
            myEnv = make(map[string]string)
        }

        myEnv[*name] = cryptoText
        godotenv.Write(myEnv, *path)

	case "decrypt":
		// Получаем путь до родительского процесса
        procPath, err := getParentExePath()
        if err != nil {
            log.Fatalf("[error] getting parent process: %v", err)
        }
    
        checksum, err := getFileChecksum(procPath)
        if err != nil {
            log.Fatalf("[error] getting checksum: %v", err)
        }
    
        myEnv, err := godotenv.Read(*path)
        if err != nil {
            log.Fatalf("[error] reading the password file: %v", err)
        }

        for key, val := range myEnv {
            if *name != "" && *name != key {
                continue
            }

            passwd, err := cryptor.Decrypt(val, checksum)
            if err != nil {
                if *debug {
                    log.Printf("[debug] password decryption (%s): %v", key, err)
                }
                continue
            }
            
            fmt.Printf("%s=%s\n", key, passwd)
        }

	default:
		pflag.Usage()
	}
    
}