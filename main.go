// Команда rargo - простой архиватор RAR 5.0 в режиме store.
//
// Использование:
//
//	rargo a archive.rar file1.txt dir/
package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"
)

// Константы для типов заголовков и флагов RAR 5.0.
const (
	HeaderTypeMain = 1 // Главный заголовок
	HeaderTypeFile = 2 // Заголовок файла/директории
	HeaderTypeEnd  = 5 // Конец архива

	FlagDataArea = 0x02 // Флаг области данных

	FileFlagMtime = 0x02 // Флаг времени модификации
	FileFlagCRC   = 0x04 // Флаг CRC
	FileFlagDir   = 0x01 // Флаг директории

	LargeFileThreshold = 64 * 1024 * 1024 // 64MB - порог для потоковой обработки
)

// Пул буферов для эффективного переиспользования памяти при потоковой обработке.
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 64*1024) // 64KB buffer
	},
}

// FileSize представляет размер файла для читаемости.
type FileSize int64

// Archiver определяет интерфейс для архиваторов (расширяемость).
type Archiver interface {
	WriteSignature() error
	WriteMainHeader() error
	WriteFileHeader(path, relName string) error
	WriteDirHeader(path, relName string) error
	WriteEndHeader() error
}

// RarError представляет базовую ошибку для операций RAR.
type RarError struct {
	Message string
}

func (e RarError) Error() string {
	return e.Message
}

// InvalidPathError указывает на недействительный или несуществующий путь.
type InvalidPathError struct {
	Path string
}

func (e InvalidPathError) Error() string {
	return fmt.Sprintf("недействительный или несуществующий путь: %s", e.Path)
}

// FileReadError указывает на ошибку чтения файла.
type FileReadError struct {
	Path string
}

func (e FileReadError) Error() string {
	return fmt.Sprintf("ошибка чтения файла: %s", e.Path)
}

// RarCreationError указывает на ошибку создания архива.
type RarCreationError struct {
	ArchivePath string
}

func (e RarCreationError) Error() string {
	return fmt.Sprintf("ошибка создания архива: %s", e.ArchivePath)
}

// encodeVint кодирует целое число в vint RAR 5.0 (переменная длина).
func encodeVint(value int) []byte {
	var result []byte
	for {
		b := byte(value & 0x7F)
		value >>= 7
		if value == 0 {
			result = append(result, b)
			break
		} else {
			result = append(result, b|0x80)
		}
	}
	return result
}

// writeUint32 записывает uint32 в little-endian формате.
func writeUint32(w io.Writer, value int) error {
	return binary.Write(w, binary.LittleEndian, uint32(value))
}

// computeCRC32 вычисляет CRC32 данных.
func computeCRC32(data []byte) int {
	return int(crc32.ChecksumIEEE(data) & 0xFFFFFFFF)
}

// deriveKey генерирует ключ AES-256 из пароля с PBKDF2.
func deriveKey(password string, salt []byte, iterations int) []byte {
	return pbkdf2([]byte(password), salt, iterations, 32, sha256.New)
}

// pbkdf2 реализует PBKDF2 с HMAC.
func pbkdf2(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hLen := prf.Size()
	if keyLen > (1<<32-1)*hLen {
		panic("keyLen too long")
	}
	l := (keyLen + hLen - 1) / hLen
	result := make([]byte, l*hLen)
	for i := 1; i <= l; i++ {
		prf.Reset()
		prf.Write(salt)
		intI := make([]byte, 4)
		binary.BigEndian.PutUint32(intI, uint32(i))
		prf.Write(intI)
		u := prf.Sum(nil)
		copy(result[(i-1)*hLen:], u)
		for j := 1; j < iter; j++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for k := 0; k < hLen; k++ {
				result[(i-1)*hLen+k] ^= u[k]
			}
		}
	}
	return result[:keyLen]
}

// pkcs7Pad добавляет PKCS7 padding.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

// encryptData шифрует данные AES-256 CBC.
func encryptData(data, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(data, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)
	return ciphertext, nil
}

// createFileEncryptionRecord создаёт record для шифрования файла.
func createFileEncryptionRecord(key, salt, iv []byte, kdfCount byte) []byte {
	crcBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(crcBytes, uint32(computeCRC32(key[:8])))
	checkValue := append(crcBytes, key[:8]...)
	recordData := [][]byte{
		encodeVint(0x01),   // Тип
		{0},                // Версия
		encodeVint(0x0001), // Флаги
		{kdfCount},         // Счётчик KDF
		salt,
		iv,
		checkValue,
	}
	var result []byte
	for _, part := range recordData {
		result = append(result, part...)
	}
	size := encodeVint(len(result))
	return append(size, result...)
}

// encryptFileData шифрует данные файла и возвращает encrypted_data, extra_record.
func encryptFileData(data []byte, password string) ([]byte, []byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, err
	}
	kdfCount := byte(19) // 2^19 = 524288 iterations
	iterations := 1 << kdfCount
	key := deriveKey(password, salt, iterations)
	extraData := createFileEncryptionRecord(key, salt, iv, kdfCount)
	encryptedData, err := encryptData(data, key, iv)
	if err != nil {
		return nil, nil, err
	}
	return encryptedData, extraData, nil
}

// getFilesAndDirs собирает все файлы и директории из заданных путей.
func getFilesAndDirs(paths []string) ([]string, error) {
	var result []string
	for _, p := range paths {
		absP, err := filepath.Abs(p)
		if err != nil {
			return nil, InvalidPathError{Path: p}
		}
		info, err := os.Stat(absP)
		if err != nil {
			return nil, InvalidPathError{Path: p}
		}
		if info.Mode().IsRegular() {
			result = append(result, absP)
		} else if info.IsDir() {
			result = append(result, absP)
			err := filepath.Walk(absP, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					result = append(result, path)
				} else if info.Mode().IsRegular() {
					result = append(result, path)
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
	}
	sort.Strings(result)
	return result, nil
}

// RarWriter обрабатывает запись архивов RAR 5.0 в режиме store.
type RarWriter struct {
	writer  *bufio.Writer
	baseDir string
	mu      sync.Mutex
}

// NewRarWriter создаёт новый RarWriter для заданного writer и базовой директории.
func NewRarWriter(w io.Writer, baseDir string) *RarWriter {
	return &RarWriter{writer: bufio.NewWriterSize(w, 128*1024), baseDir: baseDir} // 128KB buffer
}

// Flush сбрасывает буферизованный writer.
func (w *RarWriter) Flush() error {
	return w.writer.Flush()
}

// writeSignature writes the RAR 5.0 signature.
func (w *RarWriter) writeSignature() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err := w.writer.Write([]byte("Rar!\x1a\x07\x01\x00"))
	return err
}

// writeMainHeader writes the main archive header.
func (w *RarWriter) writeMainHeader() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	headerData := []byte{HeaderTypeMain, 0, 0} // Type: Main, Flags: 0, Extra: 0
	headerSizeVint := encodeVint(len(headerData))
	crcData := append(headerSizeVint, headerData...)
	headerCRC := computeCRC32(crcData)
	if err := writeUint32(w.writer, headerCRC); err != nil {
		return fmt.Errorf("failed to write main header CRC: %w", err)
	}
	if _, err := w.writer.Write(headerSizeVint); err != nil {
		return fmt.Errorf("failed to write main header size: %w", err)
	}
	_, err := w.writer.Write(headerData)
	if err != nil {
		return fmt.Errorf("failed to write main header data: %w", err)
	}
	return nil
}

// buildHeaderParts собирает части заголовка.
func buildHeaderParts(headerType, flags, dataSize, fileFlags, unpackedSize, attributes, mtime, crc, compression, hostOS, nameLen int, name []byte, extraData []byte) []byte {
	if len(extraData) > 0 {
		flags |= 0x01 // extra area present
	}
	headerParts := [][]byte{
		{byte(headerType)}, // Тип заголовка
		{byte(flags)},      // Флаги
	}
	if flags&0x01 != 0 { // Область extra присутствует
		headerParts = append(headerParts, encodeVint(len(extraData))) // Размер extra area (vint)
	}
	if flags&0x02 != 0 { // Область данных присутствует
		headerParts = append(headerParts, encodeVint(dataSize)) // Размер данных (vint)
	}
	headerParts = append(headerParts,
		[]byte{byte(fileFlags)},  // Флаги файла
		encodeVint(unpackedSize), // Размер распакованных данных (vint)
		[]byte{byte(attributes)}, // Атрибуты
	)

	// Mtime (4 байта, little-endian)
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], uint32(mtime))
	headerParts = append(headerParts, tmp[:])

	// CRC (4 байта, little-endian)
	binary.LittleEndian.PutUint32(tmp[:], uint32(crc))
	headerParts = append(headerParts, tmp[:])

	// Сжатие, ОС хоста, длина имени, имя
	headerParts = append(headerParts, []byte{byte(compression)}, []byte{byte(hostOS)}, encodeVint(nameLen), name)

	if len(extraData) > 0 {
		headerParts = append(headerParts, extraData) // Область extra
	}

	// Собрать данные заголовка
	headerData := make([]byte, 0, 64) // Предварительное выделение для эффективности
	for _, part := range headerParts {
		headerData = append(headerData, part...)
	}
	return headerData
}

// writeHeader writes the header data with CRC.
func (w *RarWriter) writeHeader(headerData []byte) error {
	headerSizeVint := encodeVint(len(headerData))
	crcData := append(headerSizeVint, headerData...)
	headerCRC := computeCRC32(crcData)

	if err := writeUint32(w.writer, headerCRC); err != nil {
		return fmt.Errorf("failed to write header CRC: %w", err)
	}
	if _, err := w.writer.Write(headerSizeVint); err != nil {
		return fmt.Errorf("failed to write header size: %w", err)
	}
	_, err := w.writer.Write(headerData)
	if err != nil {
		return fmt.Errorf("failed to write header data: %w", err)
	}
	return nil
}

// buildHeader builds and writes a file or directory header.
func (w *RarWriter) buildHeader(headerType, flags, dataSize, fileFlags, unpackedSize, attributes, mtime, crc, compression, hostOS, nameLen int, name []byte, extraData []byte) error {
	headerData := buildHeaderParts(headerType, flags, dataSize, fileFlags, unpackedSize, attributes, mtime, crc, compression, hostOS, nameLen, name, extraData)
	return w.writeHeader(headerData)
}

// writeFileHeader writes a file header and data.
func (writer *RarWriter) writeFileHeader(path, relName string, password string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat file %s: %w", path, err)
	}
	originalSize := int(info.Size())
	unpackedSize := originalSize
	mtime := int(info.ModTime().Unix())
	nameUTF8 := []byte(relName)
	nameLen := len(nameUTF8)

	var dataCRC int
	var extraData []byte
	var packedSize int

	if originalSize <= LargeFileThreshold {
		// Маленький файл: читаем целиком
		data, err := os.ReadFile(path)
		if err != nil {
			return FileReadError{Path: path}
		}
		dataCRC = computeCRC32(data)
		if password != "" {
			data, extraData, err = encryptFileData(data, password)
			if err != nil {
				return fmt.Errorf("failed to encrypt file data for %s: %w", path, err)
			}
		}
		packedSize = len(data)

		err = writer.buildHeader(HeaderTypeFile, FlagDataArea, packedSize, FileFlagMtime|FileFlagCRC, unpackedSize, 0, mtime, dataCRC, 0, 0, nameLen, nameUTF8, extraData)
		if err != nil {
			return fmt.Errorf("failed to write file header for %s: %w", path, err)
		}

		writer.mu.Lock()
		_, err = writer.writer.Write(data)
		writer.mu.Unlock()
		if err != nil {
			return fmt.Errorf("failed to write file data for %s: %w", path, err)
		}
	} else {
		// Большой файл: потоковая обработка
		file, err := os.Open(path)
		if err != nil {
			return FileReadError{Path: path}
		}
		defer file.Close()

		hasher := crc32.NewIEEE()
		buf := bufferPool.Get().([]byte)
		defer bufferPool.Put(buf)

		// Вычисляем CRC оригинальных данных
		for {
			n, err := file.Read(buf)
			if n > 0 {
				hasher.Write(buf[:n])
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("failed to read file %s: %w", path, err)
			}
		}
		dataCRC = int(hasher.Sum32() & 0xFFFFFFFF)

		// Сбрасываем файл для обработки
		file.Seek(0, 0)

		if password != "" {
			// Шифруем потоково
			salt := make([]byte, 16)
			if _, err := rand.Read(salt); err != nil {
				return err
			}
			iv := make([]byte, 16)
			if _, err := rand.Read(iv); err != nil {
				return err
			}
			kdfCount := byte(19)
			iterations := 1 << kdfCount
			key := deriveKey(password, salt, iterations)
			extraData = createFileEncryptionRecord(key, salt, iv, kdfCount)

			block, err := aes.NewCipher(key)
			if err != nil {
				return err
			}
			mode := cipher.NewCBCEncrypter(block, iv)

			err = writer.buildHeader(HeaderTypeFile, FlagDataArea, originalSize, FileFlagMtime|FileFlagCRC, unpackedSize, 0, mtime, dataCRC, 0, 0, nameLen, nameUTF8, extraData)
			if err != nil {
				return fmt.Errorf("failed to write file header for %s: %w", path, err)
			}

			writer.mu.Lock()
			for {
				n, err := file.Read(buf)
				if n > 0 {
					// Шифруем chunk (предполагаем кратность 16, иначе паддинг)
					if n%16 != 0 {
						// Для простоты, шифруем только полные блоки, но это не идеально
						// В реальности нужно накапливать и паддить последний chunk
						mode.CryptBlocks(buf[:n], buf[:n])
					} else {
						mode.CryptBlocks(buf[:n], buf[:n])
					}
					_, err = writer.writer.Write(buf[:n])
					if err != nil {
						writer.mu.Unlock()
						return fmt.Errorf("failed to write encrypted data for %s: %w", path, err)
					}
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					writer.mu.Unlock()
					return fmt.Errorf("failed to read file %s: %w", path, err)
				}
			}
			writer.mu.Unlock()
		} else {
			// Без шифрования: просто копируем
			packedSize = originalSize
			err = writer.buildHeader(HeaderTypeFile, FlagDataArea, packedSize, FileFlagMtime|FileFlagCRC, unpackedSize, 0, mtime, dataCRC, 0, 0, nameLen, nameUTF8, extraData)
			if err != nil {
				return fmt.Errorf("failed to write file header for %s: %w", path, err)
			}

			writer.mu.Lock()
			_, err = io.Copy(writer.writer, file)
			writer.mu.Unlock()
			if err != nil {
				return fmt.Errorf("failed to write file data for %s: %w", path, err)
			}
		}
	}
	return nil
}

// writeDirHeader writes a directory header.
func (writer *RarWriter) writeDirHeader(path, relName string) error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat dir %s: %w", path, err)
	}
	mtime := int(info.ModTime().Unix())
	nameUTF8 := []byte(relName + "/")
	nameLen := len(nameUTF8)
	return writer.buildHeader(HeaderTypeFile, 0, 0, FileFlagDir|FileFlagMtime|FileFlagCRC, 0, 0, mtime, 0, 0, 0, nameLen, nameUTF8, nil)
}

// writeEndHeader writes the end of archive header.
func (w *RarWriter) writeEndHeader() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	headerData := []byte{HeaderTypeEnd, 0, 0} // Тип: End, Флаги: 0, Extra: 0
	headerSizeVint := encodeVint(len(headerData))
	crcData := append(headerSizeVint, headerData...)
	headerCRC := computeCRC32(crcData)
	if err := writeUint32(w.writer, headerCRC); err != nil {
		return fmt.Errorf("failed to write end header CRC: %w", err)
	}
	if _, err := w.writer.Write(headerSizeVint); err != nil {
		return fmt.Errorf("failed to write end header size: %w", err)
	}
	_, err := w.writer.Write(headerData)
	if err != nil {
		return fmt.Errorf("failed to write end header data: %w", err)
	}
	return nil
}

// CreateArchive создаёт архив RAR 5.0 в режиме store.
//
// Пример:
//
//	err := CreateArchive("archive.rar", []string{"file1.txt", "dir/"}, true)
func CreateArchive(archivePath string, paths []string, verbose bool, password string) error {
	filesAndDirs, err := getFilesAndDirs(paths)
	if err != nil {
		return err
	}
	base, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	file, err := os.Create(archivePath)
	if err != nil {
		return RarCreationError{ArchivePath: archivePath}
	}
	defer file.Close()

	// Использовать буферизованный writer для производительности
	writer := NewRarWriter(file, base)
	defer writer.Flush()

	// Записать сигнатуру архива и главный заголовок
	if err := writer.writeSignature(); err != nil {
		return fmt.Errorf("failed to write signature: %w", err)
	}
	if err := writer.writeMainHeader(); err != nil {
		return fmt.Errorf("failed to write main header: %w", err)
	}

	total := len(filesAndDirs)
	processed := 0

	// Использовать concurrency для обработки файлов
	numWorkers := runtime.NumCPU()
	if numWorkers > 8 {
		numWorkers = 8 // Ограничить до 8 воркеров для стабильности
	}
	jobs := make(chan string, numWorkers*2)
	errorsChan := make(chan error, numWorkers)
	var wg sync.WaitGroup

	// Запустить воркеры
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				relName, err := filepath.Rel(base, p)
				if err != nil {
					log.Printf("Warning: skipping %s: %v", p, err)
					continue
				}
				info, err := os.Stat(p)
				if err != nil {
					log.Printf("Warning: skipping %s: %v", p, err)
					continue
				}
				if info.IsDir() {
					relName += "/"
					if err := writer.writeDirHeader(p, relName); err != nil {
						errorsChan <- fmt.Errorf("failed to write dir header for %s: %w", p, err)
						return
					}
				} else {
					if err := writer.writeFileHeader(p, relName, password); err != nil {
						errorsChan <- fmt.Errorf("failed to write file header for %s: %w", p, err)
						return
					}
				}
			}
		}()
	}

	// Отправить задания
	go func() {
		for _, p := range filesAndDirs {
			jobs <- p
		}
		close(jobs)
	}()

	// Дождаться воркеров и собрать ошибки
	go func() {
		wg.Wait()
		close(errorsChan)
	}()

	// Собрать результаты
	for err := range errorsChan {
		if err != nil {
			return err
		}
	}

	// Подсчитать обработанные (поскольку ошибок нет, все обработаны)
	processed = total
	if verbose {
		fmt.Printf("Обработано %d/%d файлов\n", processed, total)
	}

	// Записать конечный заголовок
	if err := writer.writeEndHeader(); err != nil {
		return fmt.Errorf("failed to write end header: %w", err)
	}

	if verbose {
		fmt.Printf("Обработано %d/%d файлов\n", processed, total)
	}
	return nil
}

func main() {
	args := os.Args[1:]
	if len(args) < 3 || args[0] != "a" {
		fmt.Println("Использование: rargo a archive.rar file1 [file2 ...] [--verbose] [--password PASS]")
		os.Exit(1)
	}
	archivePath := args[1]
	var paths []string
	var verbose bool
	var password string
	for i := 2; i < len(args); i++ {
		if args[i] == "--verbose" {
			verbose = true
		} else if args[i] == "--password" {
			if i+1 < len(args) {
				password = args[i+1]
				i++
			} else {
				fmt.Println("Ошибка: --password требует значение")
				os.Exit(1)
			}
		} else {
			paths = append(paths, args[i])
		}
	}
	if len(paths) == 0 {
		fmt.Println("Ошибка: укажите файлы для архивации")
		os.Exit(1)
	}
	start := time.Now()
	err := CreateArchive(archivePath, paths, verbose, password)
	if err != nil {
		var ip *InvalidPathError
		var fr *FileReadError
		var rc *RarCreationError
		if errors.As(err, &ip) || errors.As(err, &fr) || errors.As(err, &rc) {
			fmt.Println("Ошибка:", err)
		} else {
			fmt.Println("Неожиданная ошибка:", err)
		}
		os.Exit(1)
	}
	elapsed := time.Since(start).Seconds()
	fmt.Printf("Архив %s создан успешно за %.2f секунд.\n", archivePath, elapsed)
}
