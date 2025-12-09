package main

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

// TestEncodeVint тестирует кодирование vint RAR 5.0.
func TestEncodeVint(t *testing.T) {
	tests := []struct {
		value    int
		expected []byte
	}{
		{0, []byte{0}},
		{3, []byte{3}},
		{128, []byte{0x80, 0x01}},
		{300, []byte{0xac, 0x02}},
	}
	for _, test := range tests {
		result := encodeVint(test.value)
		if len(result) != len(test.expected) {
			t.Errorf("encodeVint(%d) length %d, expected %d", test.value, len(result), len(test.expected))
		}
		for i, b := range result {
			if b != test.expected[i] {
				t.Errorf("encodeVint(%d) [%d] = %x, expected %x", test.value, i, b, test.expected[i])
			}
		}
	}
}

// TestComputeCRC32 тестирует вычисление CRC32.
func TestComputeCRC32(t *testing.T) {
	data := []byte("test")
	expected := 0xD87F7E0C
	result := computeCRC32(data)
	if result != expected {
		t.Errorf("computeCRC32(%q) = %x, expected %x", data, result, expected)
	}
}

// TestPkcs7Pad тестирует PKCS7 padding.
func TestPkcs7Pad(t *testing.T) {
	data := []byte("test")
	blockSize := 16
	padded := pkcs7Pad(data, blockSize)
	expectedLen := 16
	if len(padded) != expectedLen {
		t.Errorf("pkcs7Pad length %d, expected %d", len(padded), expectedLen)
	}
	if padded[len(padded)-1] != byte(expectedLen-len(data)) {
		t.Errorf("padding byte %x, expected %x", padded[len(padded)-1], byte(expectedLen-len(data)))
	}
}

// TestEncryptData тестирует шифрование AES-256 CBC с PKCS7 padding.
func TestEncryptData(t *testing.T) {
	data := []byte("hello world test")
	key := make([]byte, 32)
	iv := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	for i := range iv {
		iv[i] = byte(i + 32)
	}
	encrypted, err := encryptData(data, key, iv)
	if err != nil {
		t.Fatalf("encryptData failed: %v", err)
	}
	if len(encrypted) == 0 {
		t.Error("encrypted data is empty")
	}
	// Decrypt to verify
	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(encrypted))
	mode.CryptBlocks(decrypted, encrypted)
	// Remove padding
	padding := int(decrypted[len(decrypted)-1])
	decrypted = decrypted[:len(decrypted)-padding]
	if string(decrypted) != string(data) {
		t.Errorf("decryption failed: got %q, expected %q", decrypted, data)
	}
}

// BenchmarkEncryptData измеряет производительность шифрования 1MB данных.
func BenchmarkEncryptData(b *testing.B) {
	data := make([]byte, 1024*1024) // 1MB
	for i := range data {
		data[i] = byte(i % 256)
	}
	key := make([]byte, 32)
	iv := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	for i := range iv {
		iv[i] = byte(i + 32)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = encryptData(data, key, iv)
	}
}
