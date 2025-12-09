package main

import (
	"testing"
)

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

func TestComputeCRC32(t *testing.T) {
	data := []byte("test")
	expected := 0xD87F7E0C
	result := computeCRC32(data)
	if result != expected {
		t.Errorf("computeCRC32(%q) = %x, expected %x", data, result, expected)
	}
}

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
