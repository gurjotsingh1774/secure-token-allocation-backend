// Package services provides core cryptographic and security utilities for the backend.
// It implements symmetric encryption and decryption using AES-256 in Cipher Feedback (CFB) mode,
// ensuring Personally Identifiable Information (PII) submitted by users remains encrypted at rest.
package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
)

// key is the 32-byte (256-bit) symmetric key used for AES-256 operations.
// Initialized once during package startup in init().
var key []byte

// init derives the 32-byte AES-256 key from environment variables upon package load.
//
// Working:
// 1. Reads the `AES_KEY` environment variable.
// 2. If unset, falls back to a development key string: "SecureTokenAllocationSecretKey32".
// 3. Normalizes key length:
//    - If shorter than 32 bytes, pads with a deterministic numeric suffix up to 32 bytes.
//    - If longer than 32 bytes, slices to the exact first 32 bytes.
// 4. Stores the resulting 32-byte slice into package-global `key`.
//
// Interactions:
// - Executes automatically when the application starts prior to any Encrypt or Decrypt call.
func init() {
	k := os.Getenv("AES_KEY")
	if k == "" {
		k = "SecureTokenAllocationSecretKey32"
	}
	if len(k) < 32 {
		k = (k + "01234567890123456789012345678901")[:32]
	} else if len(k) > 32 {
		k = k[:32]
	}
	key = []byte(k)
}

// Encrypt secures sensitive plaintext strings using AES-256-CFB with a randomized IV.
//
// Working:
// 1. Instantiates a new AES block cipher using the 32-byte global key (guaranteeing AES-256).
// 2. Allocates a byte buffer sized to hold the 16-byte Initialization Vector (IV) plus plaintext length.
// 3. Generates a cryptographically strong random IV via crypto/rand.Reader to ensure identical plaintexts
//    produce distinct ciphertexts (protecting against frequency analysis and replay attacks).
// 4. Initializes a CFB stream encrypter using cipher.NewCFBEncrypter(block, iv).
// 5. Encrypts the plaintext into the byte buffer following the IV prefix using XORKeyStream.
// 6. Encodes the composite [IV + ciphertext] bytes as a URL-safe Base64 string.
//
// Parameters:
// - plaintext: The sensitive raw string to encrypt (typically JSON-encoded form data).
//
// Returns:
// - string: URL-safe Base64 encoded string containing the 16-byte IV concatenated with ciphertext.
// - error: Non-nil if cipher creation fails or secure random reader fails.
//
// Interactions:
// - Called by `handlers.SubmitTokenRequest` in `handlers/handlers.go` to encrypt user-submitted
//   form fields before inserting into the `request_items.form_data` column in PostgreSQL.
func Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// Decrypt reverses the AES-256-CFB encryption, recovering original plaintext from URL-safe Base64 ciphertext.
//
// Working:
// 1. Decodes the input URL-safe Base64 string into raw binary bytes.
// 2. Instantiates an AES block cipher with the 32-byte global key.
// 3. Validates that the decoded byte slice is at least 16 bytes (aes.BlockSize) to ensure the IV is present.
//    Returns "ciphertext too short" error if invalid.
// 4. Extracts the first 16 bytes as the Initialization Vector (IV) and the remaining bytes as ciphertext.
// 5. Initializes a CFB stream decrypter using cipher.NewCFBDecrypter(block, iv).
// 6. Decrypts the ciphertext in place using XORKeyStream.
// 7. Converts decrypted bytes to string and returns.
//
// Parameters:
// - cryptoText: URL-safe Base64 encoded string containing [16-byte IV + AES ciphertext].
//
// Returns:
// - string: Decrypted original plaintext string.
// - error: Non-nil if Base64 decoding fails, block cipher creation fails, or payload is too short.
//
// Interactions:
// - Called by `handlers.toDTO` in `handlers/handlers.go` to decrypt user form data for
//   authorized admins and the authentic ticket owner.
// - Called by `handlers.ExportAllocationCSV` to populate Excel spreadsheet rows with readable form field answers.
func Decrypt(cryptoText string) (string, error) {
	ciphertext, err := base64.URLEncoding.DecodeString(cryptoText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

