package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
	"log"
	"mime/multipart"
	"path/filepath"
	"strings"
)

type Store struct {
	baseDir string
	key     []byte
}

type fileMetadata struct {
	filename  string
	filetype  string
	sizeBytes int64
}

type Storage interface {
	Save(file multipart.File, filename string) error
	Load(filename string) ([]byte, error)
	Delete(filename string) error
	// Encrypt/Decrypt functions
	Encrypt(masterKey []byte, r io.Reader, w io.Writer, chunkSize int) error
	Decrypt(masterKey []byte, r io.Reader, w io.Writer) error
}

const (
	versionByte = 1
	headerSize  = 1 + 16 + 8 + 4
	// ver(1) + salt(16) + noncePrefix(8) + chunkSize(4) + name() + filesize()
	defaultChunk = 1 << 20 // 1 MiB
)

func readHeader(r io.Reader) (chunkSize int, hdr, salt, noncePrefix []byte, err error) {
	hdr = make([]byte, headerSize)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return
	}
	if hdr[0] != versionByte {
		err = fmt.Errorf("unsupported version: %d", hdr[0])
		return
	}
	salt = make([]byte, 16)
	copy(salt, hdr[1:17])

	noncePrefix = make([]byte, 8)
	copy(noncePrefix, hdr[17:25])

	chunkSize = int(binary.BigEndian.Uint32(hdr[25:29]))
	return
}

// writeHeader writes a header to the given writer containing version, salt, noncePrefix, and chunk size information.
// It returns an error if writing to the writer fails.
func writeHeader(w io.Writer, chunkSize int, salt, noncePrefix []byte) ([]byte, error) {
	hdr := generateHeader(chunkSize, salt, noncePrefix)
	_, err := w.Write(hdr)
	return hdr, err
}

func generateHeader(chunkSize int, salt, noncePrefix []byte) []byte {
	hdr := make([]byte, headerSize)
	hdr[0] = versionByte
	copy(hdr[1:17], salt)
	copy(hdr[17:25], noncePrefix)
	binary.BigEndian.PutUint32(hdr[25:29], uint32(chunkSize))
	return hdr
}

// Use HKDF to turn file salt and masterkey, into the actual file key.
func deriveFileKey(masterKey, salt []byte) ([]byte, error) {
	x := hkdf.New(sha256.New, masterKey, salt, []byte("file-key:v1"))
	key := make([]byte, 32)
	_, err := io.ReadFull(x, key)
	return key, err
}

func getGCMBlock(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func Encrypt(masterKey []byte, r io.Reader, w io.Writer, chunkSize int) error {
	if chunkSize <= 0 {
		chunkSize = defaultChunk
	}

	// Random salt and 64-bit nonce prefix.
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	noncePrefix := make([]byte, 8)
	if _, err := rand.Read(noncePrefix); err != nil {
		return err
	}

	// Write header and keep the exact bytes for AAD.
	hdr, err := writeHeader(w, chunkSize, salt, noncePrefix)
	if err != nil {
		return err
	}

	key, err := deriveFileKey(masterKey, salt)
	if err != nil {
		return err
	}
	aeadBlock, err := getGCMBlock(key)
	if err != nil {
		return err
	}

	buf := make([]byte, chunkSize)
	nonce := make([]byte, 12) // 8B prefix || 4B counter
	copy(nonce[:8], noncePrefix)

	// Prepare AAD buffer once: header || indexBE32
	aad := make([]byte, len(hdr)+4)
	copy(aad, hdr)

	var index uint32 = 0
	for {
		n, readErr := r.Read(buf)
		if n > 0 {
			// Set per-chunk nonce and AAD index.
			binary.BigEndian.PutUint32(nonce[8:], index)
			binary.BigEndian.PutUint32(aad[len(hdr):], index)

			// Encrypt this chunk.
			ct := aeadBlock.Seal(nil, nonce, buf[:n], aad)

			var lenPrefix [4]byte
			binary.BigEndian.PutUint32(lenPrefix[:], uint32(len(ct)))
			if _, err := w.Write(lenPrefix[:]); err != nil {
				return err
			}
			if _, err := w.Write(ct); err != nil {
				return err
			}

			// Overflow guard: 2^32 chunks max.
			if index == ^uint32(0) {
				return fmt.Errorf("too many chunks: index overflow")
			}
			index++
		}

		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}

	log.Printf("Encrypted %d chunks", index)
	return nil
}

func Decrypt(masterKey []byte, r io.Reader, w io.Writer) error {
	_, hdr, salt, noncePrefix, err := readHeader(r)
	if err != nil {
		return err
	}

	key, err := deriveFileKey(masterKey, salt)
	if err != nil {
		return err
	}
	aeadBlock, err := getGCMBlock(key)
	if err != nil {
		return err
	}

	nonce := make([]byte, 12)
	copy(nonce[:8], noncePrefix)

	aad := make([]byte, len(hdr)+4)
	copy(aad, hdr)

	var index uint32 = 0
	for {
		var lenPrefix [4]byte
		_, err := io.ReadFull(r, lenPrefix[:])
		if err == io.EOF {
			log.Printf("Decrypted %d chunks", index)
			return nil
		}
		if err != nil {
			return err
		}

		ctLen := binary.BigEndian.Uint32(lenPrefix[:])
		ciphertext := make([]byte, ctLen)
		if _, err = io.ReadFull(r, ciphertext); err != nil {
			return err
		}

		binary.BigEndian.PutUint32(nonce[8:], index)
		binary.BigEndian.PutUint32(aad[len(hdr):], index)

		plaintext, err := aeadBlock.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			return fmt.Errorf("auth failed on chunk %d: %w", index, err)
		}

		if _, err = w.Write(plaintext); err != nil {
			return err
		}

		if index == ^uint32(0) {
			return fmt.Errorf("too many chunks: index overflow")
		}
		index++
	}
}

// BlindIndex computes HMAC-SHA256(dirPath + "/" + name).
func BlindIndex(masterKey []byte, dirPath, fileName string) string {
	input := dirPath + "/" + fileName
	mac := hmac.New(sha256.New, masterKey)
	mac.Write([]byte(input))
	return hex.EncodeToString(mac.Sum(nil))
}

// TranslatePath takes a logical filepath like "docs/taxes/report.pdf"
// and returns the encrypted storage path under baseDir.
func TranslatePath(masterKey []byte, baseDir, logicalPath string) string {
	cleaned := filepath.Clean(logicalPath)
	parts := strings.Split(cleaned, string(filepath.Separator))
	if parts[0] == "" {
		parts = parts[1:]
	}

	currentDir := ""
	indexes := make([]string, 0, len(parts))
	for _, name := range parts {
		idx := BlindIndex(masterKey, currentDir, name)
		indexes = append(indexes, idx)

		if currentDir == "" {
			currentDir = "/" + name
		} else {
			currentDir = currentDir + "/" + name
		}
	}

	// join all indexes under baseDir
	return filepath.Join(append([]string{baseDir, "filestorage"}, indexes...)...)
}
