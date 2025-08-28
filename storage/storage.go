package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
	"log"
	"mime/multipart"
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

func readHeader(r io.Reader) (chunkSize int, salt, noncePrefix []byte, err error) {
	buffer := make([]byte, headerSize)

	if _, err = io.ReadFull(r, buffer); err != nil {
		return
	}
	if buffer[0] != versionByte {
		err = fmt.Errorf("unsupported version: %d", buffer[0])
		return
	}

	salt = make([]byte, 16)
	copy(salt, buffer[1:17])

	noncePrefix = make([]byte, 8)
	copy(noncePrefix, buffer[17:25])

	chunkSize = int(binary.BigEndian.Uint32(buffer[25:29]))
	return
}

// writeHeader writes a header to the given writer containing version, salt, noncePrefix, and chunk size information.
// It returns an error if writing to the writer fails.
func writeHeader(w io.Writer, chunkSize int, salt, noncePrefix []byte) error {
	header := make([]byte, headerSize)
	header[0] = versionByte
	copy(header[1:17], salt)
	copy(header[17:25], noncePrefix)
	binary.BigEndian.PutUint32(header[25:29], uint32(chunkSize))
	_, err := w.Write(header)
	return err
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
	var err error

	//Fills salt and noncePrefix with random data
	salt := make([]byte, 16)
	_, err = rand.Read(salt)
	if err != nil {
		return err
	}

	noncePrefix := make([]byte, 8)
	_, err = rand.Read(noncePrefix)
	if err != nil {
		return err
	}

	err = writeHeader(w, chunkSize, salt, noncePrefix)
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

	// buffers (to not spam allocations)
	buf := make([]byte, chunkSize)
	nonce := make([]byte, 12)
	aad := make([]byte, 8)
	sealed_dst := make([]byte, 0, chunkSize+aeadBlock.Overhead())

	index := uint32(0)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			plain := buf[:n]

			//nonce := make([]byte, 12)
			copy(nonce[:8], noncePrefix)
			binary.BigEndian.PutUint32(nonce[8:], index)

			//aad := make([]byte, 8)
			binary.BigEndian.PutUint32(aad[:4], uint32(headerSize))
			binary.BigEndian.PutUint32(aad[4:], index)

			sealed_dst = sealed_dst[:0]
			ct := aeadBlock.Seal(sealed_dst, nonce, plain, aad)

			var lenPrefix [4]byte
			binary.BigEndian.PutUint32(lenPrefix[:], uint32(len(ct)))
			if _, err2 := w.Write(lenPrefix[:]); err2 != nil {
				return err2
			}
			if _, err2 := w.Write(ct); err2 != nil {
				return err2
			}

			index++
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	log.Printf("Encrypted %d chunks", index)

	return nil
}

func Decrypt(masterKey []byte, r io.Reader, w io.Writer) error {
	_, salt, noncePrefix, err := readHeader(r)
	if err != nil {
		return err
	}

	key, err := deriveFileKey(masterKey, salt)
	if err != nil {
		return err
	}
	aead_block, err := getGCMBlock(key)
	if err != nil {
		return err
	}

	//buffers
	aad := make([]byte, 8)
	nonce := make([]byte, 12)

	index := uint32(0)
	for {
		var lenPrefix [4]byte
		_, err := io.ReadFull(r, lenPrefix[:])
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		numbytes_ciphertext := binary.BigEndian.Uint32(lenPrefix[:])
		ciphertext := make([]byte, numbytes_ciphertext)
		_, err = io.ReadFull(r, ciphertext)
		if err != nil {
			return err
		}

		//nonce := make([]byte, 12)
		copy(nonce[:8], noncePrefix)
		binary.BigEndian.PutUint32(nonce[8:], index)

		//aad := make([]byte, 8)
		binary.BigEndian.PutUint32(aad[:4], uint32(headerSize))
		binary.BigEndian.PutUint32(aad[4:], index)

		plaintext, err := aead_block.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			return fmt.Errorf("auth failed on chunk %d: %w", index, err)
		}

		_, err = w.Write(plaintext)
		if err != nil {
			return err
		}

		index++
	}

}
