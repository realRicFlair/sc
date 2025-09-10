package storage

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type ChunkMeta struct {
	LogicalPath string // plaintext logical path (manifest maps it to slug later)
	FileID      string // client-provided stable id (uuid/hex/random string)
	ChunkSize   int
	Index       uint32
	TotalChunks int
	TotalSize   int64 // optional but used to UpdateFileMeta on assemble
}

// staging directory: <root>/_uploads/<fileid>/
func stagingDirFor(root, fileID string) string {
	return filepath.Join(root, "_uploads", safeID(fileID))
}
func safeID(id string) string {
	// make a filesystem-friendly id
	id = strings.TrimSpace(id)
	if id == "" {
		id = "missing"
	}
	id = strings.ReplaceAll(id, "/", "_")
	return id
}

type stagedHeader struct {
	hdr         []byte // exact header bytes used as AAD (version|salt|noncePrefix|chunkSize)
	salt        []byte
	noncePrefix []byte
}

// derive deterministic header from (masterKey, fileID, chunkSize)
func deriveHeaderFor(masterKey []byte, fileID string, chunkSize int) (stagedHeader, error) {
	// Deterministic per-file salt & noncePrefix using HKDF with fileID as "salt" input.
	// This keeps "stateless" across requests; uniqueness comes from FileID.
	fileIDbytes := []byte(fileID)
	salt := hkdfBytes(16, masterKey, fileIDbytes, []byte("upload-salt:v1"))
	nonce := hkdfBytes(8, masterKey, fileIDbytes, []byte("upload-nonceprefix:v1"))
	hdr := generateHeader(chunkSize, salt, nonce)
	return stagedHeader{hdr: hdr, salt: salt, noncePrefix: nonce}, nil
}
func hkdfBytes(n int, key, salt, info []byte) []byte {
	h := hkdf.New(sha256.New, key, salt, info)
	out := make([]byte, n)
	_, _ = io.ReadFull(h, out)
	return out
}

func encryptRecord(masterKey []byte, sh stagedHeader, index uint32, plain []byte) ([]byte, error) {
	key, err := deriveFileKey(masterKey, sh.salt)
	if err != nil {
		return nil, err
	}
	aead, err := getGCMBlock(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	copy(nonce[:8], sh.noncePrefix)
	binary.BigEndian.PutUint32(nonce[8:], index)

	aad := make([]byte, len(sh.hdr)+4)
	copy(aad, sh.hdr)
	binary.BigEndian.PutUint32(aad[len(sh.hdr):], index)

	ct := aead.Seal(nil, nonce, plain, aad)

	// frame: [len][ct]
	buf := make([]byte, 4+len(ct))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(ct)))
	copy(buf[4:], ct)
	return buf, nil
}

// write part file: <staging>/<index>.part
func writePart(staging string, idx uint32, record []byte) error {
	if err := os.MkdirAll(staging, 0755); err != nil {
		return err
	}
	part := filepath.Join(staging, fmt.Sprintf("%08d.part", idx))
	// O_EXCL to avoid torn writes if client retries the same chunk concurrently
	f, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		// if it already exists, treat as idempotent success
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return err
	}
	defer f.Close()
	if _, err := f.Write(record); err != nil {
		return err
	}
	return f.Sync()
}

func listParts(staging string) ([]string, error) {
	ents, err := os.ReadDir(staging)
	if err != nil {
		return nil, err
	}
	var parts []string
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".part") {
			parts = append(parts, filepath.Join(staging, e.Name()))
		}
	}
	sort.Strings(parts)
	return parts, nil
}

func haveAllParts(staging string, total int) (bool, error) {
	if total <= 0 {
		return false, fmt.Errorf("bad total")
	}
	for i := 0; i < total; i++ {
		part := filepath.Join(staging, fmt.Sprintf("%08d.part", i))
		if _, err := os.Stat(part); err != nil {
			return false, nil
		}
	}
	return true, nil
}

func assemble(masterKey []byte, baseDir, logicalPath, staging string, sh stagedHeader, totalChunks int, totalSize int64) (string, error) {
	root, err := ensureRoot(masterKey, baseDir)
	if err != nil {
		return "", err
	}

	// allocate final path & manifest entry *now*
	dstPath, err := ResolveForCreate(masterKey, baseDir, logicalPath)
	if err != nil {
		return "", err
	}

	// create final file; write header
	out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, 0644)
	if err != nil {
		return "", err
	}
	if _, err := out.Write(sh.hdr); err != nil {
		out.Close()
		return "", err
	}

	// append all parts in order
	for i := 0; i < totalChunks; i++ {
		part := filepath.Join(staging, fmt.Sprintf("%08d.part", i))
		b, err := os.ReadFile(part)
		if err != nil {
			out.Close()
			return "", err
		}
		if _, err := out.Write(b); err != nil {
			out.Close()
			return "", err
		}
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return "", err
	}
	_ = out.Close()

	// update manifest (plaintext size if known)
	if totalSize > 0 {
		_ = UpdateFileMeta(masterKey, baseDir, logicalPath, totalSize, time.Now())
	}

	// cleanup staging
	_ = os.RemoveAll(staging)

	_ = root // silence linter; root is used by ensureRoot side effects
	return logicalPath, nil
}

// IngestChunkStateless encrypts one chunk to a .part and assembles when complete.
func IngestChunkStateless(masterKey []byte, baseDir string, meta ChunkMeta, plain []byte) (assembled bool, assembledLogicalPath string, err error) {
	if meta.ChunkSize <= 0 {
		return false, "", fmt.Errorf("bad chunk_size")
	}
	if len(plain) == 0 || len(plain) > meta.ChunkSize {
		return false, "", fmt.Errorf("bad chunk len")
	}
	if meta.TotalChunks <= 0 {
		return false, "", fmt.Errorf("bad total_chunks")
	}
	if int(meta.Index) >= meta.TotalChunks {
		return false, "", fmt.Errorf("index out of range")
	}
	if meta.LogicalPath == "" || meta.FileID == "" {
		return false, "", fmt.Errorf("missing path or file_id")
	}

	root, err := ensureRoot(masterKey, baseDir)
	if err != nil {
		return false, "", err
	}

	// derive deterministic header from (masterKey, fileID, chunkSize)
	sh, err := deriveHeaderFor(masterKey, meta.FileID, meta.ChunkSize)
	if err != nil {
		return false, "", err
	}

	// encrypt the record with header||index as AAD
	rec, err := encryptRecord(masterKey, sh, meta.Index, plain)
	if err != nil {
		return false, "", err
	}

	// write part file into <root>/_uploads/<fileid>/
	staging := stagingDirFor(root, meta.FileID)
	if err := writePart(staging, meta.Index, rec); err != nil {
		return false, "", err
	}

	// check completeness; if all present, assemble to final format (your Decrypt can read it)
	all, err := haveAllParts(staging, meta.TotalChunks)
	if err != nil {
		return false, "", err
	}
	if !all {
		return false, "", nil
	}

	lp, err := assemble(masterKey, baseDir, meta.LogicalPath, staging, sh, meta.TotalChunks, meta.TotalSize)
	if err != nil {
		return false, "", err
	}
	return true, lp, nil
}
