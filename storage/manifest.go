package storage

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type ManifestEntry struct {
	Name    string `json:"name"`           // plaintext visible only after decrypting manifest
	Enc     string `json:"enc"`            // slug used on disk (dir name or file name, hex)
	Type    string `json:"type"`           // "file" | "dir"
	Size    int64  `json:"size,omitempty"` // plaintext size (files)
	Created int64  `json:"created,omitempty"`
	ModTime int64  `json:"mod_time,omitempty"`
}
type DirManifest struct {
	Version int             `json:"version"`
	Entries []ManifestEntry `json:"entries"`
}

func manifestPath(dir string) string { return filepath.Join(dir, manifestFileName) }

func randSlugHex(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func encryptBytes(masterKey []byte, data []byte) ([]byte, error) {
	var out bytes.Buffer
	if err := Encrypt(masterKey, bytes.NewReader(data), &out, 64*1024); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func decryptBytes(masterKey []byte, data []byte) ([]byte, error) {
	var out bytes.Buffer
	if err := Decrypt(masterKey, bytes.NewReader(data), &out); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func loadManifest(masterKey []byte, dir string) (*DirManifest, error) {
	mp := manifestPath(dir)
	f, err := os.Open(mp)
	if err != nil {
		if os.IsNotExist(err) {
			return &DirManifest{Version: 1, Entries: nil}, nil
		}
		return nil, err
	}
	defer f.Close()
	cipher, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	plain, err := decryptBytes(masterKey, cipher)
	if err != nil {
		return nil, err
	}
	var m DirManifest
	if err := json.Unmarshal(plain, &m); err != nil {
		return nil, err
	}
	if m.Entries == nil {
		m.Entries = []ManifestEntry{}
	}
	return &m, nil
}

func saveManifest(masterKey []byte, dir string, m *DirManifest) error {
	plain, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	cipher, err := encryptBytes(masterKey, plain)
	if err != nil {
		return err
	}
	tmp := manifestPath(dir) + ".tmp"
	if err := os.WriteFile(tmp, cipher, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, manifestPath(dir))
}

func ensureRoot(masterKey []byte, baseDir string) (string, error) {
	root := filepath.Join(baseDir, "filestorage")
	if err := os.MkdirAll(root, 0755); err != nil {
		return "", err
	}
	m, err := loadManifest(masterKey, root)
	if err != nil {
		return "", err
	}
	if err := saveManifest(masterKey, root, m); err != nil {
		return "", err
	}
	return root, nil
}

func findEntry(m *DirManifest, name, typ string) (int, *ManifestEntry) {
	for i := range m.Entries {
		if m.Entries[i].Name == name && m.Entries[i].Type == typ {
			return i, &m.Entries[i]
		}
	}
	return -1, nil
}

func resolveParentDir(masterKey []byte, baseDir, logicalPath string, create bool) (string, string, error) {
	cleaned := filepath.Clean(logicalPath)
	parts := strings.Split(cleaned, string(filepath.Separator))
	if len(parts) == 0 {
		return "", "", fmt.Errorf("empty logical path")
	}
	if parts[0] == "" {
		parts = parts[1:]
	}

	finalName := parts[len(parts)-1]
	dirs := parts[:len(parts)-1]

	root, err := ensureRoot(masterKey, baseDir)
	if err != nil {
		return "", "", err
	}
	curDir := root

	for _, seg := range dirs {
		m, err := loadManifest(masterKey, curDir)
		if err != nil {
			return "", "", err
		}
		if _, e := findEntry(m, seg, "dir"); e != nil {
			curDir = filepath.Join(curDir, e.Enc)
			continue
		}
		if !create {
			return "", "", fmt.Errorf("dir %q not found", seg)
		}
		// create new dir + manifest
		slug, _ := randSlugHex(16)
		_ = os.MkdirAll(filepath.Join(curDir, slug), 0755)
		now := time.Now().Unix()
		m.Entries = append(m.Entries, ManifestEntry{Name: seg, Enc: slug, Type: "dir", Created: now, ModTime: now})
		saveManifest(masterKey, curDir, m)
		curDir = filepath.Join(curDir, slug)
		saveManifest(masterKey, curDir, &DirManifest{Version: 1, Entries: nil})
	}
	return curDir, finalName, nil
}

func ResolveForCreate(masterKey []byte, baseDir, logicalPath string) (string, error) {
	parentDir, fileName, err := resolveParentDir(masterKey, baseDir, logicalPath, true)
	if err != nil {
		return "", err
	}
	m, _ := loadManifest(masterKey, parentDir)
	if _, e := findEntry(m, fileName, "file"); e != nil {
		return filepath.Join(parentDir, e.Enc+".bin"), nil
	}
	slug, _ := randSlugHex(16)
	now := time.Now().Unix()
	m.Entries = append(m.Entries, ManifestEntry{Name: fileName, Enc: slug, Type: "file", Created: now, ModTime: now})
	saveManifest(masterKey, parentDir, m)
	return filepath.Join(parentDir, slug+".bin"), nil
}

func ResolveForRead(masterKey []byte, baseDir, logicalPath string) (string, error) {
	parentDir, fileName, err := resolveParentDir(masterKey, baseDir, logicalPath, false)
	if err != nil {
		return "", err
	}
	m, _ := loadManifest(masterKey, parentDir)
	if _, e := findEntry(m, fileName, "file"); e != nil {
		return filepath.Join(parentDir, e.Enc+".bin"), nil
	}
	return "", fmt.Errorf("file %q not found", fileName)
}

func UpdateFileMeta(masterKey []byte, baseDir, logicalPath string, size int64, mod time.Time) error {
	parentDir, fileName, err := resolveParentDir(masterKey, baseDir, logicalPath, false)
	if err != nil {
		return err
	}
	m, _ := loadManifest(masterKey, parentDir)
	idx, e := findEntry(m, fileName, "file")
	if e == nil {
		return fmt.Errorf("file missing")
	}
	m.Entries[idx].Size = size
	m.Entries[idx].ModTime = mod.Unix()
	return saveManifest(masterKey, parentDir, m)
}
