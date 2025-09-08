package handlers

import (
	"SCloud/storage"
	"fmt"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

var db *gorm.DB

func UploadHandler(c *gin.Context) {
	// 32-byte key for AES-256-GCM
	mkey := []byte("12345678901234567890123456789012")

	fh, err := c.FormFile("file")
	if err != nil {
		c.String(http.StatusBadRequest, "No file uploaded: %v", err)
		return
	}

	logicalPath := c.PostForm("path")
	if logicalPath == "" {
		c.String(http.StatusBadRequest, "Missing target filepath")
		return
	}

	// Open the uploaded file as an io.Reader (Gin stores large files on disk temp)
	src, err := fh.Open()
	if err != nil {
		c.String(http.StatusInternalServerError, "Error opening upload: %v", err)
		return
	}
	defer src.Close()

	// Build a sane destination path (NO leading slash) and ensure directory exists
	baseDir, err := os.Getwd()
	if err != nil {
		c.String(http.StatusInternalServerError, "cwd error: %v", err)
		return
	}
	dstPath, err := storage.ResolveForCreate(mkey, baseDir, filepath.Clean(logicalPath))
	if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
		c.String(http.StatusInternalServerError, "mkdir: %v", err)
		return
	}

	// Open the destination file for writing (truncate if exists)
	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		c.String(http.StatusInternalServerError, "Error creating file: %v", err)
		return
	}
	defer func() {
		_ = dst.Sync()
		_ = dst.Close()
	}()

	// Stream-encrypt directly from src -> dst (no pipes needed)
	if err := storage.Encrypt(mkey, src, dst, 0); err != nil {
		c.String(http.StatusInternalServerError, "Encrypt failed: %v", err)
		return
	}

	// sanity log
	if fi, err := dst.Stat(); err == nil {
		log.Printf("wrote %s (%d bytes) to %s", fh.Filename, fi.Size(), dstPath)
	}

	plainSize := fh.Size
	_ = storage.UpdateFileMeta(mkey, baseDir, filepath.Clean(logicalPath), plainSize, time.Now())

	c.String(http.StatusOK, "File uploaded successfully")
}

func DownloadHandler(context *gin.Context) {
	mkey := []byte("12345678901234567890123456789012")

	requestedPath := context.Query("filepath")
	if requestedPath == "" {
		context.String(http.StatusBadRequest, "Missing file path")
		return
	}

	baseDir, _ := os.Getwd()
	//filePath := filepath.Join(baseDir, "/filestorage/", filepath.Clean(requestedPath))
	filePath, err := storage.ResolveForRead(mkey, baseDir, filepath.Clean(requestedPath))
	file, err := os.Open(filePath)

	if err != nil {
		context.String(http.StatusNotFound, "File not found")
		log.Printf("Error opening file: %v", err)
		return
	}
	defer file.Close()

	// Set download headers (use the requested base name)
	context.Header("Content-Type", "application/octet-stream")
	context.Header("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, filepath.Base(requestedPath)))

	// Pipe so we can detect decrypt errors and optionally fall back
	pipeReader, pipeWriter := io.Pipe()
	go func() {
		defer pipeWriter.Close()
		if err := storage.Decrypt(mkey, file, pipeWriter); err != nil {
			log.Printf("Error decrypting file %s: %v", filePath, err)
			pipeWriter.CloseWithError(err)
		}
	}()

	// Stream plaintext to client
	bytesWritten, copyErr := io.Copy(context.Writer, pipeReader)
	if copyErr != nil && bytesWritten == 0 {
		// Decryption failed before anything was sent:
		// fall back to streaming the raw file for testing convenience.
		if _, seekErr := file.Seek(0, io.SeekStart); seekErr == nil {
			if _, err := io.Copy(context.Writer, file); err != nil {
				log.Printf("Error streaming raw file %s: %v", filePath, err)
			}
			return
		}
		// If we can't seek, we can't recover; response likely has headers but no body.
		log.Printf("Download failed and could not fall back for %s: %v", filePath, copyErr)
		return
	}
}

func DeleteHandler(context *gin.Context) {

}

func ListHandler(context *gin.Context) {
	mkey := []byte("12345678901234567890123456789012")

	requestedPath := context.Query("filepath")
	if requestedPath == "" {
		requestedPath = "." // default to root
	}
	baseDir, _ := os.Getwd()

	entries, err := storage.ListDir(mkey, baseDir, filepath.Clean(requestedPath))
	if err != nil {
		context.String(http.StatusNotFound, "Error listing directory: %v", err)
		return
	}

	// Return plaintext metadata as JSON
	context.JSON(http.StatusOK, gin.H{
		"path":    requestedPath,
		"entries": entries,
	})
}
