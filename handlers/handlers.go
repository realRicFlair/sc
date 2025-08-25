package handlers

import (
	"SCloud/storage"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

var db *gorm.DB

func UploadHandler(context *gin.Context) {

}

func DownloadHandler(context *gin.Context) {
	mkey := []byte("12345678901234567890123456789012")
	requestedPath := context.Param("filepath") // includes leading "/"
	requestedPath = requestedPath[1:]          // trim leading "/"

	baseDir, _ := os.Getwd()
	file, err := os.Open(filepath.Join(baseDir, requestedPath))
	if err != nil {
		context.String(http.StatusNotFound, "File not found")
		log.Printf("Error opening file: %v", err)
		return
	}
	defer file.Close()

	context.Header("Content-Type", "application/octet-stream")
	context.Header("Content-Disposition", `attachment; filename="file.bin"`)

	pipeReader, pipeWriter := io.Pipe()
	go func() {
		defer pipeWriter.Close()
		// stream-decrypt into the pipe
		err := storage.Decrypt(mkey, file, pipeWriter)
		if err != nil {
			log.Printf("Error decrypting file: %v", err)
			pipeWriter.CloseWithError(err)
		}
	}()

	// stream plaintext to client
	_, _ = io.Copy(context.Writer, pipeReader)
}

func DeleteHandler(context *gin.Context) {
}

func ListHandler(context *gin.Context) {

}
