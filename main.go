package main

import (
	"SCloud/config"
	"SCloud/handlers"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"os"
)

//TIP <p>To run your code, right-click the code and select <b>Run</b>.</p> <p>Alternatively, click
// the <icon src="AllIcons.Actions.Execute"/> icon in the gutter and select the <b>Run</b> menu item from here.</p>

func main() {
	router := gin.Default()
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Printf("Error loading config: %v", err)
	}

	router.GET("/health", func(context *gin.Context) {
		context.String(http.StatusOK, "OK")
	})

	router.POST("/files/upload", handlers.UploadHandler)
	router.GET("/files/download/*filepath", handlers.DownloadHandler)
	router.DELETE("/files/delete/*filepath", handlers.DeleteHandler)
	router.GET("/files/ls/*filepath", handlers.ListHandler)

	err = router.Run(cfg.Port)
	if err != nil {
		log.Printf("server error: %v", err)
		os.Exit(1)
	}
}
