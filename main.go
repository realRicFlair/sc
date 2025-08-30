package main

import (
	"SCloud/auth"
	"SCloud/config"
	"SCloud/handlers"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
)

//TIP <p>To run your code, right-click the code and select <b>Run</b>.</p> <p>Alternatively, click
// the <icon src="AllIcons.Actions.Execute"/> icon in the gutter and select the <b>Run</b> menu item from here.</p>

func main() {
	router := gin.Default()
	_, err := config.LoadConfig()
	if err != nil {
		log.Printf("Error loading config: %v", err)
	}

	router.GET("/health", func(context *gin.Context) {
		context.String(http.StatusOK, "OK")
	})

	filesGroup := router.Group("/api/files")
	{
		filesGroup.POST("/upload", handlers.UploadHandler)
		filesGroup.GET("/download/*filepath", handlers.DownloadHandler)
		filesGroup.DELETE("/delete/*filepath", handlers.DeleteHandler)
		filesGroup.GET("/ls/*filepath", handlers.ListHandler)
	}

	authGroup := router.Group("/api/auth")
	{
		authGroup.POST("/register", auth.RegisterHandler)
	}

	router.Static("/assets", "./dist/assets")
	router.NoRoute(func(context *gin.Context) {
		context.File("./dist/index.html")
	})

	router.GET("/", func(context *gin.Context) {
		context.File("./dist/index.html")
	})

	//err = router.Run(":8443")
	err = router.RunTLS(":8443", "./opem.txt", "./okey.txt")

	if err != nil {
		log.Printf("server error: %v", err)
		panic(err)
	}
}
