package main

import (
	"SCloud/auth"
	"SCloud/config"
	"SCloud/handlers"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"time"
)

//TIP <p>To run your code, right-click the code and select <b>Run</b>.</p> <p>Alternatively, click
// the <icon src="AllIcons.Actions.Execute"/> icon in the gutter and select the <b>Run</b> menu item from here.</p>

func checkError(err error) {
	log.Printf("Error: %v", err)
}

func main() {
	//db.ConnectDB()

	router := gin.Default()
	_, err := config.LoadConfig()
	if err != nil {
		log.Printf("Error loading config: %v", err)
	}
	router.Use(gin.Logger(), gin.Recovery())

	router.GET("/health", func(context *gin.Context) {
		context.String(http.StatusOK, "OK")
	})

	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"https://sc.rorocorp.org", "https://apisc.rorocorp.org"},
		AllowMethods:     []string{http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodHead, http.MethodDelete, http.MethodOptions},
		AllowHeaders:     []string{"Origin", "Content-Type", "X-XSRF-TOKEN", "X-CSRF-TOKEN", "Accept", "Origin", "X-Requested-With", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		AllowOriginFunc: func(origin string) bool {
			return origin == "exampleUrl"
		},
		MaxAge: 12 * time.Hour,
	}))

	apiGroup := router.Group("/api")
	{
		filesGroup := apiGroup.Group("/files")
		filesGroup.Use(auth.Authorize())
		{
			filesGroup.POST("/upload", handlers.UploadHandler)
			filesGroup.PUT("/uploadchunked", handlers.ChunkedUploadHandler)
			filesGroup.GET("/download", handlers.DownloadHandler)
			filesGroup.DELETE("/delete", handlers.DeleteHandler)
			filesGroup.GET("/ls", handlers.ListHandler)
		}

		authGroup := apiGroup.Group("/auth")
		{
			authGroup.POST("/register", auth.RegisterHandler)
			authGroup.POST("/login", auth.LoginHandler)
			//Signed download handler
			authGroup.GET("/genDLink", auth.GenerateDownloadLink)
			authGroup.GET("/checksession", auth.SessionCheckHandler)
		}

		downloadGroup := apiGroup.Group("/dlink")
		{
			downloadGroup.GET("/generateLink", auth.GenerateDownloadLink)
			downloadGroup.GET("/download", handlers.SignedDownloadHandler)
		}

	}

	apiGroup.OPTIONS("/*path", func(context *gin.Context) {
		context.Status(204)
	})

	/*
		router.Static("/assets", "./dist/assets")


			router.NoRoute(func(context *gin.Context) {
				context.File("./dist/index.html")
			})


		router.GET("/", func(context *gin.Context) {
			context.File("./dist/index.html")
		})
	*/

	//router.MaxMultipartMemory = 4 << 30
	//err = router.RunTLS("10.8.0.2:8443", os.Getenv("SSLPUBLIC"), os.Getenv("SSLPRIVATE"))
	err = router.Run("0.0.0.0:8443")
	if err != nil {
		log.Printf("server error: %v", err)
		panic(err)
	}
}
