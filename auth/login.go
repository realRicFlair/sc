package auth

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

type Session struct {
	HashedPassword string
	SessionToken   string
	CSRFToken      string
	User           User
}

type User struct {
	Username string
	Password string
}

// hashtable to store the uesrs logged in curently
var LoggedInUsers = map[string]Session{}

func RegisterHandler(context *gin.Context) {
	username := context.PostForm("username")
	password := context.PostForm("password")
	if len(username) < 8 || len(password) < 8 {
		er := http.StatusNotAcceptable
		http.Error(context.Writer, http.StatusText(er), er)
		return
	}

}
