package auth

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"time"
)

type User struct {
	Email    string
	Username string
	Password string
	UserID   string
}
type Session struct {
	SessionToken string
	CSRFToken    string
	expiryTime   time.Time
	user         *User
}

// hashtable to store the uesrs logged in curently
var Sessions = map[string]Session{}
var Users = map[string]*User{} // map of pointers to user obj's

func RegisterHandler(context *gin.Context) {
	email := context.PostForm("email")
	username := context.PostForm("username")
	password := context.PostForm("password")
	if len(email) < 8 || len(password) < 8 {
		er := http.StatusNotAcceptable
		http.Error(context.Writer, http.StatusText(er), er)
		return
	}

	if _, ok := Users[email]; ok {
		er := http.StatusConflict
		http.Error(context.Writer, http.StatusText(er), er)
		return
	}

	hashedPassword, err := hashPassword(password)
	checkError(err)
	Users[email] = &User{
		Email:    email,
		Username: username,
		Password: hashedPassword,
		UserID:   "1",
	}
	context.JSON(http.StatusOK, gin.H{
		"message": "User created successfully",
	})
	fmt.Println("User created successfully: ", Users[email].Username, Users[email].Password)
}

func LoginHandler(context *gin.Context) {
	email := context.PostForm("email")
	password := context.PostForm("password")
	if len(email) < 8 || len(password) < 8 {
		er := http.StatusNotAcceptable
		http.Error(context.Writer, http.StatusText(er), er)
		return
	}
	_, userExist := Users[email]
	if !userExist {
		er := http.StatusNotFound
		http.Error(context.Writer, http.StatusText(er), er)
		return
	}

	if !checkPasswordHash(password, Users[email].Password) {
		er := http.StatusUnauthorized
		http.Error(context.Writer, http.StatusText(er), er)
		return
	}

	log.Printf("User logged in successfully: %s", email)

	sessionToken := generateToken(32)
	csrfToken := generateToken(32)

	context.SetCookie("session_token", sessionToken, 3600, "/", "rorocorp.org", false, true)
	context.SetCookie("csrf_token", csrfToken, 3600, "/", "rorocorp.org", false, false)

	context.SetCookie("session_token", sessionToken, 3600, "/", "localhost", false, true)
	context.SetCookie("csrf_token", csrfToken, 3600, "/", "localhost", false, false)
	//max age is how many seconds it remains active. Not the time

	Sessions[sessionToken] = Session{
		SessionToken: sessionToken,
		user:         Users[email],
		CSRFToken:    csrfToken,
		expiryTime:   time.Now().Add(24 * time.Hour),
	}

	context.JSON(http.StatusOK, gin.H{
		"message": "User logged in successfully",
	})
}

func checkError(err error) {
	if err != nil {
		log.Printf("Error: %v", err)
	}
}
