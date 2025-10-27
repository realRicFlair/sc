package auth

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"net/url"
	"time"
)

// return AuthError = errors.New("Unauthorized")

func Authorize() gin.HandlerFunc {
	return func(context *gin.Context) {
		context.Set("authorized", false)

		/*
			username := context.GetHeader()
			user, user_exists := Users[username]
			if !user_exists {
				context.AbortWithStatus(http.StatusUnauthorized)
				return
			}
		*/
		sessionToken, err := context.Cookie("session_token")
		if err != nil || sessionToken == "" || sessionToken != Sessions[sessionToken].SessionToken {
			context.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// Get CSRF token from the headers
		rawcsrf := context.GetHeader("X-CSRF-TOKEN")
		csrf, _ := url.QueryUnescape(rawcsrf)
		if csrf == "" || csrf != Sessions[sessionToken].CSRFToken {
			println("CSRF token error: ", csrf, " ", Sessions[sessionToken].CSRFToken, "")
			context.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		user := Sessions[sessionToken].user

		context.Set("username", user.Username)
		context.Set("userid", user.UserID)
		context.Set("authorized", true)
	}
}

func SessionCheckHandler(context *gin.Context) {
	// Get session token from cookie
	sessionToken, err := context.Cookie("session_token")
	if err != nil || sessionToken == "" {
		context.JSON(http.StatusUnauthorized, gin.H{
			"authenticated": false,
			"message":       "No session token found",
		})
		return
	}

	// Check if session exists and is valid
	session, exists := Sessions[sessionToken]
	if !exists {
		context.JSON(http.StatusUnauthorized, gin.H{
			"authenticated": false,
			"message":       "Invalid session token",
		})
		return
	}

	// Check if session has expired
	if time.Now().After(session.expiryTime) {
		// Clean up expired session
		delete(Sessions, sessionToken)
		context.JSON(http.StatusUnauthorized, gin.H{
			"authenticated": false,
			"message":       "Session expired",
		})
		return
	}

	// Session is valid
	context.JSON(http.StatusOK, gin.H{
		"authenticated": true,
		"username":      session.user.Username,
		"email":         session.user.Email,
		"userID":        session.user.UserID,
		"message":       "User is authenticated",
	})
}
