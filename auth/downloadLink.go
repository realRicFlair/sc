package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"net/url"
	"os"
	"time"
)

func GenerateDownloadLink(c *gin.Context) {
	sessionToken, _ := c.Cookie("session_token")
	user := Sessions[sessionToken].user
	filepath := c.Query("filepath")

	exp := time.Now().Add(30 * time.Second)
	sig := SignDownload(filepath, user.UserID, exp)

	link := fmt.Sprintf("https://apisc.rorocorp.org/api/dlink/download?fp=%s&u=%s&exp=%d&sig=%s",
		url.QueryEscape(filepath), user.UserID, exp.Unix(), sig)

	c.JSON(http.StatusOK, gin.H{"url": link})
}

func SignDownload(filepath string, userID string, exp time.Time) string {
	println("SignDownload: ", filepath, userID, exp.Unix())
	secret := []byte(os.Getenv("SIGN_SECRET"))
	message := fmt.Sprintf("%s|%s|%d", filepath, userID, exp.Unix())
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}
