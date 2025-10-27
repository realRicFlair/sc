package auth

import (
	"crypto/rand"
	"encoding/base64"
	"golang.org/x/crypto/bcrypt"
	"time"
)

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10) //Cost vector controll
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateToken(length int) string {
	arr := make([]byte, length)
	rand.Read(arr)
	return base64.URLEncoding.EncodeToString(arr)
}

func (s Session) IsExpired() bool {
	return s.expiryTime.Before(time.Now())
}
