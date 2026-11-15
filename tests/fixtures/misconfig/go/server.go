package server

import (
	"math/rand"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/golang-jwt/jwt/v5"
)

func Setup() {
	// VULNERABLE: any origin + credentials.
	_ = cors.New(cors.Config{AllowAllOrigins: true, AllowCredentials: true})
	// SAFE: explicit origins.
	_ = cors.New(cors.Config{AllowOrigins: []string{"https://app.example"}, AllowCredentials: true})
}

func Claims(raw string) {
	// VULNERABLE: signature never checked.
	token, _, _ := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	_ = token
}

func SetSession(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    value,
		HttpOnly: false, // VULNERABLE
		Secure:   true,
	})
}

func NewOTP() int {
	otp := rand.Intn(999999) // VULNERABLE (OTP)
	return otp
}

func Jitter() int {
	return rand.Intn(100) // SAFE (not a security value)
}
