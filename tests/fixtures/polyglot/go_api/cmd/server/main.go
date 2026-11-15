package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"example.com/shop/internal/handlers"
)

func main() {
	h := handlers.NewHandler(nil)
	r := gin.Default()
	r.GET("/users/search", h.SearchUsers)
	r.GET("/users/:id", h.GetUser)
	r.POST("/users/archive", h.Archive)
	r.GET("/users/lookup", h.Lookup)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /fetch", handlers.Fetch)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	_ = r.Run(":8080")
}
