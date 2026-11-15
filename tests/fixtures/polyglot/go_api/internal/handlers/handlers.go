package handlers

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
	"strconv"

	"github.com/gin-gonic/gin"
)

type UserStore struct {
	db *sql.DB
}

type Handler struct {
	store *UserStore
}

func NewHandler(store *UserStore) *Handler {
	return &Handler{store: store}
}

type searchRequest struct {
	Term string `json:"term"`
}

// VULNERABLE: SQL built with fmt.Sprintf from a query parameter.
func (h *Handler) SearchUsers(c *gin.Context) {
	name := c.Query("name")
	rows, err := h.store.db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	c.Status(http.StatusOK)
}

// SAFE: placeholder query; numeric conversion.
func (h *Handler) GetUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	row := h.store.db.QueryRow("SELECT name FROM users WHERE id = $1", id)
	_ = row
	c.Status(http.StatusOK)
}

// VULNERABLE: command injection via bound JSON body.
func (h *Handler) Archive(c *gin.Context) {
	var req searchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		return
	}
	out, _ := exec.Command("sh", "-c", "tar czf /tmp/archive.tgz "+req.Term).Output()
	c.Data(http.StatusOK, "application/gzip", out)
}

// VULNERABLE: SSRF in a plain net/http handler.
func Fetch(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	resp, err := http.Get(target)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

func Checksum(data []byte) [16]byte {
	// VULNERABLE: weak hash.
	return md5.Sum(data)
}

func InsecureClient() *http.Client {
	// VULNERABLE: TLS verification disabled.
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
}
