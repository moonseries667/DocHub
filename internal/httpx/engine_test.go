package httpx

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
)

var errSecret = errors.New("dial tcp 10.0.0.1:3306: connect: connection refused")

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) Response {
	t.Helper()
	var body Response
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not the unified shape: %v (body=%q)", err, rec.Body.String())
	}
	return body
}

func TestNoRouteUsesUnifiedShape(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := NewEngine(testLogger())

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	body := decode(t, rec)
	if body.Code != http.StatusNotFound || body.Message == "" {
		t.Fatalf("body = %+v, want code=404 with message", body)
	}
}

func TestHandlerErrorUsesUnifiedShape(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := NewEngine(testLogger())
	engine.GET("/boom", func(c *gin.Context) {
		_ = c.Error(NewError(http.StatusInternalServerError, "boom"))
	})

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	body := decode(t, rec)
	if body.Code != http.StatusInternalServerError || body.Message != "boom" {
		t.Fatalf("body = %+v, want code=500 message=boom", body)
	}
}

func TestPanicUsesUnifiedShape(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := NewEngine(testLogger())
	engine.GET("/panic", func(c *gin.Context) {
		var m map[string]int
		m["x"] = 1 // nil map write
	})

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panic", nil))

	body := decode(t, rec)
	if rec.Code != http.StatusInternalServerError || body.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d body = %+v, want unified 500", rec.Code, body)
	}
}

func TestPlainErrorIsNotLeaked(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := NewEngine(testLogger())
	engine.GET("/leak", func(c *gin.Context) {
		_ = c.Error(errSecret)
	})

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/leak", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if body := decode(t, rec); body.Message == errSecret.Error() {
		t.Fatalf("internal error text leaked to client: %q", body.Message)
	}
}
