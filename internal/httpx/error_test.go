package httpx

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestNewErrorCarriesStatus(t *testing.T) {
	e := NewError(http.StatusTeapot, "teapot")
	if e.Status != http.StatusTeapot || e.Error() != "teapot" {
		t.Fatalf("NewError = %+v", e)
	}
}

// A 500 must leave a trace: the response body says nothing, so the log is the
// only way to find out what happened.
func TestServerErrorIsLogged(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var logs bytes.Buffer
	restore := captureDefaultLogger(t, &logs)
	defer restore()

	engine := NewEngine(discardLogger())
	engine.GET("/boom", func(c *gin.Context) {
		_ = c.Error(errSecret)
	})

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	out := logs.String()
	if !strings.Contains(out, "/boom") || !strings.Contains(out, errSecret.Error()) {
		t.Fatalf("log does not carry the request path and cause: %q", out)
	}
	// The client still learns nothing.
	if strings.Contains(rec.Body.String(), errSecret.Error()) {
		t.Fatalf("error text leaked into the response: %s", rec.Body.String())
	}
}

// 4xx are client mistakes and must not flood the error log.
func TestClientErrorIsNotLogged(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var logs bytes.Buffer
	restore := captureDefaultLogger(t, &logs)
	defer restore()

	engine := NewEngine(discardLogger())
	engine.GET("/nope", func(c *gin.Context) {
		_ = c.Error(ErrNotFound)
	})

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("404 was logged as an error: %q", logs.String())
	}
}

// captureDefaultLogger points the process logger at buf, since Fail reports
// through slog.Default the same way healthz does.
func captureDefaultLogger(t *testing.T, buf *bytes.Buffer) func() {
	t.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return func() { slog.SetDefault(prev) }
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
