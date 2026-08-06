// Package httpx keeps the response and error shape identical across every handler.
// It is the only cross-cutting package in the project on purpose: anything else
// becomes a dumping ground for helpers nobody owns.
package httpx

import "github.com/gin-gonic/gin"

// Response is the only JSON shape the API ever returns.
// Code 0 means success; on failure Code mirrors the HTTP status.
type Response struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// OK writes data with the success envelope.
func OK(c *gin.Context, data any) {
	c.JSON(200, Response{Code: 0, Message: "ok", Data: data})
}
