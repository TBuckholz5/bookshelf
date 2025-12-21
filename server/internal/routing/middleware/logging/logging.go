package logging

import (
	"log"
	"net/http"
)

type LoggingMiddleware struct{}

func NewLoggingMiddleware() *LoggingMiddleware {
	return &LoggingMiddleware{}
}

func (l *LoggingMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		log.Default().Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
	})
}
