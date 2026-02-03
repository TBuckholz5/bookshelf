package routing

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/TBuckholz5/bookshelf/internal/routing/middleware"
)

type Config struct {
	Mux         *http.ServeMux
	Handler     http.Handler
	Middlewares []middleware.Middleware
	Route       string
	Method      string
	GroupRoute  string
}

func RegisterRoute(config Config) {
	handler := config.Handler
	for _, mw := range config.Middlewares {
		handler = mw.Wrap(handler)
	}

	config.Mux.Handle(fmt.Sprintf("%s %s", config.Method, config.Route), handler)
}

func RegisterRouterGroup(config Config) *http.ServeMux {
	mux := http.NewServeMux()
	handler := http.StripPrefix(strings.TrimSuffix(config.GroupRoute, "/"), mux)
	for _, mw := range config.Middlewares {
		handler = mw.Wrap(handler)
	}

	config.Mux.Handle(config.GroupRoute, handler)
	return mux
}
