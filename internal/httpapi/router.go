package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

type Dependencies struct {
	Version string
	Ready   func() error
}

func NewRouter(deps Dependencies) http.Handler {
	if deps.Ready == nil {
		deps.Ready = func() error { return nil }
	}

	router := chi.NewRouter()
	router.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"status":  "ok",
			"version": deps.Version,
		})
	})
	router.Get("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if err := deps.Ready(); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	return router
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
