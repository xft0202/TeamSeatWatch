package runtime

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func newStaticHandler(directory, route string) (http.Handler, error) {
	if directory == "" {
		return http.NotFoundHandler(), nil
	}
	info, err := os.Stat(directory)
	if err != nil {
		return nil, fmt.Errorf("stat static directory: %w", err)
	}
	if !info.IsDir() {
		return nil, errors.New("static path must be a directory")
	}
	files := os.DirFS(directory)
	assetHandler := http.StripPrefix(route+"/", http.FileServer(http.Dir(directory)))
	handler := http.NewServeMux()
	serveEntry := func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(directory, "index.html"))
	}
	handler.HandleFunc("GET "+route, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, route+"/", http.StatusPermanentRedirect)
	})
	handler.HandleFunc("GET "+route+"/{$}", serveEntry)
	handler.Handle("GET "+route+"/assets/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, route+"/")
		if !fs.ValidPath(name) {
			http.NotFound(w, r)
			return
		}
		info, err := fs.Stat(files, name)
		if err != nil || info.IsDir() {
			http.NotFound(w, r)
			return
		}
		assetHandler.ServeHTTP(w, r)
	}))
	// Non-asset GETs are client-side routes. Keep this explicit so a direct
	// navigation or refresh has the same behavior as in the development server.
	handler.HandleFunc("GET "+route+"/{path...}", serveEntry)
	return handler, nil
}
