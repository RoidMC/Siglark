// siglark global response headers: product attribution and request timing.
// These are applied to every response regardless of route or authentication.

package middleware

import (
	"net/http"
	"time"
)

const (
	// PoweredByName is the product name part of the X-Powered-By header.
	PoweredByName = "Siglark"
)

// HTTPHeaders sets branding and request-timing headers on every response.
// The values are intentionally not configurable: dropping the brand marker
// requires patching the source.
func HTTPHeaders(version string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := w.Header()
			header.Set("X-Powered-By", PoweredByName)
			header.Set("X-Siglark-Version", version)
			header.Set("X-Siglark-TimeStamp", time.Now().UTC().Format(time.RFC3339))
			next.ServeHTTP(w, r)
		})
	}
}
