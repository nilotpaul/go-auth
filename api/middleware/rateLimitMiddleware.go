package middleware

import (
	"net/http"

	"github.com/nilotpaul/go-auth/pkg"
	"github.com/nilotpaul/go-auth/utils"
)

type RateLimitMiddleware struct {
	RateLimiter *pkg.RateLimiter
}

func NewRateLimitMiddleware(RateLimiter *pkg.RateLimiter) *RateLimitMiddleware {
	return &RateLimitMiddleware{
		RateLimiter: RateLimiter,
	}
}

func (rl *RateLimitMiddleware) WithRateLimit(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userIP := r.RemoteAddr

		if len(userIP) == 0 {
			utils.WriteJSON(w, http.StatusForbidden, "request blocked")
			return
		}

		if !rl.RateLimiter.Allow(userIP) {
			utils.WriteJSON(w, http.StatusTooManyRequests, "too many requests")
			return
		}
	})
}
