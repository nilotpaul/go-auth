package pkg

import (
	"sync"
	"time"
)

type RateLimiter struct {
	sync.Mutex
	userRequests map[string][]time.Time
	windowSize   time.Duration
	limit        int
}

func NewRateLimiter(limit int, windowSize time.Duration) *RateLimiter {
	return &RateLimiter{
		userRequests: make(map[string][]time.Time),
		windowSize:   windowSize,
		limit:        limit,
	}
}

func (rl *RateLimiter) Allow(userIP string) bool {
	rl.Lock()
	defer rl.Unlock()

	now := time.Now()
	windowStart := now.Add(-rl.windowSize)

	reqs := rl.userRequests[userIP]
	startIdx := 0

	for i, reqTime := range reqs {
		if !reqTime.Before(windowStart) {
			break
		}

		startIdx = i + 1
	}

	rl.userRequests[userIP] = reqs[startIdx:]

	if len(rl.userRequests[userIP]) < rl.limit {
		rl.userRequests[userIP] = append(rl.userRequests[userIP], now)
		return true
	}

	return false
}
