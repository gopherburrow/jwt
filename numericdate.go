package jwt

import (
	"time"
)

func NumericDate(t time.Time) int64 {
	return int64(t.Sub(time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC)).Seconds())
}
