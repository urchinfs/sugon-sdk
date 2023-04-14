package util

import (
	logger "github.com/urchinfs/sugon-sdk/dflog"
	"time"
)

func Run(initBackoff float64,
	maxBackoff float64,
	maxAttempts int,
	flag string,
	f func() (data any, cancel bool, err error)) (any, bool, error) {
	var (
		res    any
		cancel bool
		cause  error
	)
	for i := 0; i < maxAttempts; i++ {
		if i > 0 {
			time.Sleep(RandBackoffSeconds(initBackoff, maxBackoff, 2.0, i))
			logger.Infof("sugon&&&retry method=%s %s", flag, i)
		}

		res, cancel, cause = f()
		if cause == nil || cancel {
			break
		}
	}

	return res, cancel, cause
}
