package util

import (
	logger "github.com/urchinfs/sugon-sdk/dflog"
	"net/http"
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

func LoopDoRequest(f func() (response *http.Response, err error)) (*http.Response, error) {
	response, err := f()
	//处理请求频次限制问题
	retryCount := 0
	for {
		if err == nil {
			break
		}
		retryCount += 1
		logger.Errorf("starlight---client do request error=%s retryCount=%d", err.Error(), retryCount)
		if retryCount <= 20 {
			time.Sleep(time.Duration(3) * time.Second)
		} else if retryCount <= 360+20 {
			time.Sleep(time.Duration(10) * time.Second)
		} else if retryCount <= 24*120+360+20 {
			time.Sleep(time.Duration(30) * time.Second)
		} else if retryCount <= 7*24*60+24*120+360+20 {
			time.Sleep(time.Duration(60) * time.Second)
		} else {
			break
		}
		response, err = f()
	}
	return response, err
}
