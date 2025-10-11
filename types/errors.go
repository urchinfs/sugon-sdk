package types

import "errors"

var (
	ErrorInvalidParameter = errors.New("invalid parameters")
	ErrorNotExists        = errors.New("not exists")
)
