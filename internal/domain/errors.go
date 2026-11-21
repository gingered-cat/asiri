package domain

import (
	"errors"
	"fmt"
)

// Code is a stable error code shared by the API, the CLI and the docs.
type Code string

const (
	CodeInvalid         Code = "invalid"
	CodeUnauthenticated Code = "unauthenticated"
	CodeNotAllowed      Code = "not_allowed"
	CodeNotFound        Code = "not_found"
	CodeConflict        Code = "conflict"
	CodeSealed          Code = "sealed"
	CodeRateLimited     Code = "rate_limited"
	CodeInterpreter     Code = "interpreter_refused"
	CodeDenied          Code = "denied"
	CodeExpired         Code = "expired"
	CodeSpent           Code = "spent"
	CodeRevoked         Code = "revoked"
	CodeInternal        Code = "internal"
)

// Error is an error the person or agent is meant to read.
type Error struct {
	Code Code
	Msg  string
}

func (e *Error) Error() string { return string(e.Code) + ": " + e.Msg }

func Errorf(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// CodeOf returns the code of the first *Error in err's chain, or CodeInternal.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return CodeInternal
}
