package argon2

import (
	"errors"
)

// Various errors returned by the library
var (
	ErrIncorrectType      = errors.New("argon2: Invalid type passed (must be either Argon2i or Argon2d)")
	ErrIncorrectParameter = errors.New("argon2: Incorrect parameter passed to the argon function")
	ErrOutputPtrNull      = errors.New("argon2: Output must be an allocated slice")
	ErrOutputTooShort     = errors.New("argon2: Output is too short")
	ErrOutputTooLong      = errors.New("argon2: Output is too long")
	ErrPwdTooShort        = errors.New("argon2: Password is too short")
	ErrPwdTooLong         = errors.New("argon2: Password is too long")
	ErrSaltTooShort       = errors.New("argon2: Salt is too short")
	ErrSaltTooLong        = errors.New("argon2: Salt is too long")
	ErrSecretTooShort     = errors.New("argon2: Secret is too short")
	ErrSecretTooLong      = errors.New("argon2: Secret is too long")
	ErrADTooShort         = errors.New("argon2: Additional data is too short")
	ErrADTooLong          = errors.New("argon2: Additional data is too long")
	ErrMemoryTooLittle    = errors.New("argon2: Too little memory passed")
	ErrMemoryTooMuch      = errors.New("argon2: Too much memory passed")
	ErrTimeTooSmall       = errors.New("argon2: Time cost too small")
	ErrTimeTooLarge       = errors.New("argon2: Time cost too high")
	ErrLanesTooFew        = errors.New("argon2: Too few lanes")
	ErrLanesTooMany       = errors.New("argon2: Too many lanes")
	ErrThreadsTooFew      = errors.New("argon2: Too few threads")
	ErrThreadsTooMany     = errors.New("argon2: Too many threads")
	ErrThreadFail         = errors.New("argon2: Thread failed")
)
