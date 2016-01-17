package argon2_test

import (
	"testing"

	conv "github.com/pzduniak/argon2"
	bind "github.com/tvdburgt/go-argon2"
)

var (
	password = []byte("test123")
	salt     = []byte("test123456")
)

func BenchmarkConversion(b *testing.B) {
	for n := 0; n < b.N; n++ {
		conv.Key(password, salt, 3, 4, 4096, 32, conv.Argon2i)
	}
}

func BenchmarkBindings(b *testing.B) {
	for n := 0; n < b.N; n++ {
		bc := bind.Context{
			Iterations:  3,
			Parallelism: 4,
			Memory:      4096,
			HashLen:     32,
			Mode:        bind.ModeArgon2i,
		}
		bc.Hash(password, salt)
	}
}
