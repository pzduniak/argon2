package argon2_test

import (
	"testing"

	magic "github.com/magical/argon2"
	conv "github.com/pzduniak/argon2"
)

func BenchmarkMConversion(b *testing.B) {
	for n := 0; n < b.N; n++ {
		conv.Key(password, salt, 3, 4, 4096, 32, conv.Argon2d)
	}
}

func BenchmarkMMagical(b *testing.B) {
	for n := 0; n < b.N; n++ {
		magic.Key(password, salt, 3, 4, 4096, 32)
	}
}
