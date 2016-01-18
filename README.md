# argon2

Go conversion of the [libargon2](https://github.com/P-H-C/phc-winner-argon2)
library. Exports a simple API with only several features. Unwrapped round
function is taken from [magical/argon2](https://github.com/magical/argon2),
licensed under the MIT license.

Please note: due to the nature of the conversion, its performance might be lower
than of [the bindings](https://github.com/tvdburgt/go-argon2). Also the memory 
clearing is NOT ported and depends on the GC.

## Installation

```bash
go get github.com/pzduniak/argon2
```

## Performance compared to bindings

Tests were ran on a 2015 Macbook Pro Retina 15". The conversion is ~3.5 times
slower. 

```
➜  argon2 git:(master) ✗ go test -bench=.
testing: warning: no tests to run
PASS
BenchmarkBConversion	     100	  14687543 ns/op	 4318704 B/op	     351 allocs/op
BenchmarkBBindings  	     300	   4093711 ns/op	     320 B/op	       3 allocs/op
BenchmarkMConversion	     100	  14622942 ns/op	 4318704 B/op	     351 allocs/op
BenchmarkMMagical   	     100	  14668521 ns/op	 4196464 B/op	       7 allocs/op
ok  	github.com/pzduniak/argon2	6.099s
```

## Usage

```go
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/pzduniak/argon2"
)

func main() {
	var (
		password = []byte("password")
		salt     = []byte("testsalt123")
	)

	output, err := argon2.Key(password, salt, 3, 4, 4096, 32, argon2.Argon2i)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(hex.EncodeToString(output))
}
```
