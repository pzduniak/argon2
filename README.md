# argon2

Go conversion of the [libargon2](https://github.com/P-H-C/phc-winner-argon2)
library. Exports a simple API with only several features.

Please note: due to the nature of the conversion, its performance might be lower
than of [the bindings](https://github.com/tvdburgt/go-argon2). Also the memory 
clearing is NOT ported and depends on the GC.

## Installation

```bash
go get github.com/pzduniak/argon2
```

## Performance compared to bindings

Tests were ran on a 2015 Macbook Pro Retina 15". The conversion is ~4.2 times
slower. 

```
➜  argon2 git:(master) ✗ go test -bench=.
testing: warning: no tests to run
PASS
BenchmarkBConversion	     100	  17760196 ns/op
BenchmarkBBindings  	     300	   4136977 ns/op
BenchmarkMConversion	     100	  18320990 ns/op
BenchmarkMMagical   	     100	  15448272 ns/op
ok  	github.com/pzduniak/argon2	7.787s
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

	fmt.Println(strings.ToUpper(hex.EncodeToString(output)))
}
```
