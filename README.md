# argon2

Go conversion of the [libargon2](https://github.com/P-H-C/phc-winner-argon2)
library. Exports a simple API with only several features.

Please note: due to the nature of the conversion, its performance might be lower
than of [the bindings](https://github.com/tvdburgt/go-argon2). Also the memory 
clearing is NOT ported properly, it will be eventually fixed, but DO NOT rely
on this feature now.

## Installation

```bash
go get github.com/pzduniak/argon2
```

## Performance compared to bindings

Tests were ran on a 2015 Macbook Pro Retina 15"

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
