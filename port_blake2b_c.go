package argon2

import (
	"encoding/binary"

	"github.com/dchest/blake2b"
)

const (
	blakeOutBytes = 64
)

func blakeLong(out []byte, in []byte) error {
	var (
		outlen      = len(out)
		outlenBytes = make([]byte, 4)
	)
	binary.LittleEndian.PutUint32(outlenBytes, uint32(outlen))

	if len(out) <= blakeOutBytes {
		hash, err := blake2b.New(&blake2b.Config{
			Size: uint8(outlen),
		})
		if err != nil {
			return err
		}

		if _, err := hash.Write(outlenBytes); err != nil {
			return err
		}
		if _, err := hash.Write(in); err != nil {
			return err
		}
		sum := hash.Sum(nil)
		copy(out, sum)
		return nil
	}

	var (
		toProduce uint32
		buffer    [blakeOutBytes]byte
	)

	hash, err := blake2b.New(&blake2b.Config{
		Size: blakeOutBytes,
	})
	if err != nil {
		return err
	}

	if _, err = hash.Write(outlenBytes); err != nil {
		return err
	}
	if _, err = hash.Write(in); err != nil {
		return err
	}
	sum := hash.Sum(nil)
	copy(out, sum[:blakeOutBytes/2])
	out = out[blakeOutBytes/2:]
	toProduce = uint32(outlen) - blakeOutBytes/2

	for toProduce > blakeOutBytes {
		copy(buffer[:], sum)
		hash.Reset()
		if _, err = hash.Write(buffer[:]); err != nil {
			return err
		}
		sum = hash.Sum(nil)
		copy(out, sum[:blakeOutBytes/2])
		out = out[blakeOutBytes/2:]
		toProduce -= blakeOutBytes / 2
	}

	copy(buffer[:], sum[:blakeOutBytes])
	hash, err = blake2b.New(&blake2b.Config{
		Size: uint8(toProduce),
	})
	if err != nil {
		return err
	}
	if _, err = hash.Write(buffer[:]); err != nil {
		return err
	}
	sum = hash.Sum(nil)
	copy(out, sum)

	return nil
}
