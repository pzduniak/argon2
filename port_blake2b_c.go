package argon2

import (
	"encoding/binary"

	"github.com/dchest/blake2b"
)

const (
	BLAKE2B_BLOCKBYTES    = 128
	BLAKE2B_OUTBYTES      = 64
	BLAKE2B_KEYBYTES      = 64
	BLAKE2B_SALTBYTES     = 16
	BLAKE2B_PERSONALBYTES = 16
)

func blake2b_long(out []byte, in []byte) error {
	outlen_bytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(outlen_bytes, uint32(len(out)))

	if len(out) < BLAKE2B_OUTBYTES {
		hash, err := blake2b.New(&blake2b.Config{
			Size: uint8(len(out)),
		})
		if err != nil {
			return err
		}

		hash.Write(outlen_bytes)
		hash.Write(in)
		sum := hash.Sum(nil)
		copy(out, sum)
		return nil
	}

	var (
		toproduce uint32
		//out_buffer [BLAKE2B_OUTBYTES]byte
		in_buffer [BLAKE2B_OUTBYTES]byte
	)

	hash, err := blake2b.New(&blake2b.Config{
		Size: BLAKE2B_OUTBYTES,
	})
	if err != nil {
		return err
	}

	hash.Write(outlen_bytes)
	hash.Write(in)
	sum := hash.Sum(nil)
	copy(out, sum[:BLAKE2B_OUTBYTES/2])
	out = out[BLAKE2B_OUTBYTES:]
	toproduce = uint32(len(out)) + BLAKE2B_OUTBYTES/2

	for toproduce > BLAKE2B_OUTBYTES {
		copy(in_buffer[:], sum)
		hash.Reset()
		hash.Write(in_buffer[:])
		sum = hash.Sum(nil)
		copy(out, sum[:BLAKE2B_OUTBYTES/2])
		out = out[BLAKE2B_OUTBYTES:]
		toproduce -= BLAKE2B_OUTBYTES
	}

	copy(in_buffer[:], sum[:BLAKE2B_OUTBYTES])
	hash, err = blake2b.New(&blake2b.Config{
		Size: uint8(toproduce),
	})
	if err != nil {
		return err
	}
	hash.Write(in_buffer[:])
	sum = hash.Sum(nil)
	copy(out, sum)

	return nil
}
