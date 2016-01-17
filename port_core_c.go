package argon2

import (
	"encoding/binary"

	"github.com/dchest/blake2b"
)

func validateInputs(ctx *context) error {
	if ctx == nil {
		return ErrIncorrectParameter
	}

	if ctx.out == nil {
		return ErrOutputPtrNull
	}

	if len(ctx.out) < minOutlen {
		return ErrOutputTooShort
	}

	if len(ctx.out) > maxOutlen {
		return ErrOutputTooLong
	}

	if ctx.pwd != nil {
		if len(ctx.pwd) < minPasswordLength {
			return ErrPwdTooShort
		}

		if len(ctx.pwd) > maxPasswordLength {
			return ErrPwdTooLong
		}
	}

	if ctx.salt != nil {
		if len(ctx.salt) < minSaltLength {
			return ErrSaltTooShort
		}

		if len(ctx.salt) > maxSaltLength {
			return ErrSaltTooLong
		}
	}

	if ctx.ad != nil {
		if len(ctx.ad) < minADLength {
			return ErrADTooShort
		}

		if len(ctx.ad) > maxADLength {
			return ErrADTooLong
		}
	}

	// Validate memory cost
	if ctx.memoryCost < minMemory {
		return ErrMemoryTooLittle
	}
	if ctx.memoryCost > maxMemory {
		return ErrMemoryTooMuch
	}
	if ctx.memoryCost < 8*ctx.lanes {
		return ErrMemoryTooLittle
	}

	// Validate time cost
	if ctx.timeCost < minTime {
		return ErrTimeTooSmall
	}
	if ctx.timeCost > maxTime {
		return ErrTimeTooLarge
	}

	// Validate lanes
	if ctx.lanes < minLanes {
		return ErrLanesTooFew
	}
	if ctx.lanes > maxLanes {
		return ErrLanesTooMany
	}

	// Validate threads
	if ctx.threads < minThreads {
		return ErrThreadsTooFew
	}
	if ctx.threads > maxThreads {
		return ErrThreadsTooMany
	}

	return nil
}

func initialize(ins *instance, ctx *context) error {
	if ins == nil || ctx == nil {
		return ErrIncorrectParameter
	}

	/* 1. Memory allocation */
	ins.memory = []block{}
	for i := uint32(0); i < ins.memoryBlocks; i++ {
		ins.memory = append(ins.memory, block{})
	}

	/* 2. Initial hashing */
	// H_0 + 8 extra bytes to produce the first blocks
	blockhash := [prehashSeedLength]byte{}

	// Hash all inputs
	if err := initialHash(&blockhash, ctx, ins.variant); err != nil {
		return err
	}

	// Zero 8 extra bytes
	secureWipeMemory(blockhash[prehashDigestLength:prehashSeedLength])

	/* 3. Creating first blocks, we always have at least two blocks in a slice */
	fillFirstBlocks(&blockhash, ins)

	/* Clearing the hash */
	secureWipeMemory(blockhash[:])

	return nil
}

func initialHash(blockhash *[prehashSeedLength]byte, ctx *context, variant Variant) error {
	state, err := blake2b.New(&blake2b.Config{
		Size: prehashDigestLength,
	})
	if err != nil {
		return err
	}

	value := make([]byte, 4) // 32-bit expressed in 4xuint8

	binary.LittleEndian.PutUint32(value, ctx.lanes)
	state.Write(value)

	binary.LittleEndian.PutUint32(value, uint32(len(ctx.out)))
	state.Write(value)

	binary.LittleEndian.PutUint32(value, ctx.memoryCost)
	state.Write(value)

	binary.LittleEndian.PutUint32(value, ctx.timeCost)
	state.Write(value)

	binary.LittleEndian.PutUint32(value, versionNumber)
	state.Write(value)

	binary.LittleEndian.PutUint32(value, uint32(variant))
	state.Write(value)

	binary.LittleEndian.PutUint32(value, uint32(len(ctx.pwd)))
	state.Write(value)
	if ctx.pwd != nil {
		state.Write(ctx.pwd)
		if ctx.flags&FlagClearPassword != 0 {
			secureWipeMemory(ctx.pwd)
			ctx.pwd = nil
		}
	}

	binary.LittleEndian.PutUint32(value, uint32(len(ctx.salt)))
	state.Write(value)
	if ctx.salt != nil {
		state.Write(ctx.salt)
	}

	binary.LittleEndian.PutUint32(value, uint32(len(ctx.secret)))
	state.Write(value)
	if ctx.secret != nil {
		state.Write(ctx.secret)
		if ctx.flags&FlagClearSecret != 0 {
			secureWipeMemory(ctx.secret)
			ctx.secret = nil
		}
	}

	binary.LittleEndian.PutUint32(value, uint32(len(ctx.ad)))
	state.Write(value)
	if ctx.ad != nil {
		state.Write(ctx.ad)
	}

	result := state.Sum(nil)
	for i, v := range result {
		blockhash[i] = v
	}

	return nil
}

func secureWipeMemory(input []byte) {
	for i := range input {
		input[i] = 0
	}
}

func secureWipeMemoryUint64(input []uint64) {
	for i := range input {
		input[i] = 0
	}
}

func fillFirstBlocks(blockhash *[prehashSeedLength]byte, ins *instance) error {
	blockhashBytes := make([]byte, blockSize)
	for l := uint32(0); l < ins.lanes; l++ {
		binary.LittleEndian.PutUint32(blockhash[prehashDigestLength:], 0)
		binary.LittleEndian.PutUint32(blockhash[prehashDigestLength+4:], l)
		if err := blakeLong(blockhashBytes, blockhash[:]); err != nil {
			return err
		}
		loadBlock(&ins.memory[l*ins.laneLength], blockhashBytes)

		binary.LittleEndian.PutUint32(blockhash[prehashDigestLength:], 1)
		if err := blakeLong(blockhashBytes, blockhash[:]); err != nil {
			return err
		}
		loadBlock(&ins.memory[l*ins.laneLength+1], blockhashBytes)
	}
	secureWipeMemory(blockhashBytes)
	return nil
}

func loadBlock(dst *block, input []byte) {
	for i := 0; i < qwordsInBlock; i++ {
		dst[i] = binary.LittleEndian.Uint64(input[i*8:])
	}
}

func storeBlock(output []byte, src *block) {
	for i := 0; i < qwordsInBlock; i++ {
		binary.LittleEndian.PutUint64(output[i*8:], src[i])
	}
}

func indexAlpha(ins *instance, pos *position, pseudoRand uint32, sameLane bool) uint32 {
	/*
	 * Pass 0:
	 *      This lane : all already finished segments plus already constructed
	 * blocks in this segment
	 *      Other lanes : all already finished segments
	 * Pass 1+:
	 *      This lane : (SYNC_POINTS - 1) last segments plus already constructed
	 * blocks in this segment
	 *      Other lanes : (SYNC_POINTS - 1) last segments
	 */
	var (
		referenceAreaSize               uint32
		relativePosition                uint64
		startPosition, absolutePosition uint32
	)

	if pos.pass == 0 {
		/* First pass */
		if pos.slice == 0 {
			/* First slice */
			referenceAreaSize =
				pos.index - 1 /* all but the previous */
		} else {
			if sameLane {
				/* The same lane => add current segment */
				referenceAreaSize =
					uint32(pos.slice)*ins.segmentLength +
						pos.index - 1
			} else {
				referenceAreaSize =
					uint32(pos.slice) * ins.segmentLength

				if pos.index == 0 {
					referenceAreaSize--
				}
			}
		}
	} else {
		/* Second pass */
		if sameLane {
			referenceAreaSize = ins.laneLength -
				ins.segmentLength + pos.index -
				1
		} else {
			referenceAreaSize = ins.laneLength -
				ins.segmentLength

			if pos.index == 0 {
				referenceAreaSize--
			}
		}
	}

	/* 1.2.4. Mapping pseudoRand to 0..<referenceAreaSize-1> and produce
	 * relative position */
	relativePosition = uint64(pseudoRand)
	relativePosition = relativePosition * relativePosition >> 32
	relativePosition = uint64(referenceAreaSize) - 1 -
		(uint64(referenceAreaSize) * relativePosition >> 32)

	/* 1.2.5 Computing starting position */
	startPosition = 0

	if pos.pass != 0 {
		if pos.slice == syncPoints-1 {
			startPosition = 0
		} else {
			startPosition = (uint32(pos.slice) + 1) * ins.segmentLength
		}
	}

	/* 1.2.6. Computing absolute position */
	absolutePosition = (startPosition + uint32(relativePosition)) %
		ins.laneLength /* absolute position */
	return absolutePosition
}

func clearMemory(ins *instance, clear bool) {
	if ins.memory != nil && clear {
		for _, b := range ins.memory {
			for i := range b {
				b[i] = 0
			}
		}
	}
}
