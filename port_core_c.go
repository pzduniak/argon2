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
	if err := initial_hash(&blockhash, ctx, ins.variant); err != nil {
		return err
	}

	// Zero 8 extra bytes
	secure_wipe_memory(blockhash[prehashDigestLength:prehashSeedLength])

	/* 3. Creating first blocks, we always have at least two blocks in a slice */
	fill_first_blocks(&blockhash, ins)

	/* Clearing the hash */
	secure_wipe_memory(blockhash[:])

	return nil
}

func initial_hash(blockhash *[prehashSeedLength]byte, ctx *context, variant Variant) error {
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

	binary.LittleEndian.PutUint32(value, ARGON2_VERSION_NUMBER)
	state.Write(value)

	binary.LittleEndian.PutUint32(value, uint32(variant))
	state.Write(value)

	binary.LittleEndian.PutUint32(value, uint32(len(ctx.pwd)))
	state.Write(value)
	if ctx.pwd != nil {
		state.Write(ctx.pwd)
		if ctx.flags&FlagClearPassword != 0 {
			secure_wipe_memory(ctx.pwd)
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
			secure_wipe_memory(ctx.secret)
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

func secure_wipe_memory(input []byte) {
	for i, _ := range input {
		input[i] = 0
	}
}

func secure_wipe_memory_uint64(input []uint64) {
	for i, _ := range input {
		input[i] = 0
	}
}

func fill_first_blocks(blockhash *[prehashSeedLength]byte, ins *instance) error {
	blockhash_bytes := make([]byte, blockSize)
	for l := uint32(0); l < ins.lanes; l++ {
		binary.LittleEndian.PutUint32(blockhash[prehashDigestLength:], 0)
		binary.LittleEndian.PutUint32(blockhash[prehashDigestLength+4:], l)
		if err := blakeLong(blockhash_bytes, blockhash[:]); err != nil {
			return err
		}
		load_block(&ins.memory[l*ins.laneLength], blockhash_bytes)

		binary.LittleEndian.PutUint32(blockhash[prehashDigestLength:], 1)
		if err := blakeLong(blockhash_bytes, blockhash[:]); err != nil {
			return err
		}
		load_block(&ins.memory[l*ins.laneLength+1], blockhash_bytes)
	}
	secure_wipe_memory(blockhash_bytes)
	return nil
}

func load_block(dst *block, input []byte) {
	for i := 0; i < qwordsInBlock; i++ {
		dst[i] = binary.LittleEndian.Uint64(input[i*8:])
	}
}

func store_block(output []byte, src *block) {
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
		reference_area_size               uint32
		relative_position                 uint64
		start_position, absolute_position uint32
	)

	if pos.pass == 0 {
		/* First pass */
		if pos.slice == 0 {
			/* First slice */
			reference_area_size =
				pos.index - 1 /* all but the previous */
		} else {
			if sameLane {
				/* The same lane => add current segment */
				reference_area_size =
					uint32(pos.slice)*ins.segmentLength +
						pos.index - 1
			} else {
				reference_area_size =
					uint32(pos.slice) * ins.segmentLength

				if pos.index == 0 {
					reference_area_size -= 1
				}
			}
		}
	} else {
		/* Second pass */
		if sameLane {
			reference_area_size = ins.laneLength -
				ins.segmentLength + pos.index -
				1
		} else {
			reference_area_size = ins.laneLength -
				ins.segmentLength

			if pos.index == 0 {
				reference_area_size -= 1
			}
		}
	}

	/* 1.2.4. Mapping pseudoRand to 0..<reference_area_size-1> and produce
	 * relative position */
	relative_position = uint64(pseudoRand)
	relative_position = relative_position * relative_position >> 32
	relative_position = uint64(reference_area_size) - 1 -
		(uint64(reference_area_size) * relative_position >> 32)

	/* 1.2.5 Computing starting position */
	start_position = 0

	if pos.pass != 0 {
		if pos.slice == syncPoints-1 {
			start_position = 0
		} else {
			start_position = (uint32(pos.slice) + 1) * ins.segmentLength
		}
	}

	/* 1.2.6. Computing absolute position */
	absolute_position = (start_position + uint32(relative_position)) %
		ins.laneLength /* absolute position */
	return absolute_position
}

func clearMemory(ins *instance, clear bool) {
	if ins.memory != nil && clear {
		for _, b := range ins.memory {
			for i, _ := range b {
				b[i] = 0
			}
		}
	}
}
