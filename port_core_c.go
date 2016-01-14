package argon2

import (
	"encoding/binary"

	"github.com/dchest/blake2b"
)

func validate_inputs(ctx *argon2_context) error {
	if ctx == nil {
		return ErrIncorrectParameter
	}

	if ctx.out == nil {
		return ErrOutputPtrNull
	}

	if len(ctx.out) < ARGON2_MIN_OUTLEN {
		return ErrOutputTooShort
	}

	if len(ctx.out) > ARGON2_MAX_OUTLEN {
		return ErrOutputTooLong
	}

	if ctx.pwd != nil {
		if len(ctx.pwd) < ARGON2_MIN_PWD_LENGTH {
			return ErrPwdTooShort
		}

		if len(ctx.pwd) > ARGON2_MAX_PWD_LENGTH {
			return ErrPwdTooLong
		}
	}

	if ctx.salt != nil {
		if len(ctx.salt) < ARGON2_MIN_SALT_LENGTH {
			return ErrSaltTooShort
		}

		if len(ctx.salt) > ARGON2_MAX_SALT_LENGTH {
			return ErrSaltTooLong
		}
	}

	if ctx.ad != nil {
		if len(ctx.ad) < ARGON2_MIN_AD_LENGTH {
			return ErrADTooShort
		}

		if len(ctx.ad) > ARGON2_MAX_AD_LENGTH {
			return ErrADTooLong
		}
	}

	// Validate memory cost
	if ctx.m_cost < ARGON2_MIN_MEMORY {
		return ErrMemoryTooLittle
	}
	if ctx.m_cost > ARGON2_MAX_MEMORY {
		return ErrMemoryTooMuch
	}
	if ctx.m_cost < 8*ctx.lanes {
		return ErrMemoryTooLittle
	}

	// Validate time cost
	if ctx.t_cost < ARGON2_MIN_TIME {
		return ErrTimeTooSmall
	}
	if ctx.t_cost > ARGON2_MAX_TIME {
		return ErrTimeTooLarge
	}

	// Validate lanes
	if ctx.lanes < ARGON2_MIN_LANES {
		return ErrLanesTooFew
	}
	if ctx.lanes > ARGON2_MAX_LANES {
		return ErrLanesTooMany
	}

	// Validate threads
	if ctx.threads < ARGON2_MIN_THREADS {
		return ErrThreadsTooFew
	}
	if ctx.threads > ARGON2_MAX_THREADS {
		return ErrThreadsTooMany
	}

	return nil
}

func initialize(instance *argon2_instance, context *argon2_context) error {
	if instance == nil || context == nil {
		return ErrIncorrectParameter
	}

	/* 1. Memory allocation */
	instance.memory = []block{}
	for i := uint32(0); i < instance.memory_blocks; i++ {
		instance.memory = append(instance.memory, block{})
	}

	/* 2. Initial hashing */
	// H_0 + 8 extra bytes to produce the first blocks
	blockhash := [ARGON2_PREHASH_SEED_LENGTH]byte{}

	// Hash all inputs
	if err := initial_hash(&blockhash, context, instance.variant); err != nil {
		return err
	}

	// Zero 8 extra bytes
	secure_wipe_memory(blockhash[ARGON2_PREHASH_DIGEST_LENGTH:ARGON2_PREHASH_SEED_LENGTH])

	/* 3. Creating first blocks, we always have at least two blocks in a slice */
	fill_first_blocks(&blockhash, instance)

	/* Clearing the hash */
	secure_wipe_memory(blockhash[:])

	return nil
}

func initial_hash(blockhash *[ARGON2_PREHASH_SEED_LENGTH]byte, context *argon2_context, variant variant) error {
	state, err := blake2b.New(&blake2b.Config{
		Size: ARGON2_PREHASH_DIGEST_LENGTH,
	})
	if err != nil {
		return err
	}

	value := make([]byte, 4) // 32-bit expressed in 4xuint8

	binary.LittleEndian.PutUint32(value, context.lanes)
	state.Write(value)

	binary.LittleEndian.PutUint32(value, uint32(len(context.out)))
	state.Write(value)

	binary.LittleEndian.PutUint32(value, context.m_cost)
	state.Write(value)

	binary.LittleEndian.PutUint32(value, context.t_cost)
	state.Write(value)

	binary.LittleEndian.PutUint32(value, ARGON2_VERSION_NUMBER)
	state.Write(value)

	binary.LittleEndian.PutUint32(value, uint32(variant))
	state.Write(value)

	binary.LittleEndian.PutUint32(value, uint32(len(context.pwd)))
	state.Write(value)
	if context.pwd != nil {
		state.Write(context.pwd)
		if context.flags&ARGON2_FLAG_CLEAR_PASSWORD != 0 {
			secure_wipe_memory(context.pwd)
			context.pwd = nil
		}
	}

	binary.LittleEndian.PutUint32(value, uint32(len(context.salt)))
	state.Write(value)
	if context.salt != nil {
		state.Write(context.salt)
	}

	binary.LittleEndian.PutUint32(value, uint32(len(context.secret)))
	state.Write(value)
	if context.secret != nil {
		state.Write(context.secret)
		if context.flags&ARGON2_FLAG_CLEAR_PASSWORD != 0 {
			secure_wipe_memory(context.secret)
			context.secret = nil
		}
	}

	binary.LittleEndian.PutUint32(value, uint32(len(context.ad)))
	state.Write(value)
	if context.ad != nil {
		state.Write(context.ad)
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

func fill_first_blocks(blockhash *[ARGON2_PREHASH_SEED_LENGTH]byte, instance *argon2_instance) error {
	blockhash_bytes := make([]byte, ARGON2_BLOCK_SIZE)
	for l := uint32(0); l < instance.lanes; l++ {
		binary.LittleEndian.PutUint32(blockhash[ARGON2_PREHASH_DIGEST_LENGTH:], 0)
		binary.LittleEndian.PutUint32(blockhash[ARGON2_PREHASH_DIGEST_LENGTH+4:], l)
		if err := blake2b_long(blockhash_bytes, blockhash[:]); err != nil {
			return err
		}
		load_block(&instance.memory[l*instance.lane_length], blockhash_bytes)

		binary.LittleEndian.PutUint32(blockhash[ARGON2_PREHASH_DIGEST_LENGTH:], 1)
		if err := blake2b_long(blockhash_bytes, blockhash[:]); err != nil {
			return err
		}
		load_block(&instance.memory[l*instance.lane_length+1], blockhash_bytes)
	}
	secure_wipe_memory(blockhash_bytes)
	return nil
}

func load_block(dst *block, input []byte) {
	for i := 0; i < ARGON2_QWORDS_IN_BLOCK; i++ {
		dst[i] = binary.LittleEndian.Uint64(input[i*8:])
	}
}

func store_block(output []byte, src *block) {
	for i := 0; i < ARGON2_QWORDS_IN_BLOCK; i++ {
		binary.LittleEndian.PutUint64(output[i*8:], src[i])
	}
}

func index_alpha(instance *argon2_instance, position *argon2_position, pseudo_rand uint32, same_lane bool) uint32 {
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

	if position.pass == 0 {
		/* First pass */
		if position.slice == 0 {
			/* First slice */
			reference_area_size =
				position.index - 1 /* all but the previous */
		} else {
			if same_lane {
				/* The same lane => add current segment */
				reference_area_size =
					uint32(position.slice)*instance.segment_length +
						position.index - 1
			} else {
				reference_area_size =
					uint32(position.slice) * instance.segment_length

				if position.index == 0 {
					reference_area_size -= 1
				}
			}
		}
	} else {
		/* Second pass */
		if same_lane {
			reference_area_size = instance.lane_length -
				instance.segment_length + position.index -
				1
		} else {
			reference_area_size = instance.lane_length -
				instance.segment_length

			if position.index == 0 {
				reference_area_size -= 1
			}
		}
	}

	/* 1.2.4. Mapping pseudo_rand to 0..<reference_area_size-1> and produce
	 * relative position */
	relative_position = uint64(pseudo_rand)
	relative_position = relative_position * relative_position >> 32
	relative_position = uint64(reference_area_size) - 1 -
		(uint64(reference_area_size) * relative_position >> 32)

	/* 1.2.5 Computing starting position */
	start_position = 0

	if position.pass != 0 {
		if position.slice == ARGON2_SYNC_POINTS-1 {
			start_position = 0
		} else {
			start_position = (uint32(position.slice) + 1) * instance.segment_length
		}
	}

	/* 1.2.6. Computing absolute position */
	absolute_position = (start_position + uint32(relative_position)) %
		instance.lane_length /* absolute position */
	return absolute_position
}

func clear_memory(instance *argon2_instance, clear bool) {
	if instance.memory != nil && clear {
		for _, b := range instance.memory {
			for i, _ := range b {
				b[i] = 0
			}
		}
	}
}
