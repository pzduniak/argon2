package argon2

func argon2_core(ctx *argon2_context, variant variant) error {
	/* 1. Validate all inputs */
	if err := validate_inputs(ctx); err != nil {
		return err
	}

	if variant != Argon2d && variant != Argon2i {
		return ErrIncorrectType
	}

	/* 2. Align memory size */
	memory_blocks := ctx.m_cost
	if memory_blocks < 2*ARGON2_SYNC_POINTS*ctx.lanes {
		memory_blocks = 2 * ARGON2_SYNC_POINTS * ctx.lanes
	}

	segment_length := memory_blocks / (ctx.lanes * ARGON2_SYNC_POINTS)
	// Ensure that all segments have equal length
	memory_blocks = segment_length * (ctx.lanes * ARGON2_SYNC_POINTS)

	instance := argon2_instance{
		memory:         nil,
		passes:         ctx.t_cost,
		memory_blocks:  memory_blocks,
		segment_length: segment_length,
		lane_length:    segment_length * ARGON2_SYNC_POINTS,
		lanes:          ctx.lanes,
		threads:        ctx.threads,
		variant:        variant,
	}

	/* 3. Initialization: Hashing inputs, allocating memory, filling
	   first blocks. */
	if err := initialize(&instance, ctx); err != nil {
		return err
	}

	/* 4. Filling memory */
	if err := fill_memory_blocks(&instance); err != nil {
		return err
	}

	/* 5. Finalization */
	/*if err := finalize(ctx, &instance); err != nil {
		return err
	}*/
	finalize(ctx, &instance)

	return nil
}

func finalize(context *argon2_context, instance *argon2_instance) {
	if context == nil || instance == nil {
		return
	}

	var blockhash block

	copy_block(&blockhash, &instance.memory[instance.lane_length-1])

	/* XOR the last blocks */
	for l := uint32(1); l < instance.lanes; l++ {
		last_block_in_lane := l*instance.lane_length + (instance.lane_length - 1)
		xor_block(&blockhash, &instance.memory[last_block_in_lane])
	}

	/* Hash the result */
	{
		var blockhash_bytes [ARGON2_BLOCK_SIZE]byte
		store_block(blockhash_bytes[:], &blockhash)
		blake2b_long(context.out, blockhash_bytes[:])
		secure_wipe_memory_uint64(blockhash[:])
		secure_wipe_memory(blockhash_bytes[:])
	}

	/* Clear memory */
	clear_memory(instance, context.flags&ARGON2_FLAG_CLEAR_PASSWORD != 0)

	/* Deallocate the memory */
	//free_memory(instance.memory)
}
