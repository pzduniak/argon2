package argon2

func core(ctx *context, variant Variant) error {
	/* 1. Validate all inputs */
	if err := validateInputs(ctx); err != nil {
		return err
	}

	if variant != Argon2d && variant != Argon2i {
		return ErrIncorrectType
	}

	/* 2. Align memory size */
	memoryBlocks := ctx.memoryCost
	if memoryBlocks < 2*syncPoints*ctx.lanes {
		memoryBlocks = 2 * syncPoints * ctx.lanes
	}

	segmentLength := memoryBlocks / (ctx.lanes * syncPoints)
	// Ensure that all segments have equal length
	memoryBlocks = segmentLength * (ctx.lanes * syncPoints)

	ins := instance{
		memory:        nil,
		passes:        ctx.timeCost,
		memoryBlocks:  memoryBlocks,
		segmentLength: segmentLength,
		laneLength:    segmentLength * syncPoints,
		lanes:         ctx.lanes,
		threads:       ctx.threads,
		variant:       variant,
	}

	/* 3. Initialization: Hashing inputs, allocating memory, filling
	   first blocks. */
	if err := initialize(&ins, ctx); err != nil {
		return err
	}

	/* 4. Filling memory */
	if err := fillMemoryBlocks(&ins); err != nil {
		return err
	}

	finalize(ctx, &ins)

	return nil
}

func finalize(ctx *context, ins *instance) {
	if ctx == nil || ins == nil {
		return
	}

	var blockhash block

	copyBlock(&blockhash, &ins.memory[ins.laneLength-1])

	/* XOR the last blocks */
	for l := uint32(1); l < ins.lanes; l++ {
		lastBlockInLane := l*ins.laneLength + (ins.laneLength - 1)
		xorBlock(&blockhash, &ins.memory[lastBlockInLane])
	}

	/* Hash the result */
	{
		var blockhashBytes [blockSize]byte
		storeBlock(blockhashBytes[:], &blockhash)
		blakeLong(ctx.out, blockhashBytes[:])
		secureWipeMemoryUint64(blockhash[:])
		secureWipeMemory(blockhashBytes[:])
	}

	/* Clear memory */
	clearMemory(ins, ctx.flags&FlagClearPassword != 0)

	/* Deallocate the memory */
	//free_memory(ins.memory)
}
