package argon2

func fillSegment(ins *instance, pos position) {
	var (
		refBlock, currBlock           *block
		pseudoRand, refIndex, refLane uint64
		prevOffset, currOffset        uint32
		startingIndex                 uint32
		dataIndependentAddressing     bool
		pseudoRands                   []uint64
	)
	if ins == nil {
		return
	}

	dataIndependentAddressing = (ins.variant == Argon2i)

	pseudoRands = make([]uint64, ins.segmentLength)

	if dataIndependentAddressing {
		generateAddresses(ins, &pos, pseudoRands)
	}

	if pos.pass == 0 && pos.slice == 0 {
		startingIndex = 2 // We have already generated the first two blocks
	}

	// Calculate offset of the current block
	currOffset = pos.lane*ins.laneLength + uint32(pos.slice)*ins.segmentLength + startingIndex

	if currOffset%ins.laneLength == 0 {
		// Last block in this lane
		prevOffset = currOffset + ins.laneLength - 1
	} else {
		// Previous block
		prevOffset = currOffset - 1
	}

	for i := startingIndex; i < ins.segmentLength; i++ {
		/* 1.1 Rotating prev_offest if needed */
		if currOffset%ins.laneLength == 1 {
			prevOffset = currOffset - 1
		}

		/* 1.2 Computing the index of the reference block */
		/* 1.2.1 Taking pseudo-random value from the previous block */
		if dataIndependentAddressing {
			pseudoRand = pseudoRands[i]
		} else {
			pseudoRand = ins.memory[prevOffset][0]
		}

		/* 1.2.2 Computing the lane of the reference block */
		refLane = (pseudoRand >> 32) % uint64(ins.lanes)

		if (pos.pass == 0) && (pos.slice == 0) {
			// Can not reference other lanes yet
			refLane = uint64(pos.lane)
		}

		/* 1.2.3 Computing the number of possible reference blocks within lane */
		pos.index = i
		refIndex = uint64(indexAlpha(ins, &pos, uint32(pseudoRand&0xFFFFFFFF), refLane == uint64(pos.lane)))

		/* 2 Creating a new block */
		refBlock =
			&ins.memory[uint64(ins.laneLength)*refLane+refIndex]
		//log.Printf("%d/%d\n", currOffset, len(ins.memory))
		currBlock = &ins.memory[currOffset]
		fillBlock(&ins.memory[prevOffset], refBlock, currBlock)

		currOffset++
		prevOffset++
	}
}

func generateAddresses(ins *instance, pos *position, pseudoRands []uint64) {
	var zeroBlock, inputBlock, addressBlock block

	initBlockValue(&zeroBlock, 0)
	initBlockValue(&inputBlock, 0)
	initBlockValue(&addressBlock, 0)

	if ins == nil || pos == nil {
		return
	}

	inputBlock[0] = uint64(pos.pass)
	inputBlock[1] = uint64(pos.lane)
	inputBlock[2] = uint64(pos.slice)
	inputBlock[3] = uint64(ins.memoryBlocks)
	inputBlock[4] = uint64(ins.passes)
	inputBlock[5] = uint64(ins.variant)

	for i := uint32(0); i < ins.segmentLength; i++ {
		if i%addressesInBlock == 0 {
			inputBlock[6]++
			fillBlock(&zeroBlock, &inputBlock, &addressBlock)
			fillBlock(&zeroBlock, &addressBlock, &addressBlock)
		}
		pseudoRands[i] = addressBlock[i%addressesInBlock]
	}
}

func initBlockValue(b *block, in byte) {
	for i := range b {
		b[i] = uint64(in)
	}
}

func copyBlock(dst, src *block) {
	copy(dst[:], src[:])
}

func xorBlock(dst, src *block) {
	for i := 0; i < qwordsInBlock; i++ {
		dst[i] ^= src[i]
	}
}

func fillBlock(prefBlock, refBlock, nextBlock *block) {
	var blockR, blockTmp block

	copyBlock(&blockR, refBlock)
	xorBlock(&blockR, prefBlock)
	copyBlock(&blockTmp, &blockR)

	/* Apply Blake2 on columns of 64-bit words: (0,1,...,15) , then
	   (16,17,..31)... finally (112,113,...127) */
	for i := 0; i < 8; i++ {
		blakeRound(
			&blockR[16*i], &blockR[16*i+1], &blockR[16*i+2],
			&blockR[16*i+3], &blockR[16*i+4], &blockR[16*i+5],
			&blockR[16*i+6], &blockR[16*i+7], &blockR[16*i+8],
			&blockR[16*i+9], &blockR[16*i+10], &blockR[16*i+11],
			&blockR[16*i+12], &blockR[16*i+13], &blockR[16*i+14],
			&blockR[16*i+15])
	}

	/* Apply Blake2 on rows of 64-bit words: (0,1,16,17,...112,113), then
	   (2,3,18,19,...,114,115).. finally (14,15,30,31,...,126,127) */
	for i := 0; i < 8; i++ {
		blakeRound(
			&blockR[2*i], &blockR[2*i+1], &blockR[2*i+16],
			&blockR[2*i+17], &blockR[2*i+32], &blockR[2*i+33],
			&blockR[2*i+48], &blockR[2*i+49], &blockR[2*i+64],
			&blockR[2*i+65], &blockR[2*i+80], &blockR[2*i+81],
			&blockR[2*i+96], &blockR[2*i+97], &blockR[2*i+112],
			&blockR[2*i+113])
	}

	copyBlock(nextBlock, &blockTmp)
	xorBlock(nextBlock, &blockR)
}
