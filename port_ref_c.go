package argon2

func fillSegment(ins *instance, pos *position) {
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

	if dataIndependentAddressing {
		pseudoRands = make([]uint64, ins.segmentLength)
		generateAddresses(ins, pos, pseudoRands)
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
		refIndex = uint64(indexAlpha(ins, pos, uint32(pseudoRand&0xFFFFFFFF), refLane == uint64(pos.lane)))

		/* 2 Creating a new block */
		refBlock =
			&ins.memory[uint64(ins.laneLength)*refLane+refIndex]
		//log.Printf("%d/%d\n", currOffset, len(ins.memory))
		currBlock = &ins.memory[currOffset]
		round(currBlock, refBlock, &ins.memory[prevOffset])
		currOffset++
		prevOffset++
	}
}

func generateAddresses(ins *instance, pos *position, pseudoRands []uint64) {
	var zeroBlock, inputBlock, addressBlock, tmpBlock block

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
			copy(tmpBlock[:], addressBlock[:])
			round(&inputBlock, &addressBlock, &zeroBlock)
			round(&addressBlock, &tmpBlock, &zeroBlock)
		}
		pseudoRands[i] = addressBlock[i%addressesInBlock]
	}
}

func xorBlock(dst, src *block) {
	for i := 0; i < qwordsInBlock; i++ {
		dst[i] ^= src[i]
	}
}
