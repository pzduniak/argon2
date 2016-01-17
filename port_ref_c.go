package argon2

func fill_segment(instance *argon2_instance, position argon2_position) {
	var (
		ref_block, curr_block            *block
		pseudo_rand, ref_index, ref_lane uint64
		prev_offset, curr_offset         uint32
		starting_index                   uint32
		data_independent_addressing      bool
		pseudo_rands                     []uint64
	)
	if instance == nil {
		return
	}

	data_independent_addressing = (instance.variant == Argon2i)

	pseudo_rands = make([]uint64, instance.segment_length)

	if data_independent_addressing {
		generate_addresses(instance, &position, pseudo_rands)
	}

	starting_index = 0

	if position.pass == 0 && position.slice == 0 {
		starting_index = 2 // We have already generated the first two blocks
	}

	// Calculate offset of the current block
	curr_offset = position.lane*instance.lane_length + uint32(position.slice)*instance.segment_length + starting_index

	if curr_offset%instance.lane_length == 0 {
		// Last block in this lane
		prev_offset = curr_offset + instance.lane_length - 1
	} else {
		// Previous block
		prev_offset = curr_offset - 1
	}

	for i := starting_index; i < instance.segment_length; i++ {
		/* 1.1 Rotating prev_offest if needed */
		if curr_offset%instance.lane_length == 1 {
			prev_offset = curr_offset - 1
		}

		/* 1.2 Computing the index of the reference block */
		/* 1.2.1 Taking pseudo-random value from the previous block */
		if data_independent_addressing {
			pseudo_rand = pseudo_rands[i]
		} else {
			pseudo_rand = instance.memory[prev_offset][0]
		}

		/* 1.2.2 Computing the lane of the reference block */
		ref_lane = (pseudo_rand >> 32) % uint64(instance.lanes)

		if (position.pass == 0) && (position.slice == 0) {
			// Can not reference other lanes yet
			ref_lane = uint64(position.lane)
		}

		/* 1.2.3 Computing the number of possible reference blocks within lane */
		position.index = i
		ref_index = uint64(index_alpha(instance, &position, uint32(pseudo_rand&0xFFFFFFFF), ref_lane == uint64(position.lane)))

		/* 2 Creating a new block */
		ref_block =
			&instance.memory[uint64(instance.lane_length)*ref_lane+ref_index]
		//log.Printf("%d/%d\n", curr_offset, len(instance.memory))
		curr_block = &instance.memory[curr_offset]
		fill_block(&instance.memory[prev_offset], ref_block, curr_block)

		curr_offset++
		prev_offset++
	}
}

func generate_addresses(instance *argon2_instance, position *argon2_position, pseudo_rands []uint64) {
	var zero_block, input_block, address_block block

	init_block_value(&zero_block, 0)
	init_block_value(&input_block, 0)
	init_block_value(&address_block, 0)

	if instance == nil || position == nil {
		return
	}

	input_block[0] = uint64(position.pass)
	input_block[1] = uint64(position.lane)
	input_block[2] = uint64(position.slice)
	input_block[3] = uint64(instance.memory_blocks)
	input_block[4] = uint64(instance.passes)
	input_block[5] = uint64(instance.variant)

	for i := uint32(0); i < instance.segment_length; i++ {
		if i%ARGON2_ADDRESSES_IN_BLOCK == 0 {
			input_block[6]++
			fill_block(&zero_block, &input_block, &address_block)
			fill_block(&zero_block, &address_block, &address_block)
		}
		pseudo_rands[i] = address_block[i%ARGON2_ADDRESSES_IN_BLOCK]
	}
}

func init_block_value(b *block, in byte) {
	for i, _ := range b {
		b[i] = uint64(in)
	}
}

func copy_block(dst, src *block) {
	copy(dst[:], src[:])
}

func xor_block(dst, src *block) {
	for i := 0; i < ARGON2_QWORDS_IN_BLOCK; i++ {
		dst[i] ^= src[i]
	}
}

func fill_block(prev_block, ref_block, next_block *block) {
	var blockR, block_tmp block

	copy_block(&blockR, ref_block)
	xor_block(&blockR, prev_block)
	copy_block(&block_tmp, &blockR)

	/* Apply Blake2 on columns of 64-bit words: (0,1,...,15) , then
	   (16,17,..31)... finally (112,113,...127) */
	for i := 0; i < 8; i++ {
		blake2_round_nomsg(
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
		blake2_round_nomsg(
			&blockR[2*i], &blockR[2*i+1], &blockR[2*i+16],
			&blockR[2*i+17], &blockR[2*i+32], &blockR[2*i+33],
			&blockR[2*i+48], &blockR[2*i+49], &blockR[2*i+64],
			&blockR[2*i+65], &blockR[2*i+80], &blockR[2*i+81],
			&blockR[2*i+96], &blockR[2*i+97], &blockR[2*i+112],
			&blockR[2*i+113])
	}

	copy_block(next_block, &block_tmp)
	xor_block(next_block, &blockR)
}
