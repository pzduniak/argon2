package argon2

// Key derives an Argon2(i|d) hash from the input.
func Key(password, salt []byte, iterations, parallelism, memory uint32, keyLength int, variant Variant) ([]byte, error) {
	// Prepare an output slice
	output := make([]byte, keyLength)

	ctx := &context{
		out:        output,
		pwd:        password,
		salt:       salt,
		timeCost:   iterations,
		memoryCost: memory,
		lanes:      parallelism,
		threads:    parallelism,
		flags:      DefaultFlags,
	}

	if err := core(ctx, variant); err != nil {
		return nil, err
	}

	return output, nil
}
