package argon2

func Key(password, salt []byte, iterations, parallelism, memory uint32, keyLength int, variant Variant) ([]byte, error) {
	// Prepare an output slice
	output := make([]byte, keyLength)

	ctx := &argon2_context{
		out:     output,
		pwd:     password,
		salt:    salt,
		t_cost:  iterations,
		m_cost:  memory,
		lanes:   parallelism,
		threads: parallelism,
		flags:   ARGON2_DEFAULT_FLAGS,
	}

	if err := argon2_core(ctx, variant); err != nil {
		return nil, err
	}

	return output, nil
}
