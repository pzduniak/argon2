package argon2

const (
	ARGON2_MIN_LANES           = 1
	ARGON2_MAX_LANES           = 0xFFFFFF
	ARGON2_MIN_THREADS         = 1
	ARGON2_MAX_THREADS         = 0xFFFFFF
	ARGON2_SYNC_POINTS         = 4
	ARGON2_MIN_OUTLEN          = 4
	ARGON2_MAX_OUTLEN          = 0xFFFFFFFF
	ARGON2_MIN_MEMORY          = 2 * ARGON2_SYNC_POINTS
	ARGON2_MAX_MEMORY          = 1<<32 - 1
	ARGON2_MIN_TIME            = 1
	ARGON2_MAX_TIME            = 0xFFFFFFFF
	ARGON2_MIN_PWD_LENGTH      = 0
	ARGON2_MAX_PWD_LENGTH      = 0xFFFFFFFF
	ARGON2_MIN_AD_LENGTH       = 0
	ARGON2_MAX_AD_LENGTH       = 0xFFFFFFFF
	ARGON2_MIN_SALT_LENGTH     = 8
	ARGON2_MAX_SALT_LENGTH     = 0xFFFFFFFF
	ARGON2_MIN_SECRET          = 0
	ARGON2_MAX_SECRET          = 0xFFFFFFFF
	ARGON2_FLAG_CLEAR_PASSWORD = 1 << 0
	ARGON2_FLAG_CLEAR_SECRET   = 1 << 1
	ARGON2_FLAG_CLEAR_MEMORY   = 1 << 2
	ARGON2_DEFAULT_FLAGS       = ARGON2_FLAG_CLEAR_MEMORY
)

type argon2_context struct {
	out     []byte
	pwd     []byte
	salt    []byte
	secret  []byte
	ad      []byte
	t_cost  uint32
	m_cost  uint32
	lanes   uint32
	threads uint32

	flags uint32
}

type Variant uint8

const (
	Argon2d Variant = iota
	Argon2i
)
