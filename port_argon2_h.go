package argon2

const (
	minLanes          = 1
	maxLanes          = 0xFFFFFF
	minThreads        = 1
	maxThreads        = 0xFFFFFF
	syncPoints        = 4
	minOutlen         = 4
	maxOutlen         = 0xFFFFFFFF
	minMemory         = 2 * syncPoints
	maxMemory         = 1<<32 - 1
	minTime           = 1
	maxTime           = 0xFFFFFFFF
	minPasswordLength = 0
	maxPasswordLength = 0xFFFFFFFF
	minADLength       = 0
	maxADLength       = 0xFFFFFFFF
	minSaltLength     = 8
	maxSaltLength     = 0xFFFFFFFF
	minSecret         = 0
	maxSecret         = 0xFFFFFFFF
)

// FLags regarding clearing of inputs during hashing
const (
	FlagClearPassword = 1 << 0
	FlagClearSecret   = 1 << 1
	FlagClearMemory   = 1 << 2
	DefaultFlags      = FlagClearMemory
)

type context struct {
	out        []byte
	pwd        []byte
	salt       []byte
	secret     []byte
	ad         []byte
	timeCost   uint32
	memoryCost uint32
	lanes      uint32
	threads    uint32

	flags uint32
}

// Variant is the type of algorithm to use
type Variant uint8

// Argon2i uses data-derived pseudorandom numbers, protecting from side-channel attacks.
const (
	Argon2d Variant = iota
	Argon2i
)
