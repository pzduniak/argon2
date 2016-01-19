package argon2

import (
	"sync"
)

func fillMemoryBlocks(ins *instance) error {
	if ins == nil || ins.lanes == 0 {
		return ErrThreadFail
	}

	for r := uint32(0); r < ins.passes; r++ {
		for s := uint32(0); s < syncPoints; s++ {
			var wg sync.WaitGroup

			/* 2. Calling threads */
			for l := uint32(0); l < ins.lanes; l++ {
				wg.Add(1)

				/* 2.2 Create thread */
				pos := position{
					pass:  r,
					lane:  l,
					slice: uint8(s),
					index: 0,
				}

				go func(ins *instance, pos *position) {
					defer wg.Done()
					fillSegment(ins, pos)
				}(ins, &pos)
			}

			wg.Wait()
		}
	}

	return nil
}
