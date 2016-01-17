package argon2

import (
	"sync"
)

func fill_memory_blocks(instance *argon2_instance) error {
	if instance == nil || instance.lanes == 0 {
		return ErrThreadFail
	}

	var (
		//thread   = make([]chan struct{}, instance.lanes)
		thr_data = make([]argon2_thread_data, instance.lanes)
	)

	for r := uint32(0); r < instance.passes; r++ {
		for s := uint32(0); s < ARGON2_SYNC_POINTS; s++ {
			var wg sync.WaitGroup

			/* 2. Calling threads */
			for l := uint32(0); l < instance.lanes; l++ {
				wg.Add(1)

				/* 2.2 Create thread */
				position := argon2_position{
					pass:  r,
					lane:  l,
					slice: uint8(s),
					index: 0,
				}
				thr_data[l].instance = instance
				thr_data[l].position = position

				go func(l, r uint32) {
					defer wg.Done()
					my_data := thr_data[l]
					fill_segment(my_data.instance, my_data.position)
				}(l, r)
			}

			wg.Wait()
		}
	}

	return nil
}
