package argon2

import (
	"sync"
)

func fill_memory_blocks(instance *argon2_instance) error {
	if instance == nil || instance.lanes == 0 {
		return ErrThreadFail
	}

	var (
		thread   = make([]sync.Mutex, instance.lanes)
		thr_data = make([]argon2_thread_data, instance.lanes)
	)

	for r := uint32(0); r < instance.passes; r++ {
		for s := uint32(0); s < ARGON2_SYNC_POINTS; s++ {
			/* 2. Calling threads */
			for l := uint32(0); l < instance.lanes; l++ {
				/* 2.1 Join a thread if limit is exceeded */
				if l >= instance.threads {
					thread[l-instance.threads].Lock()
					thread[l-instance.threads].Unlock()
				}

				/* 2.2 Create thread */
				position := argon2_position{
					pass:  r,
					lane:  l,
					slice: uint8(s),
					index: 0,
				}
				thr_data[l].instance = instance
				thr_data[l].position = position
				go func(l uint32) {
					thread[l].Lock()
					defer thread[l].Unlock()

					my_data := thr_data[l]
					fill_segment(my_data.instance, my_data.position)
				}(l)
			}

			/* 3. Join remaining threads */
			for l := instance.lanes - instance.threads; l < instance.lanes; l++ {
				thread[l-instance.threads].Lock()
				thread[l-instance.threads].Unlock()
			}
		}
	}

	return nil
}
