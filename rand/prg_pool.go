package rand

type PrgPool struct {
	arr    []*BufPRGReader
	frozen bool
}

func InitPRGPool(num uint64) *PrgPool {
	pool := new(PrgPool)
	pool.frozen = false
	pool.arr = make([]*BufPRGReader, num)

	for i := uint64(0); i < num; i++ {
		seed := RandomPRGKey()
		pool.arr[i] = NewBufPRG(NewPRG(seed))
	}

	//fmt.Printf("Init pool of capacity %d = %d\n", capacity, len(pool))
	return pool
}

func extendPool(pool *PrgPool, capacity uint64) *PrgPool {
	if pool.frozen {
		panic("Trying to extend frozen pool")
	}

	for uint64(len(pool.arr)) < capacity {
		seed := RandomPRGKey()
		pool.arr = append(pool.arr, NewBufPRG(NewPRG(seed)))
	}

	//fmt.Printf("Extended pool capacity to %d = %d\n", capacity, len(curPool))
	return pool
}

func (pool *PrgPool) At(index uint64) *BufPRGReader {
	if index >= uint64(len(pool.arr)) {
		pool = extendPool(pool, 2*index) // Double the pool's capacity
	}

	return pool.arr[index]
}

func (pool *PrgPool) Set(index uint64, seed *PRGKey) {
	if index >= uint64(len(pool.arr)) {
		pool = extendPool(pool, 2*index) // Double the pool's capacity
	}

	pool.arr[index] = NewBufPRG(NewPRG(seed))
}

func (pool *PrgPool) Freeze()     { pool.frozen = true }
func (pool *PrgPool) Len() uint64 { return uint64(len(pool.arr)) }
