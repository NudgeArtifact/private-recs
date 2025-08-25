package share

// #cgo CFLAGS: -O3 -march=native -msse4.1 -maes -mavx2 -mavx -I../uint128 
// #include "matrix.h"
import "C"

import (
	"fmt"
	"math"
	"sync"
	"math/bits"
	"slices"
	"unsafe"

	"private-recs/dcf"
	"private-recs/dmsb"
        "private-recs/multdpf"

        . "private-recs/uint128"
	. "private-recs/rand"
)

type UintElem interface {
	uint64 | Uint128
}

type ShareElem interface {
	share | Share128
}

type Elem interface {
	UintElem | ShareElem
}

type Matrix[T Elem] struct {
	Rows uint64
	Cols uint64
	Data []T
}


// CONSTRUCTORS

func MatrixZeros[T Elem](rows, cols uint64) *Matrix[T] {
	m := new(Matrix[T])
	m.Rows = rows
	m.Cols = cols
	m.Data = make([]T, rows*cols)
	return m
}

func MatrixOnes[T UintElem](rows, cols uint64) *Matrix[T] {
        m := MatrixZeros[T](rows, cols)
	SetOnes(m, rows, cols)
	return m
}

func InitPRGPoolFromMatrix[T Elem](m *Matrix[T]) *PrgPool {
        capacity := m.Rows
        if m.Rows < m.Cols {
                capacity = m.Cols
        }

        return InitPRGPoolFromCapacity(capacity, NUM_VCPUS)
}

func RandMatrix[T Elem](rows, cols, min_val, max_val uint64, pool *PrgPool) *Matrix[T] {
        m := MatrixZeros[T](rows, cols)
	SetRand(m, rows, cols, min_val, max_val, pool)
        return m
}

func Rand01Matrix(rows, cols uint64) *Matrix[uint64] {
        m := MatrixZeros[uint64](rows, cols)
	seed := RandomPRGKey()
	prg := NewBufPRG(NewPRG(seed))
        SetRand01(m, prg)
        return m
}

func SetToZero[T Elem](m *Matrix[T]) {
	clear(m.Data)
}

func SetOnes[T UintElem](m *Matrix[T], rows, cols uint64) {
        var wg sync.WaitGroup

        for row := uint64(0); row < rows; row++ {
                wg.Add(1)

                go func(m *Matrix[T], row uint64) {
                        defer wg.Done()

                        for col :=uint64(0); col < cols; col++ {
                                switch x := any(&m.Data[row*m.Cols + col]).(type) {
                                case *uint64:
                                        *x = 1
                                case *Uint128:
                                        SetUint128(0, 1, x)
                                default:
                                        panic("Hit default case.")
                                }
                        }
                }(m, row)
        }

        wg.Wait()
}

func SetRand[T Elem](m *Matrix[T], rows, cols, min_val, max_val uint64, pool *PrgPool) {
        _, ok := any(m).(*Matrix[Uint128])
        if ok && (max_val != 0) {
                panic("Can't modulus reduce Uint128 -- not yet supported.")
        }

	var wg sync.WaitGroup
        rows_per_thread := (m.Rows + NUM_VCPUS - 1) / NUM_VCPUS

        for i := uint64(0); i < rows; i += rows_per_thread {
		wg.Add(1)
                go func(m *Matrix[T], i uint64) {
                        defer wg.Done()
			prg := pool.At(i / rows_per_thread)

			for i2 := uint64(0); i2 < rows_per_thread; i2++ {
				if i + i2 > rows {
					break
				}
			
				for j := uint64(0); j < cols; j++ {
        	        		switch x := any(&m.Data[i*cols+j]).(type) {
                			case *uint64:
                        			*x = (prg.Uint64() % (max_val-min_val))
                        			*x += min_val
	                		case *Uint128:
        	                		SetUint128(prg.Uint64(), prg.Uint64(), x)
					case *share:
						x.First = (prg.Uint64() % (max_val-min_val))
						x.First += min_val
						x.Second = (prg.Uint64() % (max_val-min_val))
						x.Second += min_val
					case *Share128:
                		        	SetUint128(prg.Uint64(), prg.Uint64(), &x.First)
                        			SetUint128(prg.Uint64(), prg.Uint64(), &x.Second)
                			default:
                        			panic("Hit default case.")
					}
				}
                	}
		}(m, i)
        }

	wg.Wait()
}

func SetRand01(m *Matrix[uint64], prg *BufPRGReader) {
        for i := uint64(0); i < m.Rows * m.Cols; i++ {
                m.Data[i] = prg.Uint64() % 2
        }
}

// GETTERS

func (m *Matrix[T]) NRows() uint64 { return m.Rows }
func (m *Matrix[T]) NCols() uint64 { return m.Cols }
func (m *Matrix[T]) NEntries() uint64 { return m.Cols*m.Rows }

func (m *Matrix[T]) Get(i, j uint64) *T {
        if m.Rows == 0 || m.Cols == 0 {
                panic("Get: Matrix is empty")
        }

        if i >= m.Rows || j >= m.Cols {
                fmt.Printf("Matrix of dims (%d, %d); request to read at (%d, %d)\n", m.Rows, m.Cols, i, j)
                panic("Get: Location requested is out-of-bounds")
        }

        return &m.Data[i*m.Cols+j]
}

func (m *Matrix[T]) GetRows(start, stop uint64) *Matrix[T] {
        if stop <= start {
                panic("GetRows: invalid input")
        }

        if stop > m.Rows {
                panic("GetRowsPointer: input too large")
        }

        out := MatrixZeros[T](stop-start, m.Cols)
        copy(out.Data[:], m.Data[start*m.Cols:stop*m.Cols])

        return out
}

func (m *Matrix[T]) GetRowsPointer(start, stop uint64) *Matrix[T] {
        if stop <= start {
                panic("GetRowsPointer: invalid input")
        }

	if stop > m.Rows {
		panic("GetRowsPointer: input too large")
	}

	out := new(Matrix[T])
	out.Rows = stop - start
	out.Cols = m.Cols
	out.Data = m.Data[start*m.Cols:stop*m.Cols]

        return out
}

func (m *Matrix[T]) Equals(n *Matrix[T]) bool {
        if m.Cols != n.Cols {
                return false
        }

        if m.Rows != n.Rows {
                return false
        }

	for i, _ := range m.Data {
		if m.Data[i] != n.Data[i] {
			fmt.Printf("index %d: %d != %d\n", i, m.Data[i], n.Data[i])
		}
	}
        return slices.Equal(m.Data, n.Data)
}

// PRINTERS

func Print[T UintElem](m *Matrix[T]) {
	for i := uint64(0); i < m.Rows; i++ {
		fmt.Printf("[")
		for j := uint64(0); j < m.Cols; j++ {
			
			switch x := any(m.Get(i, j)).(type) {
                	case *uint64:
				fmt.Printf(" %d", *x)
			case *Uint128:
				fmt.Printf(" ")
				x.Print()
			default:
				panic("Hit default case.")
			}
		}
		fmt.Printf("]\n")
	}
}

func PrintSigned(m *Matrix[uint64]) {
        for i := uint64(0); i < m.Rows; i++ {
                fmt.Printf("[")
                for j := uint64(0); j < m.Cols; j++ {
                        fmt.Printf(" %d", int64(*m.Get(i, j)))
                }
                fmt.Printf("]\n")
        }
}

// COPYERS AND CONVERTERS

func (m *Matrix[T]) Copy() *Matrix[T] {
        out := MatrixZeros[T](m.Rows, m.Cols)
        copy(out.Data, m.Data)
        return out
}

func ToMatrix64(m *Matrix[Uint128]) *Matrix[uint64] {
        out := MatrixZeros[uint64](m.Rows, m.Cols)
	ToMatrix64Dst(m, out)
	return out
}

func ToMatrix64Dst(m *Matrix[Uint128], out *Matrix[uint64]) {
	if !(m.Rows == out.Rows && m.Cols == out.Cols) {
		panic("ToMatrix64: Dimension mismatch")
	}

	var wg sync.WaitGroup
	rows_per_thread := (m.Rows + NUM_VCPUS - 1) / NUM_VCPUS

        for i := uint64(0); i < m.Rows; i += rows_per_thread {
		wg.Add(1)

		go func(m *Matrix[Uint128], out *Matrix[uint64], i uint64) {
			defer wg.Done()

			for i2 := uint64(0); i2 < rows_per_thread; i2++ {
				if i + i2 >= m.Rows {
					break
				}

                		for j := uint64(0); j < m.Cols; j++ {
					x := &m.Data[(i+i2)*m.Cols+j]

					if DebugMode && !CheckUint64(x) {
						fmt.Printf("At location (%d, %d): ", i+i2, j)
                				x.Print()
						panic("ToMatrix64: value does not fit in Uint64!")
       			 		}
		
                        		out.Data[(i+i2)*m.Cols+j] = ToUint64(x)
                		}
			}
		}(m, out, i)
        }
	wg.Wait()
}

func ToMatrix128(m *Matrix[uint64]) *Matrix[Uint128] {
        out := MatrixZeros[Uint128](m.Rows, m.Cols)
	ToMatrix128Dst(m, out)
	return out
}

func ToMatrix128Dst(m *Matrix[uint64], out *Matrix[Uint128]) {
	if !(m.Rows == out.Rows && m.Cols == out.Cols) {
		panic("ToMatrix128: Dimension mismatch!")
	}

	var wg sync.WaitGroup
	rows_per_thread := (m.Rows + NUM_VCPUS - 1) / NUM_VCPUS

        for i := uint64(0); i < m.Rows; i += rows_per_thread {
		wg.Add(1)

		go func(m *Matrix[uint64], out *Matrix[Uint128], i uint64) {
			defer wg.Done()
			for i2 := uint64(0); i2 < rows_per_thread; i2++ {
				if i + i2 >= m.Rows {
					break
				}

                		for j := uint64(0); j < m.Cols; j++ {
                        		ToUint128Dst(m.Data[(i+i2)*m.Cols+j], &out.Data[(i+i2)*m.Cols+j])
                		}
			}
		}(m, out, i)
        }

	wg.Wait()
}

func (m *Matrix[T]) Transpose() *Matrix[T] {
        out := MatrixZeros[T](m.Cols, m.Rows)

	if m.Cols == 1 || m.Rows == 1 {
		// special case for vector: don't need to change Data layout 
		copy(out.Data[:], m.Data[:])
	} else {
		// else, need to change Data loyout
		var wg sync.WaitGroup

        	for i := uint64(0); i < m.Rows; i++ {
			wg.Add(1)

			go func(out *Matrix[T], m *Matrix[T], i uint64) {
				defer wg.Done()
                		for j := uint64(0); j < m.Cols; j++ {
                        		out.Data[j*m.Rows+i] = m.Data[i*m.Cols+j]
                		}
			}(out, m, i)
        	}
		wg.Wait()
	}

        return out
}

func (m *Matrix[T]) TransposeInPlace() {
	out := m.Transpose()
	m.Rows = out.Rows
	m.Cols = out.Cols
	copy(out.Data, m.Data)
}

func (m *Matrix[T]) TransposeVectorInPlace() {
	if !(m.Cols == 1 || m.Rows == 1) {
		panic("TransposeVectorInPlace: Input is not a vector")
	}

	tmp := m.Cols
	m.Cols = m.Rows
	m.Rows = tmp
}

// SETTERS

func (m *Matrix[T]) Set(i, j uint64, val *T) {
        if m.Rows == 0 || m.Cols == 0 {
                panic("Set: Matrix is empty")
        }

        if i >= m.Rows || j >= m.Cols {
		fmt.Printf("%d, %d from (%d, %d)\n", i, j, m.Rows, m.Cols)
                panic("Set: Location requested is out-of-bounds")
        }

        m.Data[i*m.Cols+j] = *val
}

func (m *Matrix[T]) SetRow(i uint64, row *Matrix[T]) {
	if !(row.Rows == 1 || row.Cols == 1) {
		panic("SetRow: row is not a vector")
	}

	if row.Rows == 1 && row.Cols != m.Cols {
		panic("SetRow: dimension mismatch")
	} else if row.Cols == 1 && row.Rows != m.Cols {
		panic("SetRow: dimension mismatch")
	}

        if i >= m.Rows {
                panic("SetRow: index is out of range")
        }

	copy(m.Data[i*m.Cols:(i+1)*m.Cols], row.Data[:])
}

func (m *Matrix[T]) DropDimsBeyond(rows, cols uint64) {
	if rows > m.Rows || cols > m.Cols {
		fmt.Printf("Called DropDimsBeyond (%d, %d) on matrix with dims (%d, %d)\n", rows, cols, m.Rows, m.Cols)
		panic("DropDimsBeyond: bad input")
	}

	m.Rows = rows
	m.Cols = cols
	m.Data = m.Data[:rows*cols]
}

func SliceAddTo(v []Uint128, u []Uint128) {
	if len(v) != len(u) {
		panic("Bad input")
	}

        for j := uint64(0); j < uint64(len(v)); j++ {
		v[j].AddInPlace(&u[j])
        }
}

func SliceMul(v []Uint128, val Uint128) []Uint128 {
	res := make([]Uint128, len(v))
	copy(res, v)

	for j := uint64(0); j < uint64(len(v)); j++ {
                res[j].MulInPlace(&val)
        }

	return res
}

func (m *Matrix[T]) SetRowFromSlice(i uint64, v []T) {
        if uint64(len(v)) != m.Cols {
		fmt.Printf("%d %d\n", uint64(len(v)), m.Cols)
                panic("SetRowFromSlice: slice has the wrong dimensions")
        }

        if i >= m.Rows {
                panic("SetRowFromSlice: index is out of range")
        }

        copy(m.Data[i*m.Cols:(i+1)*m.Cols], v)
}

func AddToRowFromSlice(m *Matrix[Share128], i uint64, v []Uint128) {
        if uint64(len(v)) < m.Cols * 2 {
                fmt.Printf("%d %d\n", uint64(len(v)), m.Cols)
                panic("SetRowFromSlice: slice has the wrong dimensions")
        }

        if i >= m.Rows {
                panic("SetRowFromSlice: index is out of range")
        }

	for j := uint64(0); j < m.Cols; j++ {
		m.Data[i*m.Cols + j].First.AddInPlace(&v[2*j])
		m.Data[i*m.Cols + j].Second.AddInPlace(&v[2*j+1])
	}
}

// SECRET SHARING OPERATIONS

func ShareMatrixRSS(m *Matrix[uint64], pool *PrgPool) (*Matrix[Share128], *Matrix[Share128], *Matrix[Share128]) {
	out0 := MatrixZeros[Share128](m.Rows, m.Cols)
	out1 := MatrixZeros[Share128](m.Rows, m.Cols)
	out2 := MatrixZeros[Share128](m.Rows, m.Cols)

	//fmt.Printf("Allocated matrices: %d by %d\n", m.Rows, m.Cols)
	//PrintMemUsage()

	var wg sync.WaitGroup
	rows_per_thread := (m.Rows + NUM_VCPUS - 1) / NUM_VCPUS

	at := uint64(0)
	for i := uint64(0); i < m.Rows; i += rows_per_thread {
		wg.Add(1)

		go func(m *Matrix[uint64], out0, out1, out2 *Matrix[Share128], i uint64, ownPRG *BufPRGReader) {
			defer wg.Done()

			for i2 := uint64(0); i2 < rows_per_thread; i2++ {
				if i + i2 >= m.Rows {
					break
				}

				for j := uint64(0); j < m.Cols; j++ {
					ShareRSS128Dst(m.Data[(i+i2)*m.Cols+j], &out0.Data[(i+i2)*m.Cols+j], &out1.Data[(i+i2)*m.Cols+j], &out2.Data[(i+i2)*m.Cols+j], ownPRG)
				}
			}
		}(m, out0, out1, out2, i, pool.At(at))

		at += 1
	}

	wg.Wait()

	return out0, out1, out2
}

func MatrixRecoverFromRSS(m0, m1, m2 *Matrix[Share128], perf *PerfLog) *Matrix[uint64] {
	out := MatrixZeros[uint64](m0.Rows, m0.Cols)
	MatrixRecoverFromRSSDst(m0, m1, m2, out, perf)
	return out
}

func MatrixRecoverFromRSSDst(m0, m1, m2 *Matrix[Share128], out *Matrix[uint64], perf *PerfLog) {
        if m0.Rows != m1.Rows || m0.Cols != m1.Cols || m0.Rows != m2.Rows || m0.Cols != m2.Cols || out.Cols != m0.Cols || out.Rows != m0.Rows {
                panic("MatrixRecoverFromRSS: Dimension mismatch")
        }

        cols := m0.Cols
        var wg sync.WaitGroup
        for i := uint64(0); i < m0.Rows; i++ {
                wg.Add(1)

                go func(m0, m1, m2 *Matrix[Share128], out *Matrix[uint64], i uint64) {
                        defer wg.Done()
                        for j := uint64(0); j < m0.Cols; j++ {
                                out.Data[i*m0.Cols+j] = recoverRSS128(&m0.Data[i*cols+j], &m1.Data[i*cols+j], &m2.Data[i*cols+j])
                        }
                }(m0, m1, m2, out, i)
        }

	perf.IncrementCommThreeServers(m0.NEntries() * 16) // 16 bytes per 128-bit value, need to send result to all three servers
        wg.Wait()
}

func MatrixAdditiveToRSS(m0, m1, m2 *Matrix[Uint128], pool *PrgPool, perf *PerfLog) (*Matrix[Share128], *Matrix[Share128], *Matrix[Share128]) {
	rows := m0.Rows
	cols := m0.Cols

        out0 := MatrixZeros[Share128](rows, cols)
        out1 := MatrixZeros[Share128](rows, cols)
        out2 := MatrixZeros[Share128](rows, cols)

	MatrixAdditiveToRSSDst(m0, m1, m2, out0, out1, out2, pool, perf)

        return out0, out1, out2
}

func MatrixAdditiveToRSSDst(m0, m1, m2 *Matrix[Uint128], out0, out1, out2 *Matrix[Share128], pool *PrgPool, perf *PerfLog) {
        rows := m0.Rows
        cols := m0.Cols

        if !(m1.Rows == rows && m1.Cols == cols && m2.Rows == rows && m2.Cols == cols) ||
	   !(out0.Rows == rows && out0.Cols == cols && out1.Rows == rows && out1.Cols == cols && out2.Rows == rows && out2.Cols == cols) {
                panic("MatrixAdditiveToRSS: Input matrix dimensions do not match")
        }

	clear(out0.Data)
	clear(out1.Data)
	clear(out2.Data)

        var wg sync.WaitGroup
	rows_per_thread := (rows + NUM_VCPUS - 1) / NUM_VCPUS

	at := uint64(0)
        for i := uint64(0); i < rows; i += rows_per_thread {
                wg.Add(1)

                go func(m0, m1, m2 *Matrix[Uint128], out0, out1, out2 *Matrix[Share128], i uint64, ownPRG *BufPRGReader) {
                        defer wg.Done()

			for k := uint64(0); k < rows_per_thread; k++ {
				if i + k >= rows {
					break
				}

                	        for j := uint64(0); j < cols; j++ {
        	                        AdditiveToRSS128Dst(&m0.Data[(i+k)*cols+j], &m1.Data[(i+k)*cols+j], &m2.Data[(i+k)*cols+j], 
				        	            &out0.Data[(i+k)*cols+j], &out1.Data[(i+k)*cols+j], &out2.Data[(i+k)*cols+j],
							    ownPRG)
                        	}
			}
                }(m0, m1, m2, out0, out1, out2, i, pool.At(at))

		at += 1
        }

	perf.IncrementCommThreeServers(m0.NEntries() * 16)
        wg.Wait()
}

func MatrixAdditive3To2InPlace(m0, m1, m2 *Matrix[Uint128], excluded uint, pool *PrgPool, perf *PerfLog) {
        rows := m0.Rows
        cols := m0.Cols

        if !(m1.Rows == rows && m1.Cols == cols && m2.Rows == rows && m2.Cols == cols) {
                panic("MatrixAdditiveToRSS: Input matrix dimensions do not match")
        }

        var wg sync.WaitGroup
        rows_per_thread := (rows + NUM_VCPUS - 1) / NUM_VCPUS

	mL := m1
	mR := m2
	if excluded == 1 {
		mL = m2
		mR = m0
	} else if excluded == 2 {
		mL = m0
		mR = m1
	}

        at := uint64(0)
        for i := uint64(0); i < rows; i += rows_per_thread {
                wg.Add(1)

                go func(mL, mR *Matrix[Uint128], i uint64, ownPRG *BufPRGReader) {
                        defer wg.Done()

                        for k := uint64(0); k < rows_per_thread; k++ {
                                if i + k >= rows {
                                        break
                                }

                                for j := uint64(0); j < cols; j++ {
					mL.Data[(i+k)*cols+j].AddInPlace(&mR.Data[(i+k)*cols+j])
					Copy(&mL.Data[(i+k)*cols+j], &mR.Data[(i+k)*cols+j])
                                }
                        }
                }(mL, mR, i, pool.At(at))

                at += 1
        }

        perf.IncrementCommAllButDealer(excluded, m0.NEntries() * 16)
        wg.Wait()
}

func MatrixRSSToAdditive(m *Matrix[Share128], share_id int) *Matrix[Uint128] {
	if !(share_id == 0 || share_id == 1 || share_id == 2) {
		panic("MatrixRSSToAdditive: Invalid share_id")
	}

        out := MatrixZeros[Uint128](m.Rows, m.Cols)

	var wg sync.WaitGroup

	if share_id == 0 {
		
		// output sum of both shares
        	for i := uint64(0); i < m.Rows; i++ {
			wg.Add(1)

			go func(out *Matrix[Uint128], m *Matrix[Share128], i uint64) {
				defer wg.Done()
                		for j := uint64(0); j < m.Cols; j++ {
					val := m.Data[i*m.Cols+j].ShareSum()
                        		out.Data[i*m.Cols+j] = *val
                		}
			}(out, m, i)
        	}

	} else if share_id == 1 {

		// output first share only
		for i := uint64(0); i < m.Rows; i++ {
			wg.Add(1)

			go func(out *Matrix[Uint128], m *Matrix[Share128], i uint64) {
                                defer wg.Done()
                        	for j := uint64(0); j < m.Cols; j++ {
					val := m.Data[i*m.Cols+j].shareFirst()
                                	out.Data[i*m.Cols+j] = *val
                        	}
			}(out, m, i)
                }
	}

	// if share_id == 2: output 0

	wg.Wait()

        return out
}

// ARITHMETIC OPERATIONS

func MulByConstantInPlace64(m *Matrix[uint64], c uint64) {
        if (c >> 63) & 1 != 0 {
                panic("Code will multiply by a negative number ... is that what you want?")
        }

        var wg sync.WaitGroup

        rows_per_thread := (m.Rows + NUM_VCPUS - 1) / NUM_VCPUS
        for i := uint64(0); i < m.Rows; i += rows_per_thread {
                wg.Add(1)

                go func(m *Matrix[uint64], i, c uint64) {
                        defer wg.Done()
			for i2 := uint64(0); i2 < rows_per_thread; i2++ {
				if i + i2 >= m.Rows {
					break
				}

                        	for j := uint64(0); j < m.Cols; j++ {
                                	m.Data[(i+i2)*m.Cols+j] = (uint64)(((int64)(m.Data[(i+i2)*m.Cols+j])) * int64(c))
                        	}
			}
                }(m, i, c)
        }

        wg.Wait()
}

func DivByConstantInPlace128(m *Matrix[Uint128], c uint64) {
	if (c >> 63) & 1 != 0 {
		panic("Code will divide by a negative number ... is that what you want?")
	}

        var wg sync.WaitGroup

        rows_per_thread := (m.Rows + NUM_VCPUS - 1) / NUM_VCPUS
        for i := uint64(0); i < m.Rows; i += rows_per_thread {
                wg.Add(1)

                go func(m *Matrix[Uint128], i, c uint64) {
                        defer wg.Done()
                        rows := C.Elem64(rows_per_thread)
                        if i + rows_per_thread > m.Rows {
                                rows = C.Elem64(m.Rows - i)
                        }
                        cols := C.Elem64(m.Cols)

                        mPtr := unsafe.Pointer(&m.Data[m.Cols*i])

                        C.divByConstantInPlace((*C.Elem128)(mPtr), C.Elem64(c), rows, cols)
                }(m, i, c)
        }

        wg.Wait()
}

func MulByConstantInPlace128(m *Matrix[Uint128], c uint64) {
        var wg sync.WaitGroup

        rows_per_thread := (m.Rows + NUM_VCPUS - 1) / NUM_VCPUS
        for i := uint64(0); i < m.Rows; i += rows_per_thread {
                wg.Add(1)

                go func(m *Matrix[Uint128], i, c uint64) {
                        defer wg.Done()

                        rows := C.Elem64(rows_per_thread)
                        if i + rows_per_thread > m.Rows {
                                rows = C.Elem64(m.Rows - i)
                        }
                        cols := C.Elem64(m.Cols)
                        mPtr := unsafe.Pointer(&m.Data[m.Cols*i])

                        C.mulByConstantInPlace((*C.Elem128)(mPtr), C.Elem64(c), rows, cols)
                }(m, i, c)
        }
        wg.Wait()
}

func MulByConstantInPlaceRSS128(m *Matrix[Share128], c uint64) {
        var wg sync.WaitGroup

	rows_per_thread := (m.Rows + NUM_VCPUS - 1) / NUM_VCPUS
        for i := uint64(0); i < m.Rows; i += rows_per_thread {
                wg.Add(1)

                go func(m *Matrix[Share128], i, c uint64) {
                        defer wg.Done()

                        rows := C.Elem64(rows_per_thread)
                        if i + rows_per_thread > m.Rows {
                                rows = C.Elem64(m.Rows - i)
                        }
                        cols := C.Elem64(m.Cols)
                        mPtr := unsafe.Pointer(&m.Data[m.Cols*i])

                        C.mulByConstantInPlaceRSS((*C.Elem128)(mPtr), C.Elem64(c), rows, cols)
                }(m, i, c)
        }
        wg.Wait()
}

func MatrixPtxtMul(a *Matrix[uint64], b *Matrix[Share128]) *Matrix[Share128] {
        c := MatrixZeros[Share128](a.Rows, b.Cols) 
	MatrixPtxtMulDst(a, b, c)
	return c
}

func MatrixPtxtMulDst(a *Matrix[uint64], b, c *Matrix[Share128]) { 
        if a.Cols != b.Rows || a.Rows != c.Rows || b.Cols != c.Cols {
                fmt.Printf("Multiplying (%d, %d) and (%d, %d) matrices\n", a.Rows, a.Cols, b.Rows, b.Cols)
                panic("MatrixPtxtMul: Dimension mismatch")
        }

	clear(c.Data)
        var wg sync.WaitGroup
        rows_per_thread := (a.Rows + 192 - 1) / 192

        for i := uint64(0); i < a.Rows; i += rows_per_thread {
                wg.Add(1)

                go func(a *Matrix[uint64], b, c *Matrix[Share128], i uint64) {
                        defer wg.Done()
                        arows := C.Elem64(rows_per_thread)
                        if i + rows_per_thread > a.Rows {
                                arows = C.Elem64(a.Rows - i)
                        }
                        acols := C.Elem64(a.Cols)
                        bcols := C.Elem64(b.Cols)

                        outPtr := unsafe.Pointer(&c.Data[c.Cols*i])
                        aPtr := unsafe.Pointer(&a.Data[a.Cols*i])
                        bPtr := unsafe.Pointer(&b.Data[0])

                        C.matMulPtxtRSS((*C.Elem64)(aPtr), (*C.Elem128)(bPtr), (*C.Elem128)(outPtr), arows, acols, bcols)
                }(a, b, c, i)
        }

        wg.Wait()
}

func MatrixTransposePtxtMul(a *Matrix[uint64], b *Matrix[Share128]) *Matrix[Share128] {
        c := MatrixZeros[Share128](a.Cols, b.Cols) 
	MatrixTransposePtxtMulDst(a, b, c)
	return c
}

func MatrixTransposePtxtMulDst(a *Matrix[uint64], b, c *Matrix[Share128]) {
        if a.Rows != b.Rows || c.Rows != a.Cols || c.Cols != b.Cols {
                fmt.Printf("Multiplying (%d, %d) and (%d, %d) matrices\n", a.Rows, a.Cols, b.Rows, b.Cols)
                panic("MatrixTranposePtxtMul: Dimension mismatch")
        }

	//clear(c.Data) <- performed by C code
        var wg sync.WaitGroup
        cols_per_thread := (a.Cols + NUM_VCPUS - 1) / NUM_VCPUS

        arows := C.Elem64(a.Rows)
        acols := C.Elem64(a.Cols)
        bcols := C.Elem64(b.Cols)

        outPtr := unsafe.Pointer(&c.Data[0])
        aPtr := unsafe.Pointer(&a.Data[0])
        bPtr := unsafe.Pointer(&b.Data[0])

        for i := uint64(0); i < a.Cols; i += cols_per_thread {
                wg.Add(1)

		go func(a *Matrix[uint64], b, c *Matrix[Share128], i uint64) {
			defer wg.Done()

		        astretch := C.Elem64(cols_per_thread)
                        if i + cols_per_thread > a.Cols {
                                astretch = C.Elem64(a.Cols - i)
                        }
                        aoffset := C.Elem64(i)

                        C.matTransposeMulPtxtRSS((*C.Elem64)(aPtr), (*C.Elem128)(bPtr), (*C.Elem128)(outPtr), arows, acols, bcols, aoffset, astretch)
                }(a, b, c, i)
        }

	wg.Wait()
}

func MatrixMul(a, b *Matrix[uint64]) *Matrix[uint64] {
        c := MatrixZeros[uint64](a.Rows, b.Cols)
	MatrixMulDst(a, b, c)
        return c
}

func MatrixMulDst(a, b, c *Matrix[uint64]) {
        if a.Cols != b.Rows || c.Rows != a.Rows || c.Cols != b.Cols {
                fmt.Printf("Multiplying (%d, %d) and (%d, %d) matrices\n", a.Rows, a.Cols, b.Rows, b.Cols)
                panic("MatrixMul: Dimension mismatch")
        }

	clear(c.Data)
        rows_per_thread := (a.Rows + NUM_VCPUS - 1) / NUM_VCPUS

        var wg sync.WaitGroup
        for i := uint64(0); i < a.Rows; i += rows_per_thread {
                wg.Add(1)

                go func(a, b, c *Matrix[uint64], i uint64) {
                        defer wg.Done()

                        for i2 := uint64(0); i2 < rows_per_thread; i2++ {
                                if i + i2 >= a.Rows {
                                        break
                                }

                                for k := uint64(0); k < a.Cols; k++ {
                                        for j := uint64(0); j < b.Cols; j++ {
                                                c.Data[b.Cols*(i+i2)+j] += a.Data[a.Cols*(i+i2)+k] * b.Data[b.Cols*k+j]
                                        }
                                }
                        }
                }(a, b, c, i)
        }

        wg.Wait()
}

func MatrixMul128Dst(a, b, c *Matrix[Uint128]) {
        if a.Cols != b.Rows || c.Rows != a.Rows || c.Cols != b.Cols {
                fmt.Printf("Multiplying (%d, %d) and (%d, %d) matrices\n", a.Rows, a.Cols, b.Rows, b.Cols)
                panic("MatrixMul128: Dimension mismatch")
        }

        clear(c.Data)
        rows_per_thread := (a.Rows + NUM_VCPUS - 1) / NUM_VCPUS

        var wg sync.WaitGroup
        for i := uint64(0); i < a.Rows; i += rows_per_thread {
                wg.Add(1)

                go func(a, b, c *Matrix[Uint128], i uint64) {
                        defer wg.Done()

                        arows := C.Elem64(rows_per_thread)
                        if i + rows_per_thread > a.Rows {
                                arows = C.Elem64(a.Rows - i)
                        }
                        acols := C.Elem64(a.Cols)
                        bcols := C.Elem64(b.Cols)

                        outPtr := unsafe.Pointer(&c.Data[c.Cols*i])
                        aPtr := unsafe.Pointer(&a.Data[a.Cols*i])
                        bPtr := unsafe.Pointer(&b.Data[0])

                        C.matMul((*C.Elem128)(aPtr), (*C.Elem128)(bPtr), (*C.Elem128)(outPtr), arows, acols, bcols)
                }(a, b, c, i)
        }

        wg.Wait()
}

func MatrixMulMixedDst(a *Matrix[uint64], b, c *Matrix[Uint128]) {
        if a.Cols != b.Rows || c.Rows != a.Rows || c.Cols != b.Cols {
                fmt.Printf("Multiplying (%d, %d) and (%d, %d) matrices\n", a.Rows, a.Cols, b.Rows, b.Cols)
                panic("MatrixMul128: Dimension mismatch")
        }

        clear(c.Data)
        rows_per_thread := (a.Rows + NUM_VCPUS - 1) / NUM_VCPUS

        var wg sync.WaitGroup
        for i := uint64(0); i < a.Rows; i += rows_per_thread {
                wg.Add(1)

                go func(a *Matrix[uint64], b, c *Matrix[Uint128], i uint64) {
                        defer wg.Done()

                        arows := C.Elem64(rows_per_thread)
                        if i + rows_per_thread > a.Rows {
                                arows = C.Elem64(a.Rows - i)
                        }
                        acols := C.Elem64(a.Cols)
                        bcols := C.Elem64(b.Cols)

                        outPtr := unsafe.Pointer(&c.Data[c.Cols*i])
                        aPtr := unsafe.Pointer(&a.Data[a.Cols*i])
                        bPtr := unsafe.Pointer(&b.Data[0])

                        C.matMulMixed((*C.Elem64)(aPtr), (*C.Elem128)(bPtr), (*C.Elem128)(outPtr), arows, acols, bcols)
                }(a, b, c, i)
        }

        wg.Wait()
}

// Same functionality as:
// MatrixMul(a.Transpose(), b)
func MatrixTransposeMul(a, b *Matrix[uint64]) *Matrix[uint64] {
        c := MatrixZeros[uint64](a.Cols, b.Cols)
	MatrixTransposeMulDst(a, b, c)
	return c
}

// Same functionality as:
// MatrixMulDst(a.Transpose(), b, c)
func MatrixTransposeMulDst(a, b, c *Matrix[uint64]) *Matrix[uint64] {
        if a.Rows != b.Rows || c.Rows != a.Cols || c.Cols != b.Cols {
                fmt.Printf("Multiplying (%d, %d) and (%d, %d) matrices\n", a.Rows, a.Cols, b.Rows, b.Cols)
                panic("MatrixMul: Dimension mismatch")
        }

	clear(c.Data)
        cols_per_thread := (a.Cols + NUM_VCPUS - 1) / NUM_VCPUS

        var wg sync.WaitGroup
        for i := uint64(0); i < a.Cols; i += cols_per_thread {
                wg.Add(1)

                go func(a, b, c *Matrix[uint64], i uint64) {
                        defer wg.Done()

			for i2 := uint64(0); i2 < cols_per_thread; i2++ {
				if i + i2 >= a.Cols {
					break
				}
				
                        	for k := uint64(0); k < a.Rows; k++ {
                                	for j := uint64(0); j < b.Cols; j++ {
                                        	c.Data[b.Cols*(i+i2) + j] += a.Data[a.Cols*k+(i+i2)] * b.Data[b.Cols*k+j]
					}
                                }
                        }
                }(a, b, c, i)
        }

        wg.Wait()

        return c
}

func MatrixTransposeMul128Dst(a, b, c *Matrix[Uint128]) *Matrix[Uint128] {
        if a.Rows != b.Rows || c.Rows != a.Cols || c.Cols != b.Cols {
                fmt.Printf("Multiplying (%d, %d) and (%d, %d) matrices\n", a.Rows, a.Cols, b.Rows, b.Cols)
                panic("MatrixMul: Dimension mismatch")
        }

        clear(c.Data)
        cols_per_thread := (a.Cols + NUM_VCPUS - 1) / NUM_VCPUS

        var wg sync.WaitGroup
        for i := uint64(0); i < a.Cols; i += cols_per_thread {
                wg.Add(1)

                go func(a, b, c *Matrix[Uint128], i uint64) {
                        defer wg.Done()

                        astretch := C.Elem64(cols_per_thread)
                        if i + cols_per_thread > a.Cols {
                                astretch = C.Elem64(a.Cols - i)
                        }
                        arows := C.Elem64(a.Rows)
                        acols := C.Elem64(a.Cols)
                        bcols := C.Elem64(b.Cols)
                        aoffset := C.Elem64(i)

                        outPtr := unsafe.Pointer(&c.Data[0])
                        aPtr := unsafe.Pointer(&a.Data[0])
                        bPtr := unsafe.Pointer(&b.Data[0])

                        C.matTransposeMul((*C.Elem128)(aPtr), (*C.Elem128)(bPtr), (*C.Elem128)(outPtr), arows, acols, bcols, aoffset, astretch)
                }(a, b, c, i)
        }

        wg.Wait()

        return c
}

func MatrixMulRSS(a *Matrix[Share128], b *Matrix[Share128]) *Matrix[Uint128] {
	c := MatrixZeros[Uint128](a.Rows, b.Cols)
	MatrixMulRSSDst(a, b, c)
	return c
}

func MatrixMulRSSDst(a, b *Matrix[Share128], c *Matrix[Uint128]) {
        if a.Cols != b.Rows || c.Rows != a.Rows || c.Cols != b.Cols {
                fmt.Printf("Multiplying (%d, %d) and (%d, %d) matrices\n", a.Rows, a.Cols, b.Rows, b.Cols)
                panic("MatrixMulRSS: Dimension mismatch")
        }

	clear(c.Data)

        var wg sync.WaitGroup
	rows_per_thread := (a.Rows + NUM_VCPUS - 1) / NUM_VCPUS

        for i := uint64(0); i < a.Rows; i += rows_per_thread {
                wg.Add(1)

                go func(a, b *Matrix[Share128], c *Matrix[Uint128], i uint64) {
                        defer wg.Done()

			arows := C.Elem64(rows_per_thread)
			if i + rows_per_thread > a.Rows {
				arows = C.Elem64(a.Rows - i)
			}
			acols := C.Elem64(a.Cols)
			bcols := C.Elem64(b.Cols)
	
			outPtr := unsafe.Pointer(&c.Data[c.Cols*i])
			aPtr := unsafe.Pointer(&a.Data[a.Cols*i])
			bPtr := unsafe.Pointer(&b.Data[0])

			C.matMulRSS((*C.Elem128)(aPtr), (*C.Elem128)(bPtr), (*C.Elem128)(outPtr), arows, acols, bcols)
                }(a, b, c, i)
        }

        wg.Wait()
}

func MatrixCheckZeroOneRSS(a *Matrix[Share128], share_id int, pool *PrgPool) *Uint128 {
        var wg sync.WaitGroup
        rows_per_thread := (a.Rows + NUM_VCPUS - 1) / NUM_VCPUS

	var mu sync.Mutex
	sum := MakeUint128(0, 0)

        for i := uint64(0); i < a.Rows; i += rows_per_thread {
                wg.Add(1)

                go func(a *Matrix[Share128], i uint64) {
                        defer wg.Done()
			prg := pool.At(i / rows_per_thread)

			var upper, lower uint64
			local_sum := MakeUint128(0, 0)
			tmp := new(Share128)
			out := MakeUint128(0, 0)
			one := MakeUint128(0, 1)

			for i2 := uint64(0); i2 < rows_per_thread; i2++ {
				if i+i2 >= a.Rows {
					break
				}

				Clear(local_sum)

				for j := uint64(0); j < a.Cols; j++ {
					upper, lower = prg.TwoUint64()
					coeff := MakeUint128(upper, lower)

					PtxtSubRSSDst128(a.Get(i+i2, j), one, share_id, tmp)
					largePtxtMulRSSInPlace128(tmp, coeff) 
					MulRSS128Dst(a.Get(i+i2, j), tmp, out)

					local_sum.AddInPlace(out) // running sum of random linear combination
				}
			}

			mu.Lock()
			sum.AddInPlace(local_sum)
			mu.Unlock()
                }(a, i)
        }

        wg.Wait()

	return sum
}

func MatrixScalarMulRSS(s *Share128, m *Matrix[Share128]) *Matrix[Uint128] {
	out :=  MatrixZeros[Uint128](m.Rows, m.Cols)

        var wg sync.WaitGroup
        rows_per_thread := (m.Rows + NUM_VCPUS - 1) / NUM_VCPUS

        for i := uint64(0); i < m.Rows; i += rows_per_thread {
                wg.Add(1)

                go func(m *Matrix[Share128], out *Matrix[Uint128], s *Share128, i uint64) {
                        defer wg.Done()

			for index := i; (index < i + rows_per_thread) && (index < m.Rows); index++ {
				for j := uint64(0); j < m.Cols; j++ {
					MulRSS128Dst(m.Get(index, j), s, out.Get(index, j))
				}
			}
                }(m, out, s, i)
        }

        wg.Wait()
	return out
}

// Same functionality as: 
// MatrixMulRSS(a.Transpose(), b)
// ... but wrote a method for it to avoid creating intermediate copies
func MatrixTransposeMulRSS(a *Matrix[Share128], b *Matrix[Share128]) *Matrix[Uint128] {
        c := MatrixZeros[Uint128](a.Cols, b.Cols)
	MatrixTransposeMulRSSDst(a, b, c)
        return c
}

func MatrixTransposeMulRSSDst(a, b *Matrix[Share128], c *Matrix[Uint128]) {
        if a.Rows != b.Rows || b.Cols != c.Cols || c.Rows != a.Cols {
                fmt.Printf("Multiplying (%d, %d) and (%d, %d) matrices\n", a.Rows, a.Cols, b.Rows, b.Cols)
                panic("MatrixMulRSS: Dimension mismatch")
        }

	clear(c.Data)

        var wg sync.WaitGroup
	cols_per_thread := (a.Cols + NUM_VCPUS - 1) / NUM_VCPUS

        for i := uint64(0); i < a.Cols; i += cols_per_thread {
                wg.Add(1)

                go func(a, b *Matrix[Share128], c *Matrix[Uint128], i uint64) {
                        defer wg.Done()

			if i >= a.Cols {
				return
			}

                        astretch := C.Elem64(cols_per_thread)
                        if i + cols_per_thread > a.Cols {
                                astretch = C.Elem64(a.Cols - i)
                        }

                        arows := C.Elem64(a.Rows)
			acols := C.Elem64(a.Cols)
                        bcols := C.Elem64(b.Cols)
			aoffset := C.Elem64(i)

                        outPtr := unsafe.Pointer(&c.Data[0])
                        aPtr := unsafe.Pointer(&a.Data[0])
                        bPtr := unsafe.Pointer(&b.Data[0])

                        C.matTransposeMulRSS((*C.Elem128)(aPtr), (*C.Elem128)(bPtr), (*C.Elem128)(outPtr), arows, acols, bcols, aoffset, astretch)
                }(a, b, c, i)
        }

        wg.Wait()
}

// Note: even is b is a Matrix[uint64], its values are cast to 128-bits in the multiplication,
// to make sure that negative values are correctly handled.
func MatrixMulRSSPtxt(a *Matrix[Share128], b *Matrix[uint64]) *Matrix[Share128] {
        c := MatrixZeros[Share128](a.Rows, b.Cols)
	MatrixMulRSSPtxtDst(a, b, c)
        return c
}

func MatrixMulRSSPtxtDst(a *Matrix[Share128], b *Matrix[uint64], c *Matrix[Share128]) {
        if a.Cols != b.Rows || c.Rows != a.Rows || c.Cols != b.Cols {
                fmt.Printf("Multiplying (%d, %d) and (%d, %d) matrices\n", a.Rows, a.Cols, b.Rows, b.Cols)
                panic("MatrixMulRSSPtxt: Dimension mismatch")
        }

	clear(c.Data)
        var wg sync.WaitGroup
	rows_per_thread := (a.Rows + NUM_VCPUS - 1) / NUM_VCPUS

        for i := uint64(0); i < a.Rows; i += rows_per_thread {
                wg.Add(1)

                go func(a *Matrix[Share128], b *Matrix[uint64], c *Matrix[Share128], i uint64) {
                        defer wg.Done()

                        arows := C.Elem64(rows_per_thread)
                        if i + rows_per_thread > a.Rows {
                                arows = C.Elem64(a.Rows - i)
                        }
                        acols := C.Elem64(a.Cols) 
                        bcols := C.Elem64(b.Cols)

                        outPtr := unsafe.Pointer(&c.Data[c.Cols*i])
                        aPtr := unsafe.Pointer(&a.Data[a.Cols*i])
                        bPtr := unsafe.Pointer(&b.Data[0])

                        C.matMulRSSPtxt((*C.Elem128)(aPtr), (*C.Elem64)(bPtr), (*C.Elem128)(outPtr), arows, acols, bcols)
                }(a, b, c, i)
        }

        wg.Wait()
}

// Same as MatrixMulRSSPtxt(a, b) -> v
//   then, MatrixMulSubRSS(c, v, rows_st, row_end)
func MatrixMulSubRSSInPlaceAt(c, a *Matrix[Share128], b *Matrix[uint64], row_st, row_end uint64) {
        if !(a.Cols == b.Rows && b.Cols == c.Cols) {
                fmt.Printf("(%d, %d) with row_start = %d, row_end = %d vs. (%d, %d) x (%d, %d) matrices\n",
                           c.Rows, c.Cols, row_st, row_end, a.Rows, a.Cols, b.Rows, b.Cols)
                panic("MatrixMulSubRSSInPlaceAt: Input matrix dimensions do not match")
        }

        if (row_end - row_st > c.Rows) {
                panic("MatrixMulSubRSSInPlaceAt: bad row_end and row_st")
        }

        var wg sync.WaitGroup
	rows_per_thread := (row_end - row_st + NUM_VCPUS - 1) / NUM_VCPUS

        for i := uint64(0); i < row_end - row_st; i += rows_per_thread {
                wg.Add(1)

                go func(i uint64) {
                        defer wg.Done()

                        arows := C.Elem64(rows_per_thread)
                        if i + rows_per_thread > row_end - row_st {
                                arows = C.Elem64(row_end - row_st - i)
                        }
                        acols := C.Elem64(a.Cols)
                        bcols := C.Elem64(b.Cols)
			outcols := C.Elem64(c.Cols)

                        outPtr := unsafe.Pointer(&c.Data[c.Cols*(i+row_st)])
                        aPtr := unsafe.Pointer(&a.Data[a.Cols*i])
                        bPtr := unsafe.Pointer(&b.Data[0])

			C.matMulSubRSSAt((*C.Elem128)(aPtr), (*C.Elem64)(bPtr), (*C.Elem128)(outPtr), arows, acols, bcols, outcols)
                }(i)
        }

        wg.Wait()
}

// Note: even is b is a Matrix[uint64], its values are cast to 128-bits in the multiplication,
// to make sure that negative values are correctly handled.
func MatrixMulAdditivePtxt[T UintElem](a *Matrix[Uint128], b *Matrix[T]) *Matrix[Uint128] {
        if a.Cols != b.Rows {
                fmt.Printf("Multiplying (%d, %d) and (%d, %d) matrices\n", a.Rows, a.Cols, b.Rows, b.Cols)
                panic("MatrixMulAdditivePtxt: Dimension mismatch")
        }

        c := MatrixZeros[Uint128](a.Rows, b.Cols)

	var wg sync.WaitGroup
        for i := uint64(0); i < a.Rows; i++ {
		wg.Add(1)

		go func(a *Matrix[Uint128], b *Matrix[T], c *Matrix[Uint128], i uint64) {
			defer wg.Done()
                	for k := uint64(0); k < a.Cols; k++ {
                	        for j := uint64(0); j < b.Cols; j++ {
					switch mul_by := any(&b.Data[b.Cols*k+j]).(type) {
					case *uint64:
						// this code casts up to Uint128 so that signs handled correctly!
						val := ToUint128(*mul_by)
	                                	val.MulInPlace(&a.Data[a.Cols*i+k])
        	                        	c.Data[b.Cols*i + j].AddInPlace(val)
					case *Uint128:
                               		 	mul_by.MulInPlace(&a.Data[a.Cols*i+k])
                                		c.Data[b.Cols*i + j].AddInPlace(mul_by)
					default:
						panic("Hit default case.")
					}
				}
                        }
                }(a, b, c, i)
        }

	wg.Wait()
        return c
}

func MatrixMulAdditivePtxtTransposed[T UintElem](a *Matrix[Uint128], b *Matrix[T]) *Matrix[Uint128] {
        if a.Cols != b.Cols {
                fmt.Printf("Multiplying (%d, %d) and (%d, %d) matrices\n", a.Rows, a.Cols, b.Rows, b.Cols)
                panic("MatrixMulAdditivePtxtTransposed: Dimension mismatch")
        }

        c := MatrixZeros[Uint128](a.Rows, b.Rows)

        var wg sync.WaitGroup
        for i := uint64(0); i < a.Rows; i++ {
                wg.Add(1)

                go func(a *Matrix[Uint128], b *Matrix[T], c *Matrix[Uint128], i uint64) {
                        defer wg.Done()
                        for k := uint64(0); k < a.Cols; k++ {
                                for j := uint64(0); j < b.Rows; j++ {
					// want actual value in B.T at b.Rows*k+j --> in B at b.Cols*j+k
                                        switch mul_by := any(&b.Data[b.Cols*j+k]).(type) {
                                        case *uint64:
                                                // this code casts up to Uint128 so that signs handled 
                                                val := ToUint128(*mul_by)
                                                val.MulInPlace(&a.Data[a.Cols*i+k])
                                                c.Data[b.Rows*i + j].AddInPlace(val)
                                        case *Uint128:
                                                mul_by.MulInPlace(&a.Data[a.Cols*i+k])
                                                c.Data[b.Rows*i + j].AddInPlace(mul_by)
                                        default:
                                                panic("Hit default case.")
                                        }
                                }
                        }
                }(a, b, c, i)
        }

        wg.Wait()

	return c
}

func MatrixAddRSSInPlace(m0, m1 *Matrix[Share128]) {
        if !(m1.Rows == m0.Rows && m1.Cols == m0.Cols) {
		fmt.Printf("Adding (%d, %d) and (%d, %d) matrices\n", m0.Rows, m0.Cols, m1.Rows, m1.Cols)
                panic("MatrixAddRSSInPlace: Input matrix dimensions do not match")
        }

	var wg sync.WaitGroup
        for i := uint64(0); i < m0.Rows; i++ {
		wg.Add(1)

		go func(m0, m1 *Matrix[Share128], i uint64) {
			defer wg.Done()
                	for j := uint64(0); j < m0.Cols; j++ {
				AddRSSInPlace128(&m0.Data[i*m0.Cols+j], &m1.Data[i*m0.Cols+j])
                	}
		}(m0, m1, i)
        }

	wg.Wait()
}

func MatrixAddInPlace128(ms ...*Matrix[Uint128]) *Matrix[Uint128] {
        rows := ms[0].Rows
        cols := ms[0].Cols
        sum := ms[0]

        // Compute sum of all matrices
	var wg sync.WaitGroup
        for i, m := range ms {
                if i > 0 {
                        if m.Rows != rows || m.Cols != cols {
                                panic("MatrixAddInPlace: dimension mismatch")
                        }

                        for i := uint64(0); i < rows; i++ {
				wg.Add(1)

				go func(sum, m *Matrix[Uint128], i uint64) {
					defer wg.Done()
                                	for j := uint64(0); j < cols; j++ {
                                        	sum.Data[i*cols+j].AddInPlace(&m.Data[i*cols+j])
					}
                                }(sum, m, i)
                        }
			wg.Wait()
                }
        }

        return sum
}

func MatrixAddInPlaceShrink(ms ...*Matrix[Uint128]) *Matrix[uint64] {
	MatrixAddInPlace128(ms...)
        return ToMatrix64(ms[0])
}

func MatrixAddInPlace64(ms ...*Matrix[uint64]) *Matrix[uint64] {
        rows := ms[0].Rows
        cols := ms[0].Cols
        sum := ms[0]

        // Compute sum of all matrices
	var wg sync.WaitGroup
        for i, m := range ms {
                if i > 0 {
                        if m.Rows != rows || m.Cols != cols {
                                panic("MatrixAddInPlace: dimension mismatch")
                        }

                        for i := uint64(0); i < rows; i++ {
				wg.Add(1)

				go func(sum, m *Matrix[uint64], i uint64) {
					defer wg.Done()
                                	for j := uint64(0); j < cols; j++ {
                                        	sum.Data[i*cols+j] = sum.Data[i*cols+j] + m.Data[i*cols+j]
					}
                                }(sum, m, i)
                        }
			wg.Wait()
                }
        }

        return sum
}

func MatrixSum(m *Matrix[Uint128]) *Uint128 {
        sum := MakeUint128(0, 0)

        for i := uint64(0); i < m.Rows; i++ {
                for j := uint64(0); j < m.Cols; j++ {
                        sum.AddInPlace(&m.Data[i*m.Cols+j])
                }
        }

        return sum
}

func MatrixSubInPlace(m0, m1 *Matrix[uint64]) {
        if !(m1.Rows == m0.Rows && m1.Cols == m0.Cols) {
                fmt.Printf("Adding (%d, %d) and (%d, %d) matrices\n", m0.Rows, m0.Cols, m1.Rows, m1.Cols)
                panic("MatrixAddRSSInPlace: Input matrix dimensions do not match")
        }

        var wg sync.WaitGroup
        rows_per_thread := (m0.Rows + NUM_VCPUS - 1) / NUM_VCPUS

        for i := uint64(0); i < m0.Rows; i += rows_per_thread {
                wg.Add(1)

                go func(m0, m1 *Matrix[uint64], i uint64) {
                        defer wg.Done()

			for i2 := uint64(0); i2 < rows_per_thread; i2++ {
				if i + i2 >= m0.Rows {
					break
				}
				for j := uint64(0); j < m0.Cols; j++ {
					m0.Data[(i+i2)*m0.Cols+j] -= m1.Data[(i+i2)*m0.Cols+j]
				}
			}
                }(m0, m1, i)
        }

        wg.Wait()
}

func MatrixAddScalarInPlace(m *Matrix[uint64], c uint64) {
        var wg sync.WaitGroup
        rows_per_thread := (m.Rows + NUM_VCPUS - 1) / NUM_VCPUS

        for i := uint64(0); i < m.Rows; i += rows_per_thread {
                wg.Add(1)

                go func(m *Matrix[uint64], c, i uint64) {
                        defer wg.Done()

                        for i2 := uint64(0); i2 < rows_per_thread; i2++ {
                                if i + i2 >= m.Rows {
                                        break
                                }
                                for j := uint64(0); j < m.Cols; j++ {
                                        m.Data[(i+i2)*m.Cols+j] += c
                                }
                        }
                }(m, c, i)
        }

        wg.Wait()
}

func MatrixSubScalarInPlace(m *Matrix[uint64], c uint64) {
        var wg sync.WaitGroup
        rows_per_thread := (m.Rows + NUM_VCPUS - 1) / NUM_VCPUS

        for i := uint64(0); i < m.Rows; i += rows_per_thread {
                wg.Add(1)

                go func(m *Matrix[uint64], c, i uint64) {
                        defer wg.Done()

                        for i2 := uint64(0); i2 < rows_per_thread; i2++ {
                                if i + i2 >= m.Rows {
                                        break
                                }
                                for j := uint64(0); j < m.Cols; j++ {
                                        m.Data[(i+i2)*m.Cols+j] -= c
                                }
                        }
                }(m, c, i)
        }

        wg.Wait()
}

func MatrixRSSSubScalarInPlace(m *Matrix[Share128], c uint64, share_id int) {
	if share_id == 0 {
		return
	}

        var wg sync.WaitGroup
        rows_per_thread := (m.Rows + NUM_VCPUS - 1) / NUM_VCPUS

        for i := uint64(0); i < m.Rows; i += rows_per_thread {
                wg.Add(1)

                go func(m *Matrix[Share128], c, i uint64) {
                        defer wg.Done()
			scalar := ToUint128(c)

                        for i2 := uint64(0); i2 < rows_per_thread; i2++ {
                                if i + i2 >= m.Rows {
                                        break
                                }
                                for j := uint64(0); j < m.Cols; j++ {
					if share_id == 1 {
                                        	m.Data[(i+i2)*m.Cols+j].First.SubInPlace(scalar)
					} else if share_id == 2 {
                                        	m.Data[(i+i2)*m.Cols+j].Second.SubInPlace(scalar)
					}
                                }
                        }
                }(m, c, i)
        }

        wg.Wait()
}

func MatrixSubRSSInPlace(m0, m1 *Matrix[Share128]) {
        if !(m1.Rows == m0.Rows && m1.Cols == m0.Cols) {
                fmt.Printf("Adding (%d, %d) and (%d, %d) matrices\n", m0.Rows, m0.Cols, m1.Rows, m1.Cols)
                panic("MatrixAddRSSInPlace: Input matrix dimensions do not match")
        }

	var wg sync.WaitGroup
        rows_per_thread := (m0.Rows + NUM_VCPUS - 1) / NUM_VCPUS

	cols := C.Elem64(m0.Cols)

        for i := uint64(0); i < m0.Rows; i += rows_per_thread {
		wg.Add(1)

		go func(m0, m1 *Matrix[Share128], i uint64) {
			defer wg.Done()

                        rows := C.Elem64(rows_per_thread)
                        if i + rows_per_thread > m0.Rows {
                                rows = C.Elem64(m0.Rows - i)
                        }

			mPtr := unsafe.Pointer(&m0.Data[m0.Cols*i])
                        subPtr := unsafe.Pointer(&m1.Data[m1.Cols*i])

                        C.matSubRSS((*C.Elem128)(mPtr), (*C.Elem128)(subPtr), rows, cols)
		}(m0, m1, i)
        }

	wg.Wait()
}

// SECERT SHARE TRUNCATION AND DIVISION

func MatrixTruncateRSS(m0, m1, m2 *Matrix[Share128], decimals uint, pool *PrgPool, perf *PerfLog) (*Matrix[Share128], *Matrix[Share128], *Matrix[Share128]) {
        out0 := MatrixZeros[Share128](m0.Rows, m0.Cols)
        out1 := MatrixZeros[Share128](m0.Rows, m0.Cols)
        out2 := MatrixZeros[Share128](m0.Rows, m0.Cols)

	MatrixTruncateRSSDst(m0, m1, m2, out0, out1, out2, decimals, pool, perf)

        return out0, out1, out2
}

func MatrixTruncateRSSInPlace(m0, m1, m2 *Matrix[Share128], decimals uint, pool *PrgPool, perf *PerfLog) {
        rows := m0.Rows
        cols := m0.Cols

        if !(m1.Rows == rows && m1.Cols == cols && m2.Rows == rows && m2.Cols == cols) {
                panic("MatrixTruncateRSS: Input matrix dimensions do not match")
        }

        var wg sync.WaitGroup
	rows_per_thread := (rows + NUM_VCPUS - 1) / NUM_VCPUS

	at := uint64(0)
        for i := uint64(0); i < rows; i += rows_per_thread {
                wg.Add(1)

                go func(m0, m1, m2 *Matrix[Share128], i uint64, ownPRG *BufPRGReader) {
                        defer wg.Done()
			var a0, a1, a2 *Uint128

			for k := uint64(0); k < rows_per_thread; k++ {
				if i + k >= rows {
					break
				}

                        	for j := uint64(0); j < cols; j++ {
					a0, a1, a2 = truncateRSSToAdditive128(&m0.Data[(i+k)*cols+j], &m1.Data[(i+k)*cols+j], &m2.Data[(i+k)*cols+j], decimals, ownPRG)
					AdditiveToRSS128Dst(a0, a1, a2, &m0.Data[(i+k)*cols+j], &m1.Data[(i+k)*cols+j], &m2.Data[(i+k)*cols+j], ownPRG)
                        	}
			}
                }(m0, m1, m2, i, pool.At(at))

		at += 1
        }
        wg.Wait()

	perf.IncrementCommDealer(m0.NEntries() * (2 * 16 + dcf.ByteLen(128, uint64(decimals), true))) // send 2 128-bit values per matrix entry
	perf.IncrementCommThreeServers(m0.NEntries() * 16) // Additive to RSS
}

func MatrixTruncateAdditiveInPlace(m0, m1, m2 *Matrix[Uint128], decimals, dealer uint, pool *PrgPool, perf *PerfLog) {
        rows := m0.Rows
        cols := m0.Cols

        if !(m1.Rows == rows && m1.Cols == cols && m2.Rows == rows && m2.Cols == cols) {
                panic("MatrixTruncateAdditive: Input matrix dimensions do not match")
        }

        var wg sync.WaitGroup
        rows_per_thread := (rows + NUM_VCPUS - 1) / NUM_VCPUS

        at := uint64(0)
        for i := uint64(0); i < rows; i += rows_per_thread {
                wg.Add(1)

                go func(m0, m1, m2 *Matrix[Uint128], i uint64, ownPRG *BufPRGReader) {
                        defer wg.Done()

                        for k := uint64(0); k < rows_per_thread; k++ {
                                if i + k >= rows {
                                        break
                                }

                                for j := uint64(0); j < cols; j++ {
                                        truncateAdditive2To3Inplace128(&m0.Data[(i+k)*cols+j], &m1.Data[(i+k)*cols+j], &m2.Data[(i+k)*cols+j], decimals, dealer, ownPRG)
                                }
                        }
                }(m0, m1, m2, i, pool.At(at))

                at += 1
        }
        wg.Wait()

        perf.IncrementCommDealer(m0.NEntries() * (2 * 16 + dcf.ByteLen(128, uint64(decimals), true))) // send 2 128-bit values per matrix entry
}

func MatrixTruncateRSSDst(m0, m1, m2, out0, out1, out2 *Matrix[Share128], decimals uint, pool *PrgPool, perf *PerfLog) {
        rows := m0.Rows
        cols := m0.Cols

        if !(m1.Rows == rows && m1.Cols == cols && m2.Rows == rows && m2.Cols == cols) ||
	   !(out0.Rows == rows && out0.Cols == cols && out1.Rows == rows && out1.Cols == cols && out2.Rows == rows && out2.Cols == cols) {
                panic("MatrixTruncateRSS: Input matrix dimensions do not match")
        }

        var wg sync.WaitGroup
	rows_per_thread := (rows + NUM_VCPUS - 1) / NUM_VCPUS

	at := uint64(0)
        for i := uint64(0); i < rows; i += rows_per_thread {
                wg.Add(1)

                go func(out0, out1, out2, m0, m1, m2 *Matrix[Share128], i uint64, ownPRG *BufPRGReader) {
                        defer wg.Done()
			var a0, a1, a2 *Uint128

			for k := uint64(0); k < rows_per_thread; k++ {
				if i + k >= rows {
					break
				}

        	                for j := uint64(0); j < cols; j++ {
					a0, a1, a2 = truncateRSSToAdditive128(&m0.Data[(i+k)*cols+j], &m1.Data[(i+k)*cols+j], &m2.Data[(i+k)*cols+j], decimals, ownPRG)
					AdditiveToRSS128Dst(a0, a1, a2, &out0.Data[(i+k)*cols+j], &out1.Data[(i+k)*cols+j], &out2.Data[(i+k)*cols+j], ownPRG)
                        	}
			}
                }(out0, out1, out2, m0, m1, m2, i, pool.At(at))

		at += 1
        }

        wg.Wait()

	perf.IncrementCommDealer(m0.NEntries() * (2 * 16 + dcf.ByteLen(128, uint64(decimals), true))) // send 2 128-bit values per matrix entry
	perf.IncrementCommThreeServers(m0.NEntries() * 16) // Additive to RSS
}

func VectorNormalizeRSSInPlace(v0, v1, v2 *Matrix[Share128], decimals, norm_decimals, newton_iters uint, pool *PrgPool, perf *PerfLog) {
	if v0.Rows != v1.Rows || v1.Rows != v2.Rows || v0.Cols != 1 || v1.Cols != 1 || v2.Cols != 1 {
		panic("VectorNormalizeRSSInPlace: Bad dimensions!")
	}

	// Build Additive shares of ||v||^2
        vsq_additive0 := MatrixSum(MatrixTransposeMulRSS(v0, v0)) // same as v0.T * v0
        vsq_additive1 := MatrixSum(MatrixTransposeMulRSS(v1, v1))
        vsq_additive2 := MatrixSum(MatrixTransposeMulRSS(v2, v2))

	// Build RSS shares of ||v||^2
	prg := pool.At(0)
	vsq_0, vsq_1, vsq_2 := AdditiveToRSS128(vsq_additive0, vsq_additive1, vsq_additive2, prg)
	perf.IncrementCommThreeServers(16)

	// Truncate RSS shares of ||v||^2
        vsq_additive0, vsq_additive1, vsq_additive2 = truncateRSSToAdditive128(vsq_0, vsq_1, vsq_2, decimals, prg)
	perf.IncrementCommDealer(2 * 16 + dcf.ByteLen(128, uint64(decimals), true))

	// ... and back to RSS shares
	vsq_0, vsq_1, vsq_2 = AdditiveToRSS128(vsq_additive0, vsq_additive1, vsq_additive2, prg)
        perf.IncrementCommThreeServers(16)

	// Get secret shares of bitlen of ||v||^2 
	r := vsq_0.ShareSum()
	r.NegateInPlace()
        y := &vsq_1.First
        if DebugMode && !(y.Equals(&vsq_2.Second)) {
                panic("VectorNormalizeRSSInPlace: should not happen")
        }

	keyL, keyR := dmsb.Gen128(r, 128)
	evalL := dmsb.Eval128(keyL, y, 128, 0)
        evalR := dmsb.Eval128(keyR, y, 128, 1)
	perf.IncrementCommDealer(dmsb.ByteLen(128, 128))

	// Non-interactively: Get shares of 2^{-MSB(||v||^2)/2}
	sumL := MakeUint128(0, 0)
	sumR := MakeUint128(0, 0)
	for i := 0; i < 128; i++ {
		coeff := MakeUint128(0, 0)

		index := 127 - i - int(decimals) 
		index /= 2 // NOTE: This is a floor instead of a ceil
		if int(norm_decimals) >= index {
			coeff = MakeUint128(0, 1)
			coeff.LshInPlace(uint(int(norm_decimals) - index))
		}
		evalL[i].MulInPlace(coeff)
		evalR[i].MulInPlace(coeff)

		sumL.AddInPlace(&evalL[i])
		sumR.AddInPlace(&evalR[i])
	}

	// Make RSS shares of starting point to Newton iteration
	y_cur0, y_cur1, y_cur2 := AdditiveToRSS128(MakeUint128(0, 0), sumL, sumR, prg)
	perf.IncrementCommThreeServers(16)

	// Perform Newton iteration to refine approximation
	for i := uint(0); i < newton_iters; i++ {
		// (1) perform x * y
		x_times_y_add0 := MulRSS128(y_cur0, vsq_0)
		x_times_y_add1 := MulRSS128(y_cur1, vsq_1)
		x_times_y_add2 := MulRSS128(y_cur2, vsq_2)

		// to RSS
		x_times_y0, x_times_y1, x_times_y2 := AdditiveToRSS128(x_times_y_add0, x_times_y_add1, x_times_y_add2, prg)
		perf.IncrementCommThreeServers(16)

		// truncate (after mul...)
		x_times_y_add0, x_times_y_add1, x_times_y_add2 = truncateRSSToAdditive128(x_times_y0, x_times_y1, x_times_y2, decimals, prg)
		perf.IncrementCommDealer(2 * 16 + dcf.ByteLen(128, uint64(decimals), true))

		// to RSS
		x_times_y0, x_times_y1, x_times_y2 = AdditiveToRSS128(x_times_y_add0, x_times_y_add1, x_times_y_add2, prg)
                perf.IncrementCommThreeServers(16)

		// (2) perform x * y * y
		x_times_ysq_add0 := MulRSS128(y_cur0, x_times_y0)
                x_times_ysq_add1 := MulRSS128(y_cur1, x_times_y1)
                x_times_ysq_add2 := MulRSS128(y_cur2, x_times_y2)

                // to RSS
                x_times_ysq0, x_times_ysq1, x_times_ysq2 := AdditiveToRSS128(x_times_ysq_add0, x_times_ysq_add1, x_times_ysq_add2, prg)
                perf.IncrementCommThreeServers(16)

                // truncate (after mul...)
                x_times_ysq_add0, x_times_ysq_add1, x_times_ysq_add2 = truncateRSSToAdditive128(x_times_ysq0, x_times_ysq1, x_times_ysq2, norm_decimals, prg)
                perf.IncrementCommDealer(2 * 16 + dcf.ByteLen(128, uint64(norm_decimals), true))

                // to RSS
                x_times_ysq0, x_times_ysq1, x_times_ysq2 = AdditiveToRSS128(x_times_ysq_add0, x_times_ysq_add1, x_times_ysq_add2, prg)
                perf.IncrementCommThreeServers(16)

		// (3) perform y * (3 - x * y * y) / 2
		three := MakeUint128(0, 3)
		three.LshInPlace(norm_decimals)
		PtxtSubRSSInPlace128(x_times_ysq0, three, 0) // compute shares of 3-x
		PtxtSubRSSInPlace128(x_times_ysq1, three, 1) // compute shares of 3-x
		PtxtSubRSSInPlace128(x_times_ysq2, three, 2) // compute shares of 3-x

		outer_add0 := MulRSS128(y_cur0, x_times_ysq0)
		outer_add1 := MulRSS128(y_cur1, x_times_ysq1)
		outer_add2 := MulRSS128(y_cur2, x_times_ysq2)

		// to RSS
		outer0, outer1, outer2 := AdditiveToRSS128(outer_add0, outer_add1, outer_add2, prg)
                perf.IncrementCommThreeServers(16)

                // truncate (after mul...)
                outer_add0, outer_add1, outer_add2 = truncateRSSToAdditive128(outer0, outer1, outer2, norm_decimals+1, prg)
                perf.IncrementCommDealer(2 * 16 + dcf.ByteLen(128, uint64(norm_decimals+1), true))

                // to RSS
                y_cur0, y_cur1, y_cur2 = AdditiveToRSS128(outer_add0, outer_add1, outer_add2, prg)
                perf.IncrementCommThreeServers(16)
	}

	// multiply by vector
	u_add0 := MatrixScalarMulRSS(y_cur0, v0)
	u_add1 := MatrixScalarMulRSS(y_cur1, v1)
	u_add2 := MatrixScalarMulRSS(y_cur2, v2)

	// to RSS
	MatrixAdditiveToRSSDst(u_add0, u_add1, u_add2, v0, v1, v2, pool, perf)

	// truncate again
	MatrixTruncateRSSInPlace(v0, v1, v2, norm_decimals, pool, perf)
}

// BIT OPERATIONS ON MATRICES

func MatrixRsh(m *Matrix[uint64], decimals int) *Matrix[uint64] {
	out := MatrixZeros[uint64](m.Rows, m.Cols)

	var wg sync.WaitGroup
	for i := uint64(0); i < m.Rows; i++ {
		wg.Add(1)

		go func(out, m *Matrix[uint64], i uint64) {
			defer wg.Done()
			for j := uint64(0); j < m.Cols; j++ {
				out.Data[i*m.Cols+j] = (m.Data[i*m.Cols+j] >> decimals)
			}
		}(out, m, i)
	}

	wg.Wait()

	return out
}

func MatrixSignedRoundInPlace(m *Matrix[uint64], divide_by int) {
	var wg sync.WaitGroup
	rows_per_thread := (m.Rows + NUM_VCPUS - 1) / NUM_VCPUS

        for i := uint64(0); i < m.Rows; i += rows_per_thread {
		wg.Add(1)

		go func(m *Matrix[uint64], i uint64) {
			defer wg.Done()
			for i2 := uint64(0); i2 < rows_per_thread; i2++ {
				if i + i2 >= m.Rows {
					break
				}

                		for j := uint64(0); j < m.Cols; j++ {
                        		m.Data[(i+i2)*m.Cols+j] = uint64(int64(math.Round(float64(int64(m.Data[(i+i2)*m.Cols+j])) / float64(divide_by))))
                		}
			}
		}(m, i)
        }

	wg.Wait()
}

func MatrixRshSigned(m *Matrix[uint64], decimals int) *Matrix[uint64] {
        out := MatrixZeros[uint64](m.Rows, m.Cols)
	MatrixRshSignedDst(m, decimals, out)
        return out
}

func MatrixRshSignedInPlace(m *Matrix[uint64], decimals int) {
        MatrixRshSignedDst(m, decimals, m)
}

func MatrixRshSignedDst(m *Matrix[uint64], decimals int, out *Matrix[uint64]) {
	if m.Rows != out.Rows || m.Cols != out.Cols {
		panic("Dimension mismatch")
	}

        var wg sync.WaitGroup
	rows_per_thread := (m.Rows + NUM_VCPUS - 1) / NUM_VCPUS
        for i := uint64(0); i < m.Rows; i += rows_per_thread {
                wg.Add(1)

                go func(out, m *Matrix[uint64], i uint64) {
                        defer wg.Done()
			for k := uint64(0); k < rows_per_thread; k++ {
				if i + k >= m.Rows {
					break
				}

                        	for j := uint64(0); j < m.Cols; j++ {
                        	        out.Data[(i+k)*m.Cols+j] = uint64(int64(m.Data[(i+k)*m.Cols+j]) >> decimals)
                        	}
			}
                }(out, m, i)
        }

        wg.Wait()
}

func MatrixRshSigned128InPlace(m *Matrix[Uint128], decimals int) {
        MatrixRshSigned128Dst(m, decimals, m)
}

func MatrixRshSigned128Dst(m *Matrix[Uint128], decimals int, out *Matrix[Uint128]) {
        if m.Rows != out.Rows || m.Cols != out.Cols {
                panic("Dimension mismatch")
        }

        var wg sync.WaitGroup
        rows_per_thread := (m.Rows + NUM_VCPUS - 1) / NUM_VCPUS
        for i := uint64(0); i < m.Rows; i += rows_per_thread {
                wg.Add(1)

                go func(out, m *Matrix[Uint128], i uint64) {
                        defer wg.Done()

                        rows := C.Elem64(rows_per_thread)
                        if i + rows_per_thread > m.Rows {
                                rows = C.Elem64(m.Rows - i)
                        }
                        cols := C.Elem64(m.Cols)
			d := C.Elem64(decimals)

                        outPtr := unsafe.Pointer(&out.Data[out.Cols*i])
                        mPtr := unsafe.Pointer(&m.Data[m.Cols*i])

                        C.matRshSigned((*C.Elem128)(mPtr), (*C.Elem128)(outPtr), rows, cols, d)
                }(out, m, i)
        }

        wg.Wait()
}

func MatrixGetBit(m *Matrix[uint64], bit int) *Matrix[uint64] {
        out := MatrixZeros[uint64](m.Rows, m.Cols)
	MatrixGetBitDst(m, bit, out)
	return out
}

func MatrixGetBitDst(m *Matrix[uint64], bit int, out *Matrix[uint64]) {
	if m.Rows != out.Rows || m.Cols != out.Cols {
		panic("Dimension mismatch")
	}

	clear(out.Data)

        var wg sync.WaitGroup
	rows_per_thread := (m.Rows + NUM_VCPUS - 1) / NUM_VCPUS
        for i := uint64(0); i < m.Rows; i += rows_per_thread {
                wg.Add(1)

                go func(out, m *Matrix[uint64], i uint64) {
                        defer wg.Done()

                        rows := C.Elem64(rows_per_thread)
                        if i + rows_per_thread > m.Rows {
                                rows = C.Elem64(m.Rows - i)
                        }
                        cols := C.Elem64(m.Cols)

                        mPtr := unsafe.Pointer(&m.Data[m.Cols*i])
                        outPtr := unsafe.Pointer(&out.Data[m.Cols*i])

                        C.selectBit((*C.Elem64)(mPtr), (*C.Elem64)(outPtr), C.Elem64(bit), rows, cols)
                }(out, m, i)
        }

        wg.Wait()
}

func GetNorm(m *Matrix[uint64], decimals int) uint64 {
	norm_sq := MakeUint128(0, 0) 

	for i := uint64(0); i < m.Rows; i++ {
		for j := uint64(0); j < m.Cols; j++ {
			val := ToUint128(m.Data[i*m.Cols+j])
			interm := Mul(val, val)
			norm_sq.AddInPlace(interm)
		}
	}

	norm_sq.RshInPlace(2*uint(decimals))
	if !CheckUint64(norm_sq) {
		norm_sq.Print()
                panic("Norm squared should fit in 64 bits")
        }

	norm_sq_int := ToUint64(norm_sq)
	return uint64(math.Sqrt(float64(norm_sq_int)))
}

func recoverAndPrint(U0, U1, U2 *Matrix[Share128], str string) {
	U0_fake := MatrixZeros[Uint128](U0.NRows(), U0.NCols())
        U0_add := MatrixRSSToAdditive(U0, 0)
        U1_add := MatrixRSSToAdditive(U1, 1)
        U2_add := MatrixRSSToAdditive(U2, 2)
	U := MatrixAddInPlaceShrink(U0_fake, U0_add, U1_add, U2_add)
        fmt.Printf(str)
	fmt.Printf(" (%d by %d)\n", U.Rows, U.Cols)
        PrintSigned(U)
}

func recoverAndPrintNorm(U0, U1, U2 *Matrix[Share128], str string) {
        U0_fake := MatrixZeros[Uint128](U0.NRows(), U0.NCols())
        U0_add := MatrixRSSToAdditive(U0, 0)
        U1_add := MatrixRSSToAdditive(U1, 1)
        U2_add := MatrixRSSToAdditive(U2, 2)
        U := MatrixAddInPlaceShrink(U0_fake, U0_add, U1_add, U2_add)
        fmt.Printf(str)
        fmt.Printf(" (%d by %d)\n", U.Rows, U.Cols)
        GetNorm(U, 0)
}
