package dmsb

import (
	"fmt"
	"math/bits"
	"testing"

	. "github.com/NudgeArtifact/private-recs/rand"
	. "github.com/NudgeArtifact/private-recs/uint128"
)

// mostSignificantBitIndex64 returns the number of leading zero bits in v,
// which is the one-hot index that DMSB should output for a 64-bit input.
func mostSignificantBitIndex64(v uint64) uint64 {
	return uint64(bits.LeadingZeros64(v))
}

// mostSignificantBitIndex128 returns the number of leading zero bits in the
// 128-bit value (hi, lo).
func mostSignificantBitIndex128(hi, lo uint64) uint64 {
	res := uint64(bits.LeadingZeros64(hi))
	if res != 64 {
		return res
	}
	return uint64(bits.LeadingZeros64(lo)) + 64
}

func TestEval64(test *testing.T) {
	fmt.Println("TestEval64")
	logN := uint64(64)

	seed := RandomPRGKey()
	bPRG := NewBufPRG(NewPRG(seed))

	for iter := 0; iter < 100; iter++ {
		r := bPRG.Uint64()
		keyL, keyR := Gen64(r, logN)

		for iter2 := 0; iter2 < 100; iter2++ {
			x := bPRG.Uint64()
			evalL := Eval64(keyL, x+r, logN, 0)
			evalR := Eval64(keyR, x+r, logN, 1)
			index := mostSignificantBitIndex64(x)

			// Verify the one-hot property: shares sum to 1 at the MSB index
			// and to 0 everywhere else.
			for j := uint64(0); j < logN; j++ {
				if j == index && (evalL[j]+evalR[j] != 1) {
					fmt.Printf("Running with x+r=%d r=%d x=%064b\n", x+r, r, x)
					fmt.Printf("Did not sum to 1 at index %d: %d + %d = %d\n", j, evalL[j], evalR[j], evalL[j]+evalR[j])
					test.Fail()
					panic("FAIL")
				}

				if j != index && (evalL[j]+evalR[j] != 0) {
					fmt.Printf("Running with x+r=%d r=%d x=%064b\n", x+r, r, x)
					fmt.Printf("Did not sum to 0 at index %d: %d + %d = %d\n", j, evalL[j], evalR[j], evalL[j]+evalR[j])
					test.Fail()
					panic("FAIL")
				}
			}
		}
	}
}

func TestEval128(test *testing.T) {
	fmt.Println("TestEval128")
	logN := uint64(128)

	seed := RandomPRGKey()
	bPRG := NewBufPRG(NewPRG(seed))

	for iter := 0; iter < 100; iter++ {
		r_hi, r_lo := bPRG.TwoUint64()
		r := MakeUint128(r_hi, r_lo)
		keyL, keyR := Gen128(r, logN)

		for iter2 := 0; iter2 < 100; iter2++ {
			x_hi, x_lo := bPRG.TwoUint64()
			x := MakeUint128(x_hi, x_lo)
			sum := Add(x, r)

			evalL := Eval128(keyL, sum, logN, 0)
			evalR := Eval128(keyR, sum, logN, 1)
			index := mostSignificantBitIndex128(x_hi, x_lo)

			// Verify the one-hot property across all 128 bit positions.
			for j := uint64(0); j < logN; j++ {
				reconstruct := Add(&evalL[j], &evalR[j])

				if j == index && !IsOne(reconstruct) {
					fmt.Printf("ERROR -- Did not sum to 1 at index %d: ", j)
					reconstruct.Print()
					evalL[j].Print()
					evalR[j].Print()
					test.Fail()
					panic("FAIL")
				}

				if j != index && !IsZero(reconstruct) {
					fmt.Printf("ERROR -- Did not sum to 0 at index %d: ", j)
					reconstruct.Print()
					evalL[j].Print()
					evalR[j].Print()
					test.Fail()
					panic("FAIL")
				}
			}
		}
	}
}
