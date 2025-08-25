package dmsb

import (
        "fmt"
	"bytes"
	"encoding/gob"
        "private-recs/dcf"
        . "private-recs/uint128"
	. "private-recs/rand"
)

// Implementation of Distributed Most-Significant-Bit function

type DMSBkey64 struct {
	Keys []dcf.DCFkey
	Cws  []uint64
}

type DMSBkey128 struct {
	Keys []dcf.DCFkey
	Cws  []Uint128
}

func Gen64(alpha uint64, logN uint64) (DMSBkey64, DMSBkey64) {
        if ((logN < 63) && (alpha >= (1 << logN))) || (logN > 64) {
		fmt.Printf("alpha: %d  logN: %d\n", alpha, logN)
                panic("dmsb: invalid parameters")
        }

        seed := RandomPRGKey()
        bPRG := NewBufPRG(NewPRG(seed))

	var kL, kR DMSBkey64

	for i := int64(logN); i >= 0; i-- {
		// Make DCF keys for alpha + all power of two (the last one is > instead of >=)
		var dcfL, dcfR dcf.DCFkey

		point := alpha + uint64(1 << i)
		if logN < 64 {
			point = point % (1 << logN)
		}

		if i > 0 {
			dcfL, dcfR = dcf.Gen64(point, logN, true /* >= */)
		} else { 
			dcfL, dcfR = dcf.Gen64(point, logN, false /* > */)
		}

		kL.Keys = append(kL.Keys, dcfL)
		kR.Keys = append(kR.Keys, dcfR)

		// Compute shares of a bit that indicates whether wrap-around occurred --> if so, need to offset all evals by 1
		if i > 0 {
			s := bPRG.Uint64()
			kR.Cws = append(kR.Cws, -s)

			next_point := alpha + uint64(1 << (i-1))
			if logN < 64 {
				next_point = next_point % (1 << logN)
			}

			if point > next_point { // shares of 0
				kL.Cws = append(kL.Cws, s)
			} else { // shares of 1
				kL.Cws = append(kL.Cws, s + 1)
			}
		}
	}

	return kL, kR
}

func Eval64(k DMSBkey64, y uint64, logN uint64, server_id int) []uint64 {
        if !(server_id == 0 || server_id == 1) {
                panic("Invalid server_id in Eval")
        }

	output := make([]uint64, logN)

	for i := uint64(0); i < logN+1; i++ {
		val := dcf.Eval64(k.Keys[i], y, logN, server_id)

		if i < logN {
			output[i] -= val // val used as UPPER BOUND
			output[i] += k.Cws[i]
		}

		if i > 0 {
			output[i-1] += val // val used as LOWER BOUND
		}
        }

	return output
}

func Gen128(alpha *Uint128, logN uint64) (DMSBkey128, DMSBkey128) {
        if (logN != 128) {
                panic("dmsb: invalid parameters")
        }

        seed := RandomPRGKey()
        bPRG := NewBufPRG(NewPRG(seed))

        var kL, kR DMSBkey128

	kL.Cws = make([]Uint128, 128)
	kR.Cws = make([]Uint128, 128)

        for i := int64(logN); i >= 0; i-- {
                // Make DCF keys for alpha + all power of two (the last one is > instead of >=)
                var dcfL, dcfR dcf.DCFkey
		var powerOfTwo *Uint128

		if i == int64(logN) {
			powerOfTwo = MakeUint128(0, 0)
		} else {
			powerOfTwo = MakeUint128(0, 1)
			powerOfTwo.LshInPlace(uint(i))
		}

                point := Add(alpha, powerOfTwo) // wraps around mod 2^128 automatically

                if i > 0 {
                        dcfL, dcfR = dcf.GenLargeInput128(point, logN, true /* >= */)
                } else {
                        dcfL, dcfR = dcf.GenLargeInput128(point, logN, false /* > */)
                }

                kL.Keys = append(kL.Keys, dcfL)
                kR.Keys = append(kR.Keys, dcfR)

                // Compute shares of a bit that indicates whether wrap-around occurred --> if so, need to offset all evals by 1
                if i > 0 {
                        s_hi, s_lo := bPRG.TwoUint64()
			SetUint128(s_hi, s_lo, &kL.Cws[logN-uint64(i)]) // set to s
			SetUint128(s_hi, s_lo, &kR.Cws[logN-uint64(i)]) // set to -s
			kR.Cws[logN-uint64(i)].NegateInPlace()

			powerOfTwo = MakeUint128(0, 1)
			powerOfTwo.LshInPlace(uint(i-1))
			next_point := Add(alpha, powerOfTwo)

                        if !point.GreaterThan(next_point) {
				// Need shares of 1
				kL.Cws[logN-uint64(i)].AddOneInPlace()
                        }
                }
        }

        return kL, kR
}

func Eval128(k DMSBkey128, y *Uint128, logN uint64, server_id int) []Uint128 {
        if !(server_id == 0 || server_id == 1) {
                panic("Invalid server_id in Eval")
        }

	if logN != 128 {
		panic("Not supported")
	}

        output := make([]Uint128, logN)

        for i := uint64(0); i < logN+1; i++ {
                val := dcf.EvalLargeInput128(k.Keys[i], y, logN, server_id)

                if i < logN {
                        output[i].AddInPlace(&k.Cws[i])
                        output[i].SubInPlace(&val) // val used as UPPER BOUND
                }

                if i > 0 {
                        output[i-1].AddInPlace(&val) // val used as LOWER BOUND
                }
        }

        return output
}

func ByteLen(mod uint64, logN uint64) uint64 {
	var buf bytes.Buffer
        enc := gob.NewEncoder(&buf)

        if mod == 64 {
                key, _ := Gen64(0, logN)
        	if err := enc.Encode(key); err != nil {
        	        panic(fmt.Sprintf("Failed to encode message: %v", err))
        	}

        } else if mod == 128 {
		input := MakeUint128(0, 0)
                key, _ := Gen128(input, logN)
		if err := enc.Encode(key); err != nil {
                        panic(fmt.Sprintf("Failed to encode message: %v", err))
                }
	} else {
	        panic("Bad input to ByteLen")
	}

	return uint64(len(buf.Bytes()))
}
