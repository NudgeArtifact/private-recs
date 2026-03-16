// Package dmsb implements a two-party Distributed Most-Significant-Bit (DMSB)
// function.
//
// Key generation (Gen) produces logN+1 DCF key pairs — one per bit threshold —
// plus logN correction words that account for modular wrap-around.  Evaluation
// (Eval) runs all DCF evals and accumulates the one-hot output.
//
// Two widths are supported: 64-bit (Gen64/Eval64) and 128-bit
// (Gen128/Eval128, restricted to logN=128).

package dmsb

import (
	"bytes"
	"encoding/gob"
	"fmt"

	"github.com/NudgeArtifact/private-recs/dcf"
	. "github.com/NudgeArtifact/private-recs/rand"
	. "github.com/NudgeArtifact/private-recs/uint128"
)

// DMSBkey64 holds one party's DMSB key for a 64-bit domain.
// Keys[i] is the DCF key encoding threshold alpha+2^(logN-i), and Cws[i] is
// that party's additive share of the wrap-around correction for bit position i.
type DMSBkey64 struct {
	Keys []dcf.DCFkey
	Cws  []uint64
}

// DMSBkey128 holds one party's DMSB key for a 128-bit domain (logN=128).
type DMSBkey128 struct {
	Keys []dcf.DCFkey
	Cws  []Uint128
}

// validateServerID panics if serverID is not 0 or 1.
func validateServerID(serverID int) {
	if serverID != 0 && serverID != 1 {
		panic("dmsb: invalid serverID")
	}
}

// Gen64 generates a pair of DMSB keys (kL, kR) for a 64-bit domain of size
// 2^logN with secret shift alpha.
//
// Internally, logN+1 DCF keys are generated: key i encodes threshold
// alpha+2^(logN-i) with ">=" semantics for all but the last (i=logN), which
// uses ">" so that every point falls in exactly one interval.  The logN
// correction words (Cws) encode additive shares of a wrap-around indicator
// bit: 0 if the threshold did not wrap around mod 2^logN, 1 if it did.
func Gen64(alpha uint64, logN uint64) (DMSBkey64, DMSBkey64) {
	if ((logN < 63) && (alpha >= (1 << logN))) || (logN > 64) {
		fmt.Printf("alpha: %d  logN: %d\n", alpha, logN)
		panic("dmsb: invalid parameters")
	}

	seed := RandomPRGKey()
	bPRG := NewBufPRG(NewPRG(seed))

	var kL, kR DMSBkey64

	for i := int64(logN); i >= 0; i-- {
		// Threshold is alpha + 2^i (mod 2^logN). The last key (i=0) uses
		// strict ">" so the boundary is covered by exactly one interval.
		point := alpha + uint64(1<<i)
		if logN < 64 {
			point = point % (1 << logN)
		}

		var dcfL, dcfR dcf.DCFkey
		if i > 0 {
			dcfL, dcfR = dcf.Gen64(point, logN, true /* >= */)
		} else {
			dcfL, dcfR = dcf.Gen64(point, logN, false /* > */)
		}

		kL.Keys = append(kL.Keys, dcfL)
		kR.Keys = append(kR.Keys, dcfR)

		// For each adjacent threshold pair, generate additive shares of the
		// wrap-around bit: shares of 0 if point > next_point (no wrap),
		// shares of 1 if next_point >= point (wrap occurred).
		if i > 0 {
			s := bPRG.Uint64()
			kR.Cws = append(kR.Cws, -s)

			next_point := alpha + uint64(1<<(i-1))
			if logN < 64 {
				next_point = next_point % (1 << logN)
			}

			if point > next_point { // no wrap-around: shares of 0
				kL.Cws = append(kL.Cws, s)
			} else { // wrap-around occurred: shares of 1
				kL.Cws = append(kL.Cws, s+1)
			}
		}
	}

	return kL, kR
}

// Eval64 evaluates a 64-bit DMSB key at masked point y = x+alpha (mod 2^logN).
// serverID must be 0 or 1.  The two servers' outputs sum (mod 2^64) to the
// one-hot vector of length logN, with a 1 at the leading-zeros count of x.
func Eval64(k DMSBkey64, y uint64, logN uint64, serverID int) []uint64 {
	validateServerID(serverID)

	output := make([]uint64, logN)

	// Key i acts as an upper bound for output[i] and a lower bound for
	// output[i-1].  The correction word Cws[i] adjusts for wrap-around.
	for i := uint64(0); i < logN+1; i++ {
		val := dcf.Eval64(k.Keys[i], y, logN, serverID)

		if i < logN {
			output[i] -= val      // upper bound: subtract this threshold
			output[i] += k.Cws[i] // wrap-around correction
		}

		if i > 0 {
			output[i-1] += val // lower bound: add to the previous position
		}
	}

	return output
}

// Gen128 generates a pair of DMSB keys for a 128-bit domain with secret shift
// alpha.  logN must equal 128.  See Gen64 for the general protocol description.
func Gen128(alpha *Uint128, logN uint64) (DMSBkey128, DMSBkey128) {
	if logN != 128 {
		panic("dmsb: invalid parameters")
	}

	seed := RandomPRGKey()
	bPRG := NewBufPRG(NewPRG(seed))

	var kL, kR DMSBkey128

	kL.Cws = make([]Uint128, 128)
	kR.Cws = make([]Uint128, 128)

	for i := int64(logN); i >= 0; i-- {
		// Compute 2^i mod 2^128. When i == logN (== 128), 2^128 wraps to 0,
		// so point = alpha (the "degenerate" first threshold).
		var powerOfTwo *Uint128
		if i == int64(logN) {
			powerOfTwo = MakeUint128(0, 0)
		} else {
			powerOfTwo = MakeUint128(0, 1)
			powerOfTwo.LshInPlace(uint(i))
		}

		point := Add(alpha, powerOfTwo) // wraps mod 2^128 automatically

		var dcfL, dcfR dcf.DCFkey
		if i > 0 {
			dcfL, dcfR = dcf.GenLargeInput128(point, logN, true /* >= */)
		} else {
			dcfL, dcfR = dcf.GenLargeInput128(point, logN, false /* > */)
		}

		kL.Keys = append(kL.Keys, dcfL)
		kR.Keys = append(kR.Keys, dcfR)

		// Generate additive shares of the wrap-around bit for this threshold.
		// Stored at index logN-i so indices align with the Eval loop (0..logN-1).
		if i > 0 {
			s_hi, s_lo := bPRG.TwoUint64()
			SetUint128(s_hi, s_lo, &kL.Cws[logN-uint64(i)]) // share: s
			SetUint128(s_hi, s_lo, &kR.Cws[logN-uint64(i)]) // share: -s
			kR.Cws[logN-uint64(i)].NegateInPlace()

			powerOfTwo = MakeUint128(0, 1)
			powerOfTwo.LshInPlace(uint(i - 1))
			next_point := Add(alpha, powerOfTwo)

			if !point.GreaterThan(next_point) {
				// Wrap-around occurred: increment kL share so shares sum to 1.
				kL.Cws[logN-uint64(i)].AddOneInPlace()
			}
		}
	}

	return kL, kR
}

// Eval128 evaluates a 128-bit DMSB key at masked point y.  logN must equal 128.
// See Eval64 for parameter semantics.
func Eval128(k DMSBkey128, y *Uint128, logN uint64, serverID int) []Uint128 {
	validateServerID(serverID)

	if logN != 128 {
		panic("dmsb: not supported")
	}

	output := make([]Uint128, logN)

	for i := uint64(0); i < logN+1; i++ {
		val := dcf.EvalLargeInput128(k.Keys[i], y, logN, serverID)

		if i < logN {
			output[i].AddInPlace(&k.Cws[i])
			output[i].SubInPlace(&val) // upper bound
		}

		if i > 0 {
			output[i-1].AddInPlace(&val) // lower bound
		}
	}

	return output
}

// ByteLen returns the serialized byte length of a DMSB key for the given
// parameters.  mod must be 64 or 128.
func ByteLen(mod uint64, logN uint64) uint64 {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	switch mod {
	case 64:
		key, _ := Gen64(0, logN)
		if err := enc.Encode(key); err != nil {
			panic(fmt.Sprintf("dmsb: failed to encode key: %v", err))
		}
	case 128:
		input := MakeUint128(0, 0)
		key, _ := Gen128(input, logN)
		if err := enc.Encode(key); err != nil {
			panic(fmt.Sprintf("dmsb: failed to encode key: %v", err))
		}
	default:
		panic("dmsb: unsupported mod in ByteLen")
	}

	return uint64(len(buf.Bytes()))
}
