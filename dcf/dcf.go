// Package dcf implements a two-party Distributed Comparison Function (DCF).
//
// A DCF allows two servers to hold key shares (kA, kB) for a secret threshold
// alpha such that evaluating kA and kB at any point x yields additive shares
// of f(x), where f(x) = 1 if x >= alpha (leq=true) or x > alpha (leq=false),
// and f(x) = 0 otherwise.  All arithmetic is modular (wrapping).
//
// Three output widths are supported:
//   - 64-bit  (Gen64 / Eval64 / EvalFull64)
//   - 128-bit (Gen128 / Eval128 / EvalFull128, GenLargeInput128 / EvalLargeInput128)
//   - Small-output 128-bit with bit-valued leaves (see smaller_dcf.go)
//
// Adapted from: github.com/dimakogan/dpf-go/blob/master/dpf/dpf.go

package dcf

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/gob"
	"fmt"

	aes "github.com/NudgeArtifact/private-recs/aes"
	. "github.com/NudgeArtifact/private-recs/uint128"
)

// DCFkey is a serialized key for one party.  Both parties receive identical
// correction words; only the initial seed (and its implied t-bit) differs.
type DCFkey []byte

// block is a 128-bit AES block, used as a PRG seed or correction word.
type block [16]byte

// bytearr is a flat output buffer used by EvalFull64.
type bytearr struct {
	data  []uint64
	index uint64
}

// bytearr128 is a flat output buffer used by EvalFull128.
type bytearr128 struct {
	data  []Uint128
	index uint64
}

// DCF key layout constants.
const (
	// keyPrefixLen is the number of bytes before the per-level correction
	// words: 16 seed bytes + 1 t-bit byte.
	keyPrefixLen = 17

	// cw64Stride is the per-level correction-word size for 64-bit DCF:
	// 16 seed CW + 1 tLCW + 1 tRCW + 8 value CW = 26 bytes.
	cw64Stride = 26

	// cw128Stride is the per-level CW size for 128-bit DCF:
	// 16 seed CW + 1 tLCW + 1 tRCW + 16 value CW = 34 bytes.
	cw128Stride = 34

	// cwSmallStride is the per-level CW size for small-output DCF:
	// 16 seed CW + 1 packed byte (tLCW | tRCW | b) = 17 bytes.
	cwSmallStride = 17
)

// Package-level PRF keys, expanded at init time into the round-key schedules
// used by the low-level AES assembly routines.
var (
	keyL     = make([]uint32, 11*4)
	keyR     = make([]uint32, 11*4)
	keyExtra = make([]uint32, 11*4)
)

func init() {
	// Hard-coded PRF keys for left-child, right-child, and value derivation.
	prfkeyL := []byte{36, 156, 50, 234, 92, 230, 49, 9, 174, 170, 205, 160, 98, 236, 29, 243}
	prfkeyR := []byte{209, 12, 199, 173, 29, 74, 44, 128, 194, 224, 14, 44, 2, 201, 110, 28}
	prfkeyExtra := []byte{210, 12, 199, 173, 29, 74, 44, 128, 194, 224, 14, 44, 2, 201, 110, 28}

	// Validate the ciphers can be constructed before expanding the key schedules.
	if _, err := aes.NewCipher(prfkeyL); err != nil {
		panic("dcf: can't init AES")
	}
	if _, err := aes.NewCipher(prfkeyR); err != nil {
		panic("dcf: can't init AES")
	}
	if _, err := aes.NewCipher(prfkeyExtra); err != nil {
		panic("dcf: can't init AES")
	}

	aes.ExpandKeyAsm(&prfkeyL[0], &keyL[0])
	aes.ExpandKeyAsm(&prfkeyR[0], &keyR[0])
	aes.ExpandKeyAsm(&prfkeyExtra[0], &keyExtra[0])
}

// getBit returns the lowest-order bit of *in as 0 or 1.
// This bit serves as the DCF control bit (t-bit) embedded in a seed.
func getBit(in *byte) byte {
	return *in & 1
}

// clr clears the lowest-order bit of *in in place, stripping the control bit
// from a seed so it can be used as a plain 128-bit AES input.
func clr(in *byte) {
	*in &^= 0x1
}

// expandSeeds derives left (s0) and right (s1) child seeds from a parent seed
// using the keyed PRFs keyL and keyR.  It strips each child's control bit and
// returns it separately as t0 and t1.
func expandSeeds(seed *block, s0, s1 *byte) (t0, t1 byte) {
	aes.Aes128MMO(&keyL[0], s0, &seed[0])
	t0 = getBit(s0)
	clr(s0)

	aes.Aes128MMO(&keyR[0], s1, &seed[0])
	t1 = getBit(s1)
	clr(s1)
	return
}

// prg64 expands a seed into left child (s0), right child (s1), and a 64-bit
// value derived from the extra PRF key.  Control bits are stripped from the
// children and returned separately.
func prg64(seed *block, s0, s1 *byte) (byte, byte, uint64) {
	t0, t1 := expandSeeds(seed, s0, s1)

	var buf [16]byte
	aes.Aes128MMO(&keyExtra[0], &buf[0], &seed[0])
	return t0, t1, binary.LittleEndian.Uint64(buf[:8])
}

// prg128 is like prg64 but returns a full 128-bit value instead of 64 bits.
func prg128(seed *block, s0, s1 *byte) (byte, byte, *Uint128) {
	t0, t1 := expandSeeds(seed, s0, s1)

	var buf [16]byte
	aes.Aes128MMO(&keyExtra[0], &buf[0], &seed[0])
	return t0, t1, BytesToUint128(buf[:16])
}

// genAdvancePath moves both parties' active seeds to the next level along the
// special path.  keepA/keepB are the seeds for the kept child; tCW is the
// t-bit correction for that direction; scw is the seed correction word.
// tA and tB are updated in place.
func genAdvancePath(sA, sB *block, tA, tB *byte,
	keepA, keepB *block, keepTA, keepTB, tCW byte, scw *block) {
	*sA = *keepA
	if *tA != 0 {
		aes.Xor16(&sA[0], &sA[0], &scw[0])
	}
	*sB = *keepB
	if *tB != 0 {
		aes.Xor16(&sB[0], &sB[0], &scw[0])
	}

	newTA := keepTA
	if *tA != 0 {
		newTA ^= tCW
	}
	newTB := keepTB
	if *tB != 0 {
		newTB ^= tCW
	}
	*tA, *tB = newTA, newTB
}

// evalApplyCW applies the correction word to both child seeds and t-bits.
// Called when the current control bit t is non-zero.
func evalApplyCW(sL, sR *block, tL, tR *byte, scw []byte, tLCW, tRCW byte) {
	aes.Xor16(&sL[0], &sL[0], &scw[0])
	aes.Xor16(&sR[0], &sR[0], &scw[0])
	*tL ^= tLCW
	*tR ^= tRCW
}

// Gen64 generates a pair of DCF keys (kA, kB) for a 64-bit domain of size
// 2^logN with secret threshold alpha.  If leq is true the function computes
// f(x) = [x >= alpha]; if false, f(x) = [x > alpha].  Output shares are
// uint64 and sum to f(x) mod 2^64.
func Gen64(alpha uint64, logN uint64, leq bool) (DCFkey, DCFkey) {
	if ((logN < 64) && alpha >= (1<<logN)) || logN > 64 {
		panic("dcf: invalid parameters")
	}

	var kA, kB DCFkey
	var CW []byte
	var buf [8]byte
	sA := new(block)
	sB := new(block)
	scw := new(block)

	rand.Read(sA[:])
	rand.Read(sB[:])

	// tA and tB are the initial control bits; they start opposite each other.
	tA := getBit(&sA[0])
	tB := tA ^ 1
	clr(&sA[0])
	clr(&sB[0])

	kA = append(kA, sA[:]...)
	kA = append(kA, tA)
	kB = append(kB, sB[:]...)
	kB = append(kB, tB)

	sAL, sAR := new(block), new(block)
	sBL, sBR := new(block), new(block)

	for i := uint64(0); i < logN; i++ {
		tAL, tAR, aAR := prg64(sA, &sAL[0], &sAR[0])
		tBL, tBR, aBR := prg64(sB, &sBL[0], &sBR[0])

		if (alpha & (1 << (logN - 1 - i))) != 0 {
			// Special path goes right: mask the left branch.
			aes.Xor16(&scw[0], &sAL[0], &sBL[0])
			tLCW := tAL ^ tBL
			tRCW := tAR ^ tBR ^ 1

			bR := aAR - aBR
			if tA == 1 {
				bR = -bR
			}

			CW = append(CW, scw[:]...)
			CW = append(CW, tLCW, tRCW)
			binary.LittleEndian.PutUint64(buf[:8], bR)
			CW = append(CW, buf[:8]...)

			genAdvancePath(sA, sB, &tA, &tB, sAR, sBR, tAR, tBR, tRCW, scw)
		} else {
			// Special path goes left: mask the right branch.
			aes.Xor16(&scw[0], &sAR[0], &sBR[0])
			tLCW := tAL ^ tBL ^ 1
			tRCW := tAR ^ tBR

			bR := aAR - aBR - 1
			if tA == 1 {
				bR = -bR
			}

			CW = append(CW, scw[:]...)
			CW = append(CW, tLCW, tRCW)
			binary.LittleEndian.PutUint64(buf[:8], bR)
			CW = append(CW, buf[:8]...)

			genAdvancePath(sA, sB, &tA, &tB, sAL, sBL, tAL, tBL, tLCW, scw)
		}
	}

	// Final correction word: ensures leaf output shares sum to 0 or 1.
	aes.Aes128MMO(&keyL[0], &sAL[0], &sA[0])
	aes.Aes128MMO(&keyL[0], &sBL[0], &sB[0])

	cwVal := binary.LittleEndian.Uint64(sAL[:8]) - binary.LittleEndian.Uint64(sBL[:8])
	if leq {
		cwVal--
	}
	if tA == 1 {
		cwVal = -cwVal
	}

	binary.LittleEndian.PutUint64(scw[:8], cwVal)
	CW = append(CW, scw[:8]...)

	kA = append(kA, CW...)
	kB = append(kB, CW...)
	return kA, kB
}

// Gen128 generates DCF keys for a 64-bit domain with 128-bit output shares.
// See Gen64 for parameter semantics.
func Gen128(alpha uint64, logN uint64, leq bool) (DCFkey, DCFkey) {
	if logN > 128 {
		panic("dcf: invalid parameters")
	}

	var kA, kB DCFkey
	var CW []byte
	sA := new(block)
	sB := new(block)
	scw := new(block)

	rand.Read(sA[:])
	rand.Read(sB[:])

	tA := getBit(&sA[0])
	tB := tA ^ 1
	clr(&sA[0])
	clr(&sB[0])

	kA = append(kA, sA[:]...)
	kA = append(kA, tA)
	kB = append(kB, sB[:]...)
	kB = append(kB, tB)

	sAL, sAR := new(block), new(block)
	sBL, sBR := new(block), new(block)

	for i := uint64(0); i < logN; i++ {
		tAL, tAR, aAR := prg128(sA, &sAL[0], &sAR[0])
		tBL, tBR, aBR := prg128(sB, &sBL[0], &sBR[0])

		if (alpha & (1 << (logN - 1 - i))) != 0 {
			// Special path goes right: mask the left branch.
			aes.Xor16(&scw[0], &sAL[0], &sBL[0])
			tLCW := tAL ^ tBL
			tRCW := tAR ^ tBR ^ 1

			bR := Sub(aAR, aBR)
			if tA == 1 {
				bR.NegateInPlace()
			}

			CW = append(CW, scw[:]...)
			CW = append(CW, tLCW, tRCW)
			CW = append(CW, Uint128ToBytes(bR)...)

			genAdvancePath(sA, sB, &tA, &tB, sAR, sBR, tAR, tBR, tRCW, scw)
		} else {
			// Special path goes left: mask the right branch.
			aes.Xor16(&scw[0], &sAR[0], &sBR[0])
			tLCW := tAL ^ tBL ^ 1
			tRCW := tAR ^ tBR

			bR := Sub(aAR, aBR)
			bR.SubOneInPlace()
			if tA == 1 {
				bR.NegateInPlace()
			}

			CW = append(CW, scw[:]...)
			CW = append(CW, tLCW, tRCW)
			CW = append(CW, Uint128ToBytes(bR)...)

			genAdvancePath(sA, sB, &tA, &tB, sAL, sBL, tAL, tBL, tLCW, scw)
		}
	}

	// Final correction word.
	aes.Aes128MMO(&keyL[0], &sAL[0], &sA[0])
	aes.Aes128MMO(&keyL[0], &sBL[0], &sB[0])

	cwVal := Sub(BytesToUint128(sAL[:16]), BytesToUint128(sBL[:16]))
	if leq {
		cwVal.SubOneInPlace()
	}
	if tA == 1 {
		cwVal.NegateInPlace()
	}

	Uint128ToBytesDst(cwVal, scw[:16])
	CW = append(CW, scw[:]...)

	kA = append(kA, CW...)
	kB = append(kB, CW...)
	return kA, kB
}

// GenLargeInput128 generates DCF keys for a full 128-bit domain (logN up to
// 128) with 128-bit output shares.  alpha is the 128-bit threshold.
// See Gen64 for other parameter semantics.
func GenLargeInput128(alpha *Uint128, logN uint64, leq bool) (DCFkey, DCFkey) {
	if logN > 128 {
		panic("dcf: invalid parameters")
	}

	var kA, kB DCFkey
	var CW []byte
	sA := new(block)
	sB := new(block)
	scw := new(block)

	rand.Read(sA[:])
	rand.Read(sB[:])

	tA := getBit(&sA[0])
	tB := tA ^ 1
	clr(&sA[0])
	clr(&sB[0])

	kA = append(kA, sA[:]...)
	kA = append(kA, tA)
	kB = append(kB, sB[:]...)
	kB = append(kB, tB)

	sAL, sAR := new(block), new(block)
	sBL, sBR := new(block), new(block)

	// Traverse alpha's bits from most- to least-significant.
	// Process the high 64 bits first, then the low 64 bits.
	hi, lo := Uint128ToLimbs(alpha)
	at := hi
	index := uint64(0)

	for i := uint64(0); i < logN; i++ {
		tAL, tAR, aAR := prg128(sA, &sAL[0], &sAR[0])
		tBL, tBR, aBR := prg128(sB, &sBL[0], &sBR[0])

		if (at & (1 << (63 - index))) != 0 {
			// Special path goes right: mask the left branch.
			aes.Xor16(&scw[0], &sAL[0], &sBL[0])
			tLCW := tAL ^ tBL
			tRCW := tAR ^ tBR ^ 1

			bR := Sub(aAR, aBR)
			if tA == 1 {
				bR.NegateInPlace()
			}

			CW = append(CW, scw[:]...)
			CW = append(CW, tLCW, tRCW)
			CW = append(CW, Uint128ToBytes(bR)...)

			genAdvancePath(sA, sB, &tA, &tB, sAR, sBR, tAR, tBR, tRCW, scw)
		} else {
			// Special path goes left: mask the right branch.
			aes.Xor16(&scw[0], &sAR[0], &sBR[0])
			tLCW := tAL ^ tBL ^ 1
			tRCW := tAR ^ tBR

			bR := Sub(aAR, aBR)
			bR.SubOneInPlace()
			if tA == 1 {
				bR.NegateInPlace()
			}

			CW = append(CW, scw[:]...)
			CW = append(CW, tLCW, tRCW)
			CW = append(CW, Uint128ToBytes(bR)...)

			genAdvancePath(sA, sB, &tA, &tB, sAL, sBL, tAL, tBL, tLCW, scw)
		}

		index++
		if index == 64 {
			at = lo
			index = 0
		}
	}

	// Final correction word.
	aes.Aes128MMO(&keyL[0], &sAL[0], &sA[0])
	aes.Aes128MMO(&keyL[0], &sBL[0], &sB[0])

	cwVal := Sub(BytesToUint128(sAL[:16]), BytesToUint128(sBL[:16]))
	if leq {
		cwVal.SubOneInPlace()
	}
	if tA == 1 {
		cwVal.NegateInPlace()
	}

	Uint128ToBytesDst(cwVal, scw[:16])
	CW = append(CW, scw[:]...)

	kA = append(kA, CW...)
	kB = append(kB, CW...)
	return kA, kB
}

// Eval64 evaluates a 64-bit DCF key k at point x in a domain of size 2^logN.
// serverID must be 0 or 1.  The two servers' outputs sum to f(x) mod 2^64.
func Eval64(k DCFkey, x uint64, logN uint64, serverID int) uint64 {
	if serverID != 0 && serverID != 1 {
		panic("Invalid server_id in Eval")
	}

	s := new(block)
	sL := new(block)
	sR := new(block)
	copy(s[:], k[:16])
	t := k[16]

	sum := uint64(0)

	for i := uint64(0); i < logN; i++ {
		tL, tR, aR := prg64(s, &sL[0], &sR[0])

		if t != 0 {
			off := keyPrefixLen + i*cw64Stride
			evalApplyCW(sL, sR, &tL, &tR, k[off:off+16], k[off+16], k[off+17])
			aR += binary.LittleEndian.Uint64(k[off+18 : off+26])
		}

		if (x & (uint64(1) << (logN - 1 - i))) != 0 {
			*s = *sR
			t = tR
			sum += aR
		} else {
			*s = *sL
			t = tL
		}
	}

	aes.Aes128MMO(&keyL[0], &s[0], &s[0])
	res := binary.LittleEndian.Uint64(s[:8])
	if t != 0 {
		res += binary.LittleEndian.Uint64(k[len(k)-8:])
	}

	if serverID == 0 {
		return sum + res
	}
	return -sum - res
}

// Eval128 evaluates a 128-bit DCF key at point x.
// See Eval64 for parameter semantics.
func Eval128(k DCFkey, x uint64, logN uint64, serverID int) Uint128 {
	if serverID != 0 && serverID != 1 {
		panic("Invalid server_id in Eval")
	}

	s := new(block)
	sL := new(block)
	sR := new(block)
	copy(s[:], k[:16])
	t := k[16]

	sum := ToUint128(0)

	for i := uint64(0); i < logN; i++ {
		tL, tR, aR := prg128(s, &sL[0], &sR[0])

		if t != 0 {
			off := keyPrefixLen + i*cw128Stride
			evalApplyCW(sL, sR, &tL, &tR, k[off:off+16], k[off+16], k[off+17])
			aR.AddInPlace(BytesToUint128(k[off+18 : off+34]))
		}

		if (x & (uint64(1) << (logN - 1 - i))) != 0 {
			*s = *sR
			t = tR
			sum.AddInPlace(aR)
		} else {
			*s = *sL
			t = tL
		}
	}

	aes.Aes128MMO(&keyL[0], &s[0], &s[0])
	res := BytesToUint128(s[:16])
	if t != 0 {
		res.AddInPlace(BytesToUint128(k[len(k)-16:]))
	}

	if serverID == 0 {
		res.AddInPlace(sum)
		return *res
	}
	res.NegateInPlace()
	res.SubInPlace(sum)
	return *res
}

// EvalLargeInput128 evaluates a 128-bit DCF key at a 128-bit point x.
// logN must equal 128.  See Eval64 for other parameter semantics.
func EvalLargeInput128(k DCFkey, x *Uint128, logN uint64, serverID int) Uint128 {
	if serverID != 0 && serverID != 1 {
		panic("Invalid server_id in Eval")
	}
	if logN != 128 {
		panic("Not supported")
	}

	s := new(block)
	sL := new(block)
	sR := new(block)
	copy(s[:], k[:16])
	t := k[16]

	sum := ToUint128(0)

	hi, lo := Uint128ToLimbs(x)
	at := hi
	index := uint64(0)

	for i := uint64(0); i < logN; i++ {
		tL, tR, aR := prg128(s, &sL[0], &sR[0])

		if t != 0 {
			off := keyPrefixLen + i*cw128Stride
			evalApplyCW(sL, sR, &tL, &tR, k[off:off+16], k[off+16], k[off+17])
			aR.AddInPlace(BytesToUint128(k[off+18 : off+34]))
		}

		if (at & (uint64(1) << (63 - index))) != 0 {
			*s = *sR
			t = tR
			sum.AddInPlace(aR)
		} else {
			*s = *sL
			t = tL
		}

		index++
		if index == 64 {
			index = 0
			at = lo
		}
	}

	aes.Aes128MMO(&keyL[0], &s[0], &s[0])
	res := BytesToUint128(s[:16])
	if t != 0 {
		res.AddInPlace(BytesToUint128(k[len(k)-16:]))
	}

	if serverID == 0 {
		res.AddInPlace(sum)
		return *res
	}
	res.NegateInPlace()
	res.SubInPlace(sum)
	return *res
}

// evalFullRecursive64 recursively evaluates all 2^(stop-lvl) leaves of a
// 64-bit DCF subtree rooted at seed s with control bit t.  sum accumulates
// the value corrections collected along the path from the root to this node.
func evalFullRecursive64(blockStack [][2]*block, k DCFkey, s *block, t byte,
	lvl, stop uint64, res *bytearr, sum uint64, serverID int) {
	if lvl == stop {
		aes.Aes128MMO(&keyL[0], &s[0], &s[0])
		val := binary.LittleEndian.Uint64(s[:8])
		if t != 0 {
			val += binary.LittleEndian.Uint64(k[len(k)-8:])
		}
		if serverID == 0 {
			res.data[res.index] = sum + val
		} else {
			res.data[res.index] = -sum - val
		}
		res.index++
		return
	}

	sL := blockStack[lvl][0]
	sR := blockStack[lvl][1]
	tL, tR, aR := prg64(s, &sL[0], &sR[0])

	if t != 0 {
		off := keyPrefixLen + lvl*cw64Stride
		evalApplyCW(sL, sR, &tL, &tR, k[off:off+16], k[off+16], k[off+17])
		aR += binary.LittleEndian.Uint64(k[off+18 : off+26])
	}

	evalFullRecursive64(blockStack, k, sL, tL, lvl+1, stop, res, sum, serverID)
	evalFullRecursive64(blockStack, k, sR, tR, lvl+1, stop, res, sum+aR, serverID)
}

// evalFullRecursive128 is like evalFullRecursive64 but for 128-bit outputs.
func evalFullRecursive128(blockStack [][2]*block, k DCFkey, s *block, t byte,
	lvl, stop uint64, res *bytearr128, sum *Uint128, serverID int) {
	if lvl == stop {
		aes.Aes128MMO(&keyL[0], &s[0], &s[0])
		val := BytesToUint128(s[:16])
		if t != 0 {
			val.AddInPlace(BytesToUint128(k[len(k)-16:]))
		}
		val.AddInPlace(sum)
		if serverID == 1 {
			val.NegateInPlace()
		}
		res.data[res.index] = *val
		res.index++
		return
	}

	sL := blockStack[lvl][0]
	sR := blockStack[lvl][1]
	tL, tR, aR := prg128(s, &sL[0], &sR[0])

	if t != 0 {
		off := keyPrefixLen + lvl*cw128Stride
		evalApplyCW(sL, sR, &tL, &tR, k[off:off+16], k[off+16], k[off+17])
		aR.AddInPlace(BytesToUint128(k[off+18 : off+34]))
	}

	evalFullRecursive128(blockStack, k, sL, tL, lvl+1, stop, res, sum, serverID)
	evalFullRecursive128(blockStack, k, sR, tR, lvl+1, stop, res, Add(sum, aR), serverID)
}

// EvalFull64 evaluates a 64-bit DCF key at every point in [0, 2^logN),
// returning a slice of 2^logN uint64 shares.
func EvalFull64(key DCFkey, logN uint64, serverID int) []uint64 {
	if serverID != 0 && serverID != 1 {
		panic("Invalid server_id in EvalFull64")
	}

	s := new(block)
	copy(s[:], key[:16])
	t := key[16]

	buf := make([]uint64, 1<<logN)
	b := bytearr{buf, 0}

	blockStack := make([][2]*block, 64)
	for i := range blockStack {
		blockStack[i][0] = new(block)
		blockStack[i][1] = new(block)
	}

	evalFullRecursive64(blockStack, key, s, t, 0, logN, &b, 0, serverID)
	return b.data
}

// EvalFull128 evaluates a 128-bit DCF key at every point in [0, 2^logN),
// returning a slice of 2^logN Uint128 shares.
func EvalFull128(key DCFkey, logN uint64, serverID int) []Uint128 {
	if serverID != 0 && serverID != 1 {
		panic("Invalid server_id in EvalFull128")
	}

	s := new(block)
	copy(s[:], key[:16])
	t := key[16]

	buf := make([]Uint128, 1<<logN)
	b := bytearr128{buf, 0}

	blockStack := make([][2]*block, 128)
	for i := range blockStack {
		blockStack[i][0] = new(block)
		blockStack[i][1] = new(block)
	}

	evalFullRecursive128(blockStack, key, s, t, 0, logN, &b, ToUint128(0), serverID)
	return b.data
}

// ByteLen returns the serialized byte length of a DCF key for the given
// parameters.  mod must be 64 or 128; small selects the small-output 128-bit
// variant.
func ByteLen(mod uint64, logN uint64, small bool) uint64 {
	var key DCFkey
	switch mod {
	case 64:
		key, _ = Gen64(0, logN, true)
	case 128:
		if small {
			key, _ = GenSmallOutput128(0, logN, true)
		} else {
			key, _ = Gen128(0, logN, true)
		}
	default:
		panic("Bad input to ByteLen")
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(key); err != nil {
		panic(fmt.Sprintf("Failed to encode message: %v", err))
	}
	return uint64(len(buf.Bytes()))
}
