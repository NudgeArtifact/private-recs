package dcf

// This file implements a small-output DCF variant where the per-level value
// shares are single bits rather than 64- or 128-bit integers.  This reduces
// the per-level correction-word size from 34 bytes to 17 bytes (cwSmallStride).

import (
	"crypto/rand"

	aes "github.com/NudgeArtifact/private-recs/aes"
	. "github.com/NudgeArtifact/private-recs/uint128"
)

// bitPrg128 is like prg128 but derives a single bit instead of a full 128-bit
// value.  The bit is extracted from the lowest-order bit of the extra PRF
// output, matching the packing used in the small-output CW format.
func bitPrg128(seed *block, s0, s1 *byte) (t0, t1, b byte) {
	t0, t1 = expandSeeds(seed, s0, s1)

	var buf [16]byte
	aes.Aes128MMO(&keyExtra[0], &buf[0], &seed[0])
	b = getBit(&buf[0])
	return
}

// GenSmallOutput128 generates DCF keys for a 64-bit domain where the output
// shares are single bits (lifted into Uint128 for the caller's convenience).
// It uses an early-stopping optimisation: the tree is only expanded for the
// top (logN - 7) levels, and the bottom 7 levels are handled by a precomputed
// 16-byte correction block stored at the end of the key.
// See Gen64 for parameter semantics.
func GenSmallOutput128(alpha uint64, logN uint64, leq bool) (DCFkey, DCFkey) {
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

	// Early stopping: only traverse the top (logN - 7) levels of the tree.
	stop := logN - 7
	if logN < 7 {
		stop = 0
	}

	sAL, sAR := new(block), new(block)
	sBL, sBR := new(block), new(block)

	for i := uint64(0); i < stop; i++ {
		tAL, tAR, bA := bitPrg128(sA, &sAL[0], &sAR[0])
		tBL, tBR, bB := bitPrg128(sB, &sBL[0], &sBR[0])

		if (alpha & (uint64(1) << (logN - 1 - i))) != 0 {
			// Special path goes right: mask the left branch.
			aes.Xor16(&scw[0], &sAL[0], &sBL[0])
			tLCW := tAL ^ tBL
			tRCW := tAR ^ tBR ^ 1
			bR := bA ^ bB

			CW = append(CW, scw[:]...)
			CW = append(CW, (tLCW<<2)|(tRCW<<1)|bR)

			genAdvancePath(sA, sB, &tA, &tB, sAR, sBR, tAR, tBR, tRCW, scw)
		} else {
			// Special path goes left: mask the right branch.
			aes.Xor16(&scw[0], &sAR[0], &sBR[0])
			tLCW := tAL ^ tBL ^ 1
			tRCW := tAR ^ tBR
			bR := bA ^ bB ^ 1

			CW = append(CW, scw[:]...)
			CW = append(CW, (tLCW<<2)|(tRCW<<1)|bR)

			genAdvancePath(sA, sB, &tA, &tB, sAL, sBL, tAL, tBL, tLCW, scw)
		}
	}

	// Final correction block: a 16-byte mask encoding one correction bit per
	// entry in the bottom 128-entry subtree rooted at the early-stopping leaf.
	aes.Aes128MMO(&keyL[0], &sAL[0], &sA[0])
	aes.Aes128MMO(&keyL[0], &sBL[0], &sB[0])

	// start is the index into the 128-entry subtree where f first becomes 1.
	var start uint64
	if leq {
		start = alpha % (1 << 7)
	} else {
		start = (alpha + 1) % (1 << 7)
	}

	idx := start / 8
	offset := start % 8

	// XOR the two parties' leaf seeds; then flip all bits that should equal 1.
	for b := 0; b < 16; b++ {
		last := sAL[b] ^ sBL[b]
		if b == int(idx) {
			// Flip bits [7-offset .. 0], i.e. entries [start .. 127 mod 8].
			last ^= byte((1 << (8 - offset)) - 1)
		} else if b > int(idx) {
			last ^= ^byte(0) // flip all bits in this byte
		}
		CW = append(CW, last)
	}

	kA = append(kA, CW...)
	kB = append(kB, CW...)
	return kA, kB
}

// EvalSmallOutput128 evaluates a small-output DCF key at point x and returns
// the share as a Uint128 (value is 0 or ±1).
// See Eval64 for parameter semantics.
func EvalSmallOutput128(k DCFkey, x uint64, logN uint64, serverID int) Uint128 {
	if serverID != 0 && serverID != 1 {
		panic("Invalid server_id in Eval")
	}

	s := new(block)
	sL := new(block)
	sR := new(block)
	copy(s[:], k[:16])
	t := k[16]

	stop := logN - 7
	if logN < 7 {
		stop = 0
	}

	var sum byte

	for i := uint64(0); i < stop; i++ {
		tL, tR, b := bitPrg128(s, &sL[0], &sR[0])

		if t != 0 {
			off := keyPrefixLen + i*cwSmallStride
			packed := k[off+16]
			tLCW := (packed & 0x4) >> 2
			tRCW := (packed & 0x2) >> 1
			bCW := packed & 0x1

			evalApplyCW(sL, sR, &tL, &tR, k[off:off+16], tLCW, tRCW)
			b ^= bCW
		}

		if (x & (uint64(1) << (logN - 1 - i))) != 0 {
			*s = *sR
			t = tR
			sum ^= b
		} else {
			*s = *sL
			t = tL
		}
	}

	// Read the correction bit from the precomputed final block.
	at := int(x % (1 << 7))
	idx := at / 8
	offset := at % 8

	aes.Aes128MMO(&keyL[0], &sL[0], &s[0])
	last := sL[idx]
	if t != 0 {
		last ^= k[len(k)-16+idx]
	}

	if (last & (1 << (7 - offset))) != 0 {
		sum ^= 1
	}

	res := MakeUint128(0, uint64(sum))
	if serverID == 0 {
		return *res
	}
	res.NegateInPlace()
	return *res
}
