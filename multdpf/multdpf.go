// Package multdpf implements a three-party multiplicative Distributed Point
// Function (DPF).
//
// A multiplicative DPF for a secret index alpha produces three key shares
// (kA, kB, kC) such that evaluating any key at a point x yields a pair of
// values (first, second) that form a replicated secret share (RSS) of
// f(x) = [x == alpha].  In RSS each server holds two shares that overlap with
// its neighbours:
//
//   - Server 0 holds (s1, s0): Eval returns (second=s0, first=s1)
//   - Server 1 holds (s2, s1): Eval returns (first=s2, second=s1)
//   - Server 2 holds (s0, s2): Eval returns (first=s0, second=s2)
//
// The values s1, s2, s3 from all three servers sum to f(x).
//
// Based on: "Compressing Unit-Vector Correlations via Sparse Pseudorandom
// Generators". Adapted from github.com/dimakogan/dpf-go.
//
package multdpf

import (
	"crypto/rand"
	"encoding/binary"

	aes "github.com/NudgeArtifact/private-recs/aes"
	. "github.com/NudgeArtifact/private-recs/uint128"
)

// DPFkey is a serialized key for one of the three servers.
type DPFkey []byte

// Block is a 128-bit AES block used as a PRG seed or correction word.
type Block [16]byte

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

// Key layout constants.
const (
	// keyPrefixLen is the number of bytes before the per-level correction
	// words: 16 seed bytes + 1 packed t-bit byte.
	keyPrefixLen = 17

	// cwStride is the per-level correction-word size:
	// scw0 (16) + scw1 (16) + packed t-bits (1) = 33 bytes.
	cwStride = 33

	// finalCW64 is the trailing correction-word size for 64-bit output:
	// scw0 (16) + scw1 (16) = 32 bytes.
	finalCW64 = 32

	// finalCW128 is the trailing correction-word size for 128-bit output:
	// scw0 (16) + tcw0 (16) + scw1 (16) + tcw1 (16) = 64 bytes.
	finalCW128 = 64
)

// Package-level PRF key schedules expanded at init time.
var (
	keyL = make([]uint32, 11*4)
	keyR = make([]uint32, 11*4)
)

func init() {
	// Hard-coded PRF keys for left-child and right-child seed expansion.
	prfkeyL := []byte{36, 156, 50, 234, 92, 230, 49, 9, 174, 170, 205, 160, 98, 236, 29, 243}
	prfkeyR := []byte{209, 12, 199, 173, 29, 74, 44, 128, 194, 224, 14, 44, 2, 201, 110, 28}

	if _, err := aes.NewCipher(prfkeyL); err != nil {
		panic("multdpf: can't init AES")
	}
	if _, err := aes.NewCipher(prfkeyR); err != nil {
		panic("multdpf: can't init AES")
	}

	aes.ExpandKeyAsm(&prfkeyL[0], &keyL[0])
	aes.ExpandKeyAsm(&prfkeyR[0], &keyR[0])
}

// getBits returns the two lowest-order bits of in as [2]byte{bit1, bit0},
// each stored in a separate byte for use as a control bit.
func getBits(in *byte) [2]byte {
	return [2]byte{(*in & 2) >> 1, *in & 1}
}

// clr clears the lowest-order two bits of *in in place, stripping control
// bits from a seed before it is used as AES input.
func clr(in *byte) {
	*in &^= 0x3
}

// prg expands seed into left (s0) and right (s1) child seeds using keyL and
// keyR.  Returns the two-bit control pairs extracted from each child.
func prg(seed, s0, s1 *byte) ([2]byte, [2]byte) {
	aes.Aes128MMO(&keyL[0], s0, seed)
	t0 := getBits(s0)
	clr(s0)

	aes.Aes128MMO(&keyR[0], s1, seed)
	t1 := getBits(s1)
	clr(s1)

	return t0, t1
}

// applyCW applies one level's correction words to the child seeds and control
// bits during tree traversal.  t0 and t1 are the current server's control bits;
// sL/sR and tL/tR are the expanded child seeds and control-bit pairs;
// cwOff is the byte offset of this level's CW block within k.
func applyCW(sL, sR *Block, t0, t1 byte, tL, tR *[2]byte, k DPFkey, cwOff uint64) {
	allBits := k[cwOff+32]
	if t0 != 0 {
		aes.Xor16(&sL[0], &sL[0], &k[cwOff])
		aes.Xor16(&sR[0], &sR[0], &k[cwOff])
		tL[0] ^= (allBits >> 7) & 1
		tL[1] ^= (allBits >> 6) & 1
		tR[0] ^= (allBits >> 3) & 1
		tR[1] ^= (allBits >> 2) & 1
	}
	if t1 != 0 {
		aes.Xor16(&sL[0], &sL[0], &k[cwOff+16])
		aes.Xor16(&sR[0], &sR[0], &k[cwOff+16])
		tL[0] ^= (allBits >> 5) & 1
		tL[1] ^= (allBits >> 4) & 1
		tR[0] ^= (allBits >> 1) & 1
		tR[1] ^= allBits & 1
	}
}

// genAdvancePath advances one server's active seed and control bits to the
// kept child after processing one level during key generation.
// sKeep/tKeep are the kept child's seed and control bits from the PRG;
// scw0/scw1 are the seed correction words for this level;
// tCWij is the correction for control bit j when control bit i is active.
func genAdvancePath(s *Block, t *[2]byte, sKeep *Block, tKeep [2]byte,
	scw0, scw1 *Block, tCW00, tCW01, tCW10, tCW11 byte) {
	*s = *sKeep
	if t[0] != 0 {
		aes.Xor16(&s[0], &s[0], &scw0[0])
	}
	if t[1] != 0 {
		aes.Xor16(&s[0], &s[0], &scw1[0])
	}
	tmp0, tmp1 := tKeep[0], tKeep[1]
	if t[0] != 0 {
		tmp0 ^= tCW00
		tmp1 ^= tCW01
	}
	if t[1] != 0 {
		tmp0 ^= tCW10
		tmp1 ^= tCW11
	}
	t[0], t[1] = tmp0, tmp1
}

// validateServerID panics if serverID is not 0, 1, or 2.
func validateServerID(serverID int) {
	if serverID != 0 && serverID != 1 && serverID != 2 {
		panic("multdpf: invalid serverID")
	}
}

// Gen generates a fresh set of three DPF key shares for a domain of size
// 2^logN with distinguished point alpha.  outputBitlen must be 64 or 128.
// It samples fresh random seeds and delegates to GenFromBlock.
func Gen(alpha uint64, logN uint64, outputBitlen uint64) (DPFkey, DPFkey, DPFkey) {
	sA := new(Block)
	sB := new(Block)
	sC := new(Block)

	rand.Read(sA[:])
	rand.Read(sB[:])
	rand.Read(sC[:])

	return GenFromBlock(alpha, logN, outputBitlen, sA, sB, sC)
}

// GenFromBlock generates three DPF key shares using provided initial seeds.
// This variant is used for testing or when seeds must be derived deterministically.
//
// The three returned keys encode f(x) = [x == alpha] such that evaluating them
// at any x yields RSS shares of f(x) across the three servers.
func GenFromBlock(alpha uint64, logN uint64, outputBitlen uint64, sA, sB, sC *Block) (DPFkey, DPFkey, DPFkey) {
	if alpha >= (1<<logN) || logN > 63 {
		panic("multdpf: invalid parameters")
	}
	if outputBitlen != 64 && outputBitlen != 128 {
		panic("multdpf: invalid output bitlength")
	}

	var kA, kB, kC DPFkey
	var CW []byte
	scw0 := new(Block)
	scw1 := new(Block)

	// Initialize control bits.  In RSS, bit 0 distinguishes A from B and bit 1
	// distinguishes A from C, so exactly one of each pair starts unequal.
	tA := getBits(&sA[0])
	var tB, tC [2]byte
	tB[0] = tA[0] ^ 1 // bit 0: differs between A and B
	tB[1] = tA[1]     // bit 1: shared between A and B
	tC[0] = tA[0]     // bit 0: shared between A and C
	tC[1] = tA[1] ^ 1 // bit 1: differs between A and C

	clr(&sA[0])
	clr(&sB[0])
	clr(&sC[0])

	// Pack both control bits into one byte and write the key prefix.
	kA = append(kA, sA[:]...)
	kA = append(kA, (tA[0]<<1)^tA[1])
	kB = append(kB, sB[:]...)
	kB = append(kB, (tB[0]<<1)^tB[1])
	kC = append(kC, sC[:]...)
	kC = append(kC, (tC[0]<<1)^tC[1])

	sAL := new(Block)
	sAR := new(Block)
	sBL := new(Block)
	sBR := new(Block)
	sCL := new(Block)
	sCR := new(Block)

	for i := uint64(0); i < logN; i++ {
		tAL, tAR := prg(&sA[0], &sAL[0], &sAR[0])
		tBL, tBR := prg(&sB[0], &sBL[0], &sBR[0])
		tCL, tCR := prg(&sC[0], &sCL[0], &sCR[0])

		if (alpha & (1 << (logN - 1 - i))) != 0 {
			// Special path goes right: correction words mask the left branch.
			aes.Xor16(&scw0[0], &sAL[0], &sBL[0])
			aes.Xor16(&scw1[0], &sAL[0], &sCL[0])

			tLCW00 := tAL[0] ^ tBL[0]
			tLCW01 := tAL[1] ^ tBL[1]
			tLCW10 := tAL[0] ^ tCL[0]
			tLCW11 := tAL[1] ^ tCL[1]

			tRCW00 := tAR[0] ^ tBR[0] ^ 1 // bit 0: differs between A and B
			tRCW01 := tAR[1] ^ tBR[1]     // bit 1: shared between A and B
			tRCW10 := tAR[0] ^ tCR[0]     // bit 0: shared between A and C
			tRCW11 := tAR[1] ^ tCR[1] ^ 1 // bit 1: differs between A and C

			allBits := (tLCW00 << 7) ^ (tLCW01 << 6) ^ (tLCW10 << 5) ^ (tLCW11 << 4) ^
				(tRCW00 << 3) ^ (tRCW01 << 2) ^ (tRCW10 << 1) ^ tRCW11
			CW = append(CW, scw0[:]...)
			CW = append(CW, scw1[:]...)
			CW = append(CW, allBits)

			genAdvancePath(sA, &tA, sAR, tAR, scw0, scw1, tRCW00, tRCW01, tRCW10, tRCW11)
			genAdvancePath(sB, &tB, sBR, tBR, scw0, scw1, tRCW00, tRCW01, tRCW10, tRCW11)
			genAdvancePath(sC, &tC, sCR, tCR, scw0, scw1, tRCW00, tRCW01, tRCW10, tRCW11)
		} else {
			// Special path goes left: correction words mask the right branch.
			aes.Xor16(&scw0[0], &sAR[0], &sBR[0])
			aes.Xor16(&scw1[0], &sAR[0], &sCR[0])

			tLCW00 := tAL[0] ^ tBL[0] ^ 1 // bit 0: differs between A and B
			tLCW01 := tAL[1] ^ tBL[1]     // bit 1: shared between A and B
			tLCW10 := tAL[0] ^ tCL[0]     // bit 0: shared between A and C
			tLCW11 := tAL[1] ^ tCL[1] ^ 1 // bit 1: differs between A and C

			tRCW00 := tAR[0] ^ tBR[0]
			tRCW01 := tAR[1] ^ tBR[1]
			tRCW10 := tAR[0] ^ tCR[0]
			tRCW11 := tAR[1] ^ tCR[1]

			allBits := (tLCW00 << 7) ^ (tLCW01 << 6) ^ (tLCW10 << 5) ^ (tLCW11 << 4) ^
				(tRCW00 << 3) ^ (tRCW01 << 2) ^ (tRCW10 << 1) ^ tRCW11
			CW = append(CW, scw0[:]...)
			CW = append(CW, scw1[:]...)
			CW = append(CW, allBits)

			genAdvancePath(sA, &tA, sAL, tAL, scw0, scw1, tLCW00, tLCW01, tLCW10, tLCW11)
			genAdvancePath(sB, &tB, sBL, tBL, scw0, scw1, tLCW00, tLCW01, tLCW10, tLCW11)
			genAdvancePath(sC, &tC, sCL, tCL, scw0, scw1, tLCW00, tLCW01, tLCW10, tLCW11)
		}
	}

	// Derive leaf values via a final PRG application.
	aes.Aes128MMO(&keyL[0], &sAL[0], &sA[0])
	aes.Aes128MMO(&keyL[0], &sBL[0], &sB[0])
	aes.Aes128MMO(&keyL[0], &sCL[0], &sC[0])

	if outputBitlen == 128 {
		aes.Aes128MMO(&keyR[0], &sAR[0], &sA[0])
		aes.Aes128MMO(&keyR[0], &sBR[0], &sB[0])
		aes.Aes128MMO(&keyR[0], &sCR[0], &sC[0])
	}

	c := new(Block)
	d := new(Block)

	if outputBitlen == 64 {
		// Set up RSS shares of 1 at alpha.  For random values a, b:
		//   Server A gets (a  || b)   → Eval outputs (b, a)
		//   Server B gets (a-1|| b)   → Eval outputs (-a-b+1, b)
		//   Server C gets (a  || b-1) → Eval outputs (a, -a-b+1)
		// The "second" values sum to a + b + (-a-b+1) = 1.
		//
		// tA[1] is shared between A and B (tA[1] == tB[1]).
		// tA[0] is shared between A and C (tA[0] == tC[0]).
		// These four cases enumerate all combinations.

		if (tA[1] == 0) && (tA[0] == 0) {
			// Server A holds clean (a, b) with no CW applied.
			a_val := binary.LittleEndian.Uint64(sAL[:8])
			b_val := binary.LittleEndian.Uint64(sAL[8:16])

			// Server C has tC[1] = tA[1]^1 = 1 → XORs in scw1. Target: (a || b-1).
			binary.LittleEndian.PutUint64(c[:8], a_val)
			binary.LittleEndian.PutUint64(c[8:16], b_val-1)
			aes.Xor16(&scw1[0], &c[0], &sCL[0])

			// Server B has tB[0] = tA[0]^1 = 1 → XORs in scw0. Target: (a-1 || b).
			binary.LittleEndian.PutUint64(c[:8], a_val-1)
			binary.LittleEndian.PutUint64(c[8:16], b_val)
			aes.Xor16(&scw0[0], &c[0], &sBL[0])
		}

		if (tA[1] == 1) && (tA[0] == 0) {
			// Server C has tC[1]=0, tC[0]=0 → holds clean (a, b-1). Recover a, b.
			a_val := binary.LittleEndian.Uint64(sCL[:8])
			b_val := binary.LittleEndian.Uint64(sCL[8:16]) + 1

			// Server A has tA[0]=0, tA[1]=1 → XORs in scw1. Target: (a || b).
			binary.LittleEndian.PutUint64(c[:8], a_val)
			binary.LittleEndian.PutUint64(c[8:16], b_val)
			aes.Xor16(&scw1[0], &c[0], &sAL[0])

			// Server B has tB[0]=1, tB[1]=1 → XORs in scw0 and scw1. Target: (a-1 || b).
			binary.LittleEndian.PutUint64(c[:8], a_val-1)
			binary.LittleEndian.PutUint64(c[8:16], b_val)
			aes.Xor16(&scw0[0], &c[0], &sBL[0])
			aes.Xor16(&scw0[0], &scw0[0], &scw1[0])
		}

		if (tA[1] == 0) && (tA[0] == 1) {
			// Server B has tB[1]=0, tB[0]=0 → holds clean (a-1, b). Recover a, b.
			a_val := binary.LittleEndian.Uint64(sBL[:8]) + 1
			b_val := binary.LittleEndian.Uint64(sBL[8:16])

			// Server A has tA[0]=1, tA[1]=0 → XORs in scw0. Target: (a || b).
			binary.LittleEndian.PutUint64(c[:8], a_val)
			binary.LittleEndian.PutUint64(c[8:16], b_val)
			aes.Xor16(&scw0[0], &c[0], &sAL[0])

			// Server C has tC[0]=1, tC[1]=1 → XORs in scw0 and scw1. Target: (a || b-1).
			binary.LittleEndian.PutUint64(c[:8], a_val)
			binary.LittleEndian.PutUint64(c[8:16], b_val-1)
			aes.Xor16(&scw1[0], &c[0], &sCL[0])
			aes.Xor16(&scw1[0], &scw1[0], &scw0[0])
		}

		if (tA[1] == 1) && (tA[0] == 1) {
			// All three servers XOR in CWs; recover a, b from sA ^ sB ^ sC = (a-1 || b-1).
			copy(c[:], sAL[:])
			aes.Xor16(&c[0], &c[0], &sBL[0])
			aes.Xor16(&c[0], &c[0], &sCL[0])
			a_val := binary.LittleEndian.Uint64(c[:8]) + 1
			b_val := binary.LittleEndian.Uint64(c[8:16]) + 1

			// Server B has tB[1]=1, tB[0]=0 → XORs in scw1. Target: (a-1 || b).
			binary.LittleEndian.PutUint64(c[:8], a_val-1)
			binary.LittleEndian.PutUint64(c[8:16], b_val)
			aes.Xor16(&scw1[0], &c[0], &sBL[0])

			// Server C has tC[1]=0, tC[0]=1 → XORs in scw0. Target: (a || b-1).
			binary.LittleEndian.PutUint64(c[:8], a_val)
			binary.LittleEndian.PutUint64(c[8:16], b_val-1)
			aes.Xor16(&scw0[0], &c[0], &sCL[0])
		}

		CW = append(CW, scw0[:]...)
		CW = append(CW, scw1[:]...)
	} else {
		// outputBitlen == 128: same structure as the 64-bit case but values are
		// Uint128 and the final CW carries four 128-bit blocks (scw0, tcw0, scw1, tcw1).
		tcw0 := new(Block)
		tcw1 := new(Block)

		if (tA[1] == 0) && (tA[0] == 0) {
			a_val := BytesToUint128(sAL[:])
			b_val := BytesToUint128(sAR[:])

			// Server C: tC[1]=1 → XORs in scw1/tcw1. Target: (a || b-1).
			copy(c[:], sAL[:])
			copy(d[:], Uint128ToBytes(SubOne(b_val)))
			aes.Xor16(&scw1[0], &c[0], &sCL[0])
			aes.Xor16(&tcw1[0], &d[0], &sCR[0])

			// Server B: tB[0]=1 → XORs in scw0/tcw0. Target: (a-1 || b).
			copy(c[:], Uint128ToBytes(SubOne(a_val)))
			copy(d[:], sAR[:])
			aes.Xor16(&scw0[0], &c[0], &sBL[0])
			aes.Xor16(&tcw0[0], &d[0], &sBR[0])
		}

		if (tA[1] == 1) && (tA[0] == 0) {
			// Server C: tC[1]=0, tC[0]=0 → holds clean (a, b-1). Recover a, b.
			a_val := BytesToUint128(sCL[:])
			b_val := AddOne(BytesToUint128(sCR[:]))

			// Server A: tA[0]=0, tA[1]=1 → XORs in scw1/tcw1. Target: (a || b).
			copy(c[:], sCL[:])
			copy(d[:], Uint128ToBytes(b_val))
			aes.Xor16(&scw1[0], &c[0], &sAL[0])
			aes.Xor16(&tcw1[0], &d[0], &sAR[0])

			// Server B: tB[0]=1, tB[1]=1 → XORs in scw0/tcw0 and scw1/tcw1. Target: (a-1 || b).
			copy(c[:], Uint128ToBytes(SubOne(a_val)))
			copy(d[:], Uint128ToBytes(b_val))
			aes.Xor16(&scw0[0], &c[0], &sBL[0])
			aes.Xor16(&scw0[0], &scw0[0], &scw1[0])
			aes.Xor16(&tcw0[0], &d[0], &sBR[0])
			aes.Xor16(&tcw0[0], &tcw0[0], &tcw1[0])
		}

		if (tA[1] == 0) && (tA[0] == 1) {
			// Server B: tB[1]=0, tB[0]=0 → holds clean (a-1, b). Recover a, b.
			a_val := AddOne(BytesToUint128(sBL[:]))
			b_val := BytesToUint128(sBR[:])

			// Server A: tA[0]=1, tA[1]=0 → XORs in scw0/tcw0. Target: (a || b).
			copy(c[:], Uint128ToBytes(a_val))
			copy(d[:], sBR[:])
			aes.Xor16(&scw0[0], &c[0], &sAL[0])
			aes.Xor16(&tcw0[0], &d[0], &sAR[0])

			// Server C: tC[0]=1, tC[1]=1 → XORs in scw0/tcw0 and scw1/tcw1. Target: (a || b-1).
			copy(c[:], Uint128ToBytes(a_val))
			copy(d[:], Uint128ToBytes(SubOne(b_val)))
			aes.Xor16(&scw1[0], &c[0], &sCL[0])
			aes.Xor16(&scw1[0], &scw1[0], &scw0[0])
			aes.Xor16(&tcw1[0], &d[0], &sCR[0])
			aes.Xor16(&tcw1[0], &tcw1[0], &tcw0[0])
		}

		if (tA[1] == 1) && (tA[0] == 1) {
			// All three XOR in CWs; recover a, b from sA ^ sB ^ sC = (a-1 || b-1).
			copy(c[:], sAL[:])
			copy(d[:], sAR[:])
			aes.Xor16(&c[0], &c[0], &sBL[0])
			aes.Xor16(&d[0], &d[0], &sBR[0])
			aes.Xor16(&c[0], &c[0], &sCL[0])
			aes.Xor16(&d[0], &d[0], &sCR[0])
			a_val := AddOne(BytesToUint128(c[:]))
			b_val := AddOne(BytesToUint128(d[:]))

			// Server B: tB[1]=1, tB[0]=0 → XORs in scw1/tcw1. Target: (a-1 || b).
			copy(c[:], Uint128ToBytes(SubOne(a_val)))
			copy(d[:], Uint128ToBytes(b_val))
			aes.Xor16(&scw1[0], &c[0], &sBL[0])
			aes.Xor16(&tcw1[0], &d[0], &sBR[0])

			// Server C: tC[1]=0, tC[0]=1 → XORs in scw0/tcw0. Target: (a || b-1).
			copy(c[:], Uint128ToBytes(a_val))
			copy(d[:], Uint128ToBytes(SubOne(b_val)))
			aes.Xor16(&scw0[0], &c[0], &sCL[0])
			aes.Xor16(&tcw0[0], &d[0], &sCR[0])
		}

		CW = append(CW, scw0[:]...)
		CW = append(CW, tcw0[:]...)
		CW = append(CW, scw1[:]...)
		CW = append(CW, tcw1[:]...)
	}

	kA = append(kA, CW...)
	kB = append(kB, CW...)
	kC = append(kC, CW...)

	return kA, kB, kC
}

// Eval64 evaluates a 64-bit multiplicative DPF key at point x in a domain of
// size 2^logN.  serverID must be 0, 1, or 2.  Returns a pair (first, second)
// that is this server's RSS share of f(x) = [x == alpha].
func Eval64(k DPFkey, x uint64, logN uint64, serverID int) (uint64, uint64) {
	validateServerID(serverID)

	s := new(Block)
	sL := new(Block)
	sR := new(Block)
	copy(s[:], k[:16])
	t0 := (k[16] & 2) >> 1
	t1 := k[16] & 1

	for i := uint64(0); i < logN; i++ {
		tL, tR := prg(&s[0], &sL[0], &sR[0])
		applyCW(sL, sR, t0, t1, &tL, &tR, k, keyPrefixLen+i*cwStride)

		if (x & (uint64(1) << (logN - 1 - i))) != 0 {
			*s = *sR
			t0 = tR[0]
			t1 = tR[1]
		} else {
			*s = *sL
			t0 = tL[0]
			t1 = tL[1]
		}
	}

	aes.Aes128MMO(&keyL[0], &s[0], &s[0])

	// Apply the final correction word (scw0 then scw1 from the end of the key).
	if t0 != 0 {
		aes.Xor16(&s[0], &s[0], &k[len(k)-finalCW64])
	}
	if t1 != 0 {
		aes.Xor16(&s[0], &s[0], &k[len(k)-finalCW64/2])
	}

	first := binary.LittleEndian.Uint64(s[:8])
	second := binary.LittleEndian.Uint64(s[8:16])

	switch serverID {
	case 0:
		return second, first
	case 1:
		return -first - second, second
	default: // serverID == 2
		return first, -first - second
	}
}

// Eval128 evaluates a 128-bit multiplicative DPF key at point x.
// See Eval64 for parameter semantics; returns (first, second) as Uint128.
func Eval128(k DPFkey, x uint64, logN uint64, serverID int) (Uint128, Uint128) {
	validateServerID(serverID)

	s := new(Block)
	sL := new(Block)
	sR := new(Block)
	copy(s[:], k[:16])
	t0 := (k[16] & 2) >> 1
	t1 := k[16] & 1

	for i := uint64(0); i < logN; i++ {
		tL, tR := prg(&s[0], &sL[0], &sR[0])
		applyCW(sL, sR, t0, t1, &tL, &tR, k, keyPrefixLen+i*cwStride)

		if (x & (uint64(1) << (logN - 1 - i))) != 0 {
			*s = *sR
			t0 = tR[0]
			t1 = tR[1]
		} else {
			*s = *sL
			t0 = tL[0]
			t1 = tL[1]
		}
	}

	aes.Aes128MMO(&keyL[0], &sL[0], &s[0])
	aes.Aes128MMO(&keyR[0], &sR[0], &s[0])

	// Apply the final correction word (layout: scw0, tcw0, scw1, tcw1).
	if t0 != 0 {
		aes.Xor16(&sL[0], &sL[0], &k[len(k)-finalCW128])
		aes.Xor16(&sR[0], &sR[0], &k[len(k)-finalCW128+16])
	}
	if t1 != 0 {
		aes.Xor16(&sL[0], &sL[0], &k[len(k)-finalCW128/2])
		aes.Xor16(&sR[0], &sR[0], &k[len(k)-finalCW128/2+16])
	}

	first := BytesToUint128(sL[:])
	second := BytesToUint128(sR[:])

	switch serverID {
	case 0:
		return *second, *first
	case 1:
		first.NegateInPlace()
		first.SubInPlace(second)
		return *first, *second
	default: // serverID == 2
		second.NegateInPlace()
		second.SubInPlace(first)
		return *first, *second
	}
}

// evalFullRecursive64 recursively evaluates all 2^(stop-lvl) leaves of a
// 64-bit DPF subtree rooted at (s, t0, t1).  Results are written into res as
// pairs of uint64, two entries per leaf (matching the RSS layout of Eval64).
func evalFullRecursive64(blockStack [][2]*Block, k DPFkey, s *Block, t0, t1 byte,
	lvl, stop uint64, res *bytearr, serverID int) {
	if lvl == stop {
		ss := blockStack[lvl][0]
		*ss = *s
		aes.Aes128MMO(&keyL[0], &ss[0], &ss[0])

		if t0 != 0 {
			aes.Xor16(&ss[0], &ss[0], &k[len(k)-finalCW64])
		}
		if t1 != 0 {
			aes.Xor16(&ss[0], &ss[0], &k[len(k)-finalCW64/2])
		}

		first := binary.LittleEndian.Uint64(ss[:8])
		second := binary.LittleEndian.Uint64(ss[8:16])

		switch serverID {
		case 0:
			res.data[res.index] = second
			res.data[res.index+1] = first
		case 1:
			res.data[res.index] = -first - second
			res.data[res.index+1] = second
		default: // serverID == 2
			res.data[res.index] = first
			res.data[res.index+1] = -first - second
		}

		res.index += 2
		return
	}

	sL := blockStack[lvl][0]
	sR := blockStack[lvl][1]
	tL, tR := prg(&s[0], &sL[0], &sR[0])
	applyCW(sL, sR, t0, t1, &tL, &tR, k, keyPrefixLen+lvl*cwStride)

	evalFullRecursive64(blockStack, k, sL, tL[0], tL[1], lvl+1, stop, res, serverID)
	evalFullRecursive64(blockStack, k, sR, tR[0], tR[1], lvl+1, stop, res, serverID)
}

// evalFullRecursive128 is like evalFullRecursive64 but for 128-bit outputs.
func evalFullRecursive128(blockStack [][2]*Block, k DPFkey, s *Block, t0, t1 byte,
	lvl, stop uint64, res *bytearr128, serverID int) {
	if lvl == stop {
		ss0 := blockStack[lvl][0]
		ss1 := blockStack[lvl][1]

		aes.Aes128MMO(&keyL[0], &ss0[0], &s[0])
		aes.Aes128MMO(&keyR[0], &ss1[0], &s[0])

		if t0 != 0 {
			aes.Xor16(&ss0[0], &ss0[0], &k[len(k)-finalCW128])
			aes.Xor16(&ss1[0], &ss1[0], &k[len(k)-finalCW128+16])
		}
		if t1 != 0 {
			aes.Xor16(&ss0[0], &ss0[0], &k[len(k)-finalCW128/2])
			aes.Xor16(&ss1[0], &ss1[0], &k[len(k)-finalCW128/2+16])
		}

		first := BytesToUint128(ss0[:])
		second := BytesToUint128(ss1[:])

		switch serverID {
		case 0:
			res.data[res.index].AddInPlace(second)
			res.data[res.index+1].AddInPlace(first)
		case 1:
			res.data[res.index].SubInPlace(first)
			res.data[res.index].SubInPlace(second)
			res.data[res.index+1].AddInPlace(second)
		default: // serverID == 2
			res.data[res.index].AddInPlace(first)
			res.data[res.index+1].SubInPlace(first)
			res.data[res.index+1].SubInPlace(second)
		}

		res.index += 2
		return
	}

	sL := blockStack[lvl][0]
	sR := blockStack[lvl][1]
	tL, tR := prg(&s[0], &sL[0], &sR[0])
	applyCW(sL, sR, t0, t1, &tL, &tR, k, keyPrefixLen+lvl*cwStride)

	evalFullRecursive128(blockStack, k, sL, tL[0], tL[1], lvl+1, stop, res, serverID)
	evalFullRecursive128(blockStack, k, sR, tR[0], tR[1], lvl+1, stop, res, serverID)
}

// EvalFull64 evaluates a 64-bit DPF key at every point in [0, 2^logN),
// returning a slice of 2*2^logN uint64 values.  Pairs (data[2i], data[2i+1])
// are this server's RSS share at point i, matching the layout of Eval64.
func EvalFull64(key DPFkey, logN uint64, serverID int) []uint64 {
	validateServerID(serverID)

	s := new(Block)
	copy(s[:], key[:16])
	t0 := (key[16] & 2) >> 1
	t1 := key[16] & 1

	buf := make([]uint64, (1<<logN)*2)
	b := bytearr{buf, 0}

	blockStack := make([][2]*Block, logN+1)
	for i := uint64(0); i < logN+1; i++ {
		blockStack[i][0] = new(Block)
		blockStack[i][1] = new(Block)
	}

	evalFullRecursive64(blockStack, key, s, t0, t1, 0, logN, &b, serverID)
	return b.data
}

// EvalFull128 evaluates a 128-bit DPF key at every point in [0, 2^logN),
// returning a slice of 2*2^logN Uint128 values.  See EvalFull64 for layout.
func EvalFull128(key DPFkey, logN uint64, serverID int) []Uint128 {
	buf := make([]Uint128, (1<<logN)*2)
	return EvalFull128Into(key, logN, serverID, buf)
}

// EvalFull128Into is like EvalFull128 but writes results into a caller-provided
// slice, avoiding an allocation when the buffer is reused across calls.
func EvalFull128Into(key DPFkey, logN uint64, serverID int, into []Uint128) []Uint128 {
	validateServerID(serverID)

	s := new(Block)
	copy(s[:], key[:16])
	t0 := (key[16] & 2) >> 1
	t1 := key[16] & 1

	b := bytearr128{into, 0}

	blockStack := make([][2]*Block, logN+1)
	for i := uint64(0); i < logN+1; i++ {
		blockStack[i][0] = new(Block)
		blockStack[i][1] = new(Block)
	}

	evalFullRecursive128(blockStack, key, s, t0, t1, 0, logN, &b, serverID)
	return b.data
}
