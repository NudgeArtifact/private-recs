// Code adapted from: https://github.com/dkales/dpf-go/blob/master/dpf/dpf.go
//                    https://github.com/dimakogan/dpf-go/blob/master/dpf/dpf.go
//
// Implementing 3-party RSS DPF from: "Compressing Unit-Vector Correlations 
//                                     via Sparse Pseudorandom Generators"

package multdpf

import (
	"crypto/rand"
	"encoding/binary"
	. "private-recs/uint128"
	aes "private-recs/aes"
)

type DPFkey []byte
type Block [16]byte

type bytearr struct {
	data  []uint64
	index uint64
}

type bytearr128 struct {
        data  []Uint128
        index uint64
}

var prfL *aes.AesPrf
var prfR *aes.AesPrf
var keyL = make([]uint32, 11*4)
var keyR = make([]uint32, 11*4)


// Implements a three-party, replicated-secret-share DPF with 64-bit shares

func init() {
	// Hard-codes the left and right PRF keys
	var prfkeyL = []byte{36, 156, 50, 234, 92, 230, 49, 9, 174, 170, 205, 160, 98, 236, 29, 243}
	var prfkeyR = []byte{209, 12, 199, 173, 29, 74, 44, 128, 194, 224, 14, 44, 2, 201, 110, 28}
	var errL, errR error

	prfL, errL = aes.NewCipher(prfkeyL)
	if errL != nil {
		panic("dpf: can't init AES")
	}

	prfR, errR = aes.NewCipher(prfkeyR)
	if errR != nil {
		panic("dpf: can't init AES")
	}

	aes.ExpandKeyAsm(&prfkeyL[0], &keyL[0])
	aes.ExpandKeyAsm(&prfkeyR[0], &keyR[0])

	//if cpu.X86.HasSSE2 == false || cpu.X86.HasAVX2 == false {
	//	panic("we need sse2 and avx")
	//}
}

// Returns the two lowest-order bits of in, each stored in a separate byte
func getBits(in *byte) [2]byte {
	bit1 := (*in & 2) >> 1
	bit0 := *in & 1
	return [2]byte{bit1, bit0}
}

// Bitwise AND-and-NOT: Clears out lowest-order two bits
func clr(in *byte) {
	*in &^= 0x3
}

func prg(seed, s0, s1 *byte) ([2]byte, [2]byte) {
	aes.Aes128MMO(&keyL[0], s0, seed) // inputs: key, dst, src
	t0 := getBits(s0)
	clr(s0)

	aes.Aes128MMO(&keyR[0], s1, seed)
	t1 := getBits(s1)
	clr(s1)

	return t0, t1
}

func Gen(alpha uint64, logN uint64, output_bitlen uint64) (DPFkey, DPFkey, DPFkey) {
        sA := new(Block)
        sB := new(Block)
        sC := new(Block)

        rand.Read(sA[:])
        rand.Read(sB[:])
        rand.Read(sC[:])

	return GenFromBlock(alpha, logN, output_bitlen, sA, sB, sC)
}

func GenFromBlock(alpha uint64, logN uint64, output_bitlen uint64, sA, sB, sC *Block) (DPFkey, DPFkey, DPFkey) {
	if alpha >= (1<<logN) || logN > 63 {
		panic("dpf: invalid parameters")
	}

	if !(output_bitlen==64 || output_bitlen==128) {
		panic("dpf: invalid output bitlength")
	}

	var kA, kB, kC DPFkey
	var CW []byte
	scw0 := new(Block)
	scw1 := new(Block)

	var tB, tC [2]byte
	tA := getBits(&sA[0])
	tB[0] = tA[0] ^ 1 // bit 0: different between servers A and B
	tB[1] = tA[1]     // bit 1: shared between servers A and B
	tC[0] = tA[0]     // bit 0: shares between servers A and C
	tC[1] = tA[1] ^ 1 // bit 1: different between servers A and C

	clr(&sA[0])
	clr(&sB[0])
	clr(&sC[0])

	kA = append(kA, sA[:]...)
	kA = append(kA, (tA[0] << 1) ^ tA[1]) // merge both bits to be stored in a single byte
	kB = append(kB, sB[:]...)
	kB = append(kB, (tB[0] << 1) ^ tB[1])
	kC = append(kC, sC[:]...)
	kC = append(kC, (tC[0] << 1) ^ tC[1])

	stop := logN
	sAL := new(Block)
	sAR := new(Block)
	sBL := new(Block)
	sBR := new(Block)
	sCL := new(Block)
	sCR := new(Block)

	for i := uint64(0); i < stop; i++ {
		tAL, tAR := prg(&sA[0], &sAL[0], &sAR[0]) // inputs: seed, left child, right child
		tBL, tBR := prg(&sB[0], &sBL[0], &sBR[0])
		tCL, tCR := prg(&sC[0], &sCL[0], &sCR[0])

		if (alpha & (1 << (logN - 1 - i))) != 0 {
			//KEEP = R, LOSE = L
			aes.Xor16(&scw0[0], &sAL[0], &sBL[0])
			aes.Xor16(&scw1[0], &sAL[0], &sCL[0]) 

			tLCW00 := tAL[0] ^ tBL[0] 
			tLCW01 := tAL[1] ^ tBL[1]
			tLCW10 := tAL[0] ^ tCL[0]
			tLCW11 := tAL[1] ^ tCL[1]

			tRCW00 := tAR[0] ^ tBR[0] ^ 1 // <-- bit 0: different between A and B
			tRCW01 := tAR[1] ^ tBR[1]     // <-- bit 1: shared between A and B
			tRCW10 := tAR[0] ^ tCR[0]     // <-- bit 0: shared between A and C
			tRCW11 := tAR[1] ^ tCR[1] ^ 1 // <-- bit 1: different between A and C

			all_bits := (tLCW00 << 7) ^ (tLCW01 << 6) ^ (tLCW10 << 5) ^ (tLCW11 << 4) ^ (tRCW00 << 3) ^ (tRCW01 << 2) ^ (tRCW10 << 1) ^ tRCW11
			CW = append(CW, scw0[:]...)
			CW = append(CW, scw1[:]...)
			CW = append(CW, all_bits) 

			*sA = *sAR
			if tA[0] != 0 {
				aes.Xor16(&sA[0], &sA[0], &scw0[0])
			}
			if tA[1] != 0 {
				aes.Xor16(&sA[0], &sA[0], &scw1[0])
			}

			*sB = *sBR
			if tB[0] != 0 {
				aes.Xor16(&sB[0], &sB[0], &scw0[0])
			}
			if tB[1] != 0 {
				aes.Xor16(&sB[0], &sB[0], &scw1[0])
			}

			*sC = *sCR
			if tC[0] != 0 {
				aes.Xor16(&sC[0], &sC[0], &scw0[0])
			}
			if tC[1] != 0 {
				aes.Xor16(&sC[0], &sC[0], &scw1[0])
			}

			var tmp0, tmp1 byte
                        tmp0 = tAR[0]
                        tmp1 = tAR[1]
                        if tA[0] != 0 {
                                tmp0 ^= tRCW00
                                tmp1 ^= tRCW01
                        }
                        if tA[1] != 0 {
                                tmp0 ^= tRCW10
                                tmp1 ^= tRCW11
                        }
                        tA[0] = tmp0
                        tA[1] = tmp1

                        tmp0 = tBR[0]
                        tmp1 = tBR[1]
                        if tB[0] != 0 { 
                                tmp0 ^= tRCW00
                                tmp1 ^= tRCW01
                        }
                        if tB[1] != 0 {
                                tmp0 ^= tRCW10
                                tmp1 ^= tRCW11
                        }
                        tB[0] = tmp0
                        tB[1] = tmp1

                        tmp0 = tCR[0]
                        tmp1 = tCR[1]
                        if tC[0] != 0 {
                                tmp0 ^= tRCW00
                                tmp1 ^= tRCW01
                        }
                        if tC[1] != 0 {
                                tmp0 ^= tRCW10
                                tmp1 ^= tRCW11
                        }
                        tC[0] = tmp0
                        tC[1] = tmp1
		} else {
			//KEEP = L, LOSE = R
			aes.Xor16(&scw0[0], &sAR[0], &sBR[0])
                        aes.Xor16(&scw1[0], &sAR[0], &sCR[0]) 

                        tLCW00 := tAL[0] ^ tBL[0] ^ 1 // <-- bit 0: different between A and B
                        tLCW01 := tAL[1] ^ tBL[1]     // <-- bit 1: shared between A and B
                        tLCW10 := tAL[0] ^ tCL[0]     // <-- bit 0: shared between A and C
                        tLCW11 := tAL[1] ^ tCL[1] ^ 1 // <-- bit 1: different between A and C

                        tRCW00 := tAR[0] ^ tBR[0] 
                        tRCW01 := tAR[1] ^ tBR[1]
                        tRCW10 := tAR[0] ^ tCR[0]
                        tRCW11 := tAR[1] ^ tCR[1]

			all_bits := (tLCW00 << 7) ^ (tLCW01 << 6) ^ (tLCW10 << 5) ^ (tLCW11 << 4) ^ (tRCW00 << 3) ^ (tRCW01 << 2) ^ (tRCW10 << 1) ^ tRCW11
                        CW = append(CW, scw0[:]...)
                        CW = append(CW, scw1[:]...)
			CW = append(CW, all_bits) 

                        *sA = *sAL
                        if tA[0] != 0 {
                                aes.Xor16(&sA[0], &sA[0], &scw0[0])
                        }
                        if tA[1] != 0 {
                                aes.Xor16(&sA[0], &sA[0], &scw1[0])
                        }

                        *sB = *sBL
                        if tB[0] != 0 {
                                aes.Xor16(&sB[0], &sB[0], &scw0[0])
                        }
                        if tB[1] != 0 {
                                aes.Xor16(&sB[0], &sB[0], &scw1[0])
                        }

                        *sC = *sCL
                        if tC[0] != 0 {
                                aes.Xor16(&sC[0], &sC[0], &scw0[0])
                        }
                        if tC[1] != 0 {
                                aes.Xor16(&sC[0], &sC[0], &scw1[0])
                        }
		
			var tmp0, tmp1 byte
			tmp0 = tAL[0]
			tmp1 = tAL[1]
                        if tA[0] != 0 {
                                tmp0 ^= tLCW00
				tmp1 ^= tLCW01
                        }
                        if tA[1] != 0 {
				tmp0 ^= tLCW10
                                tmp1 ^= tLCW11
                        }
			tA[0] = tmp0
			tA[1] = tmp1

			tmp0 = tBL[0]
			tmp1 = tBL[1]
                        if tB[0] != 0 {
                                tmp0 ^= tLCW00
				tmp1 ^= tLCW01
                        }
                        if tB[1] != 0 {
                                tmp0 ^= tLCW10
                                tmp1 ^= tLCW11
                        }
			tB[0] = tmp0
			tB[1] = tmp1

			tmp0 = tCL[0]
			tmp1 = tCL[1]
                        if tC[0] != 0 {
                                tmp0 ^= tLCW00
                                tmp1 ^= tLCW01
                        }
                        if tC[1] != 0 {
                                tmp0 ^= tLCW10
                                tmp1 ^= tLCW11
                        }
			tC[0] = tmp0
			tC[1] = tmp1
		}
	}

	aes.Aes128MMO(&keyL[0], &sAL[0], &sA[0]) // inputs: key, dst, src
	aes.Aes128MMO(&keyL[0], &sBL[0], &sB[0]) 
	aes.Aes128MMO(&keyL[0], &sCL[0], &sC[0])

	if output_bitlen == 128 {
		aes.Aes128MMO(&keyR[0], &sAR[0], &sA[0]) // inputs: key, dst, src
		aes.Aes128MMO(&keyR[0], &sBR[0], &sB[0]) 
		aes.Aes128MMO(&keyR[0], &sCR[0], &sC[0])
	}

	c := new(Block)
	d := new(Block)

	if output_bitlen == 64 {
		// Set up so that servers A, B, C get CNF shares of 1, at the distinguished point.
		// Namely: for a random a, b: 
		// - Server A gets (a  ||b) --> will output (a, b) in Eval
		// - Server B gets (a-1||b) --> will output (-a-b+1, b) in Eval
		// - Server C gets (a  ||b-1) --> will output (a, -a-b+1) in Eval

		// At this point:
		// - tA[1] is shared between servers A and B (i.e., tA[1] == tB[1])
		// - tA[0] is shared between servers A and C (i.e., tA[0] = tC[0])
		if (tA[1] == 0) && (tA[0] == 0) {
			// Server A's value determines (a, b), since it will not get CW added in
			a_val := binary.LittleEndian.Uint64(sAL[:8])
			b_val := binary.LittleEndian.Uint64(sAL[8:16])

			// Server C must have tC[1] = tA[1] ^ 1 = 1 --> XORs in scw1
			// Set c to what server C should get: (a || b-1)
			binary.LittleEndian.PutUint64(c[:8], a_val)
			binary.LittleEndian.PutUint64(c[8:16], b_val-1)

			// Set scw1 to what server C should XOR in 
			aes.Xor16(&scw1[0], &c[0], &sCL[0])

			// Server B must have tB[0] = tA[0] ^ 1 = 1 --> XORs in scw0
			// Set c to what server B should get: (a-1 || b)
			binary.LittleEndian.PutUint64(c[:8], a_val-1)
			binary.LittleEndian.PutUint64(c[8:16], b_val)

			// Set scw0 to what server B should XOR in
			aes.Xor16(&scw0[0], &c[0], &sBL[0])
		} 

		if (tA[1] == 1) && (tA[0] == 0) {
			// Server C has ^tA[1] = 0 and tA[0] = 0 --> determines (a, b-1)
			a_val := binary.LittleEndian.Uint64(sCL[:8])
			b_val := binary.LittleEndian.Uint64(sCL[8:16]) + 1

			// Server A must have tA[0] = 0 and tA[1] = 1 --> XORs in scw1
			// Set c to what server A should get: (a || b)
			binary.LittleEndian.PutUint64(c[:8], a_val)
			binary.LittleEndian.PutUint64(c[8:16], b_val)

			// Set scw1 to what server A should XOR in
			aes.Xor16(&scw1[0], &c[0], &sAL[0])

			// Server B must have tB[0] = 1 and tB[1] = 1 --> XORs in scw0 and scw1
			// Set c to what server B should get: (a-1 || b)
			binary.LittleEndian.PutUint64(c[:8], a_val-1)
        	        binary.LittleEndian.PutUint64(c[8:16], b_val)

			// Set scw0 to what server B should XOR in
			aes.Xor16(&scw0[0], &c[0], &sBL[0])
			aes.Xor16(&scw0[0], &scw0[0], &scw1[0])
		}

		if (tA[1] == 0) && (tA[0] == 1) {
			// Server B must have tB[1] = 0 and tB[0] = 0 --> determines (a-1, b)
			a_val := binary.LittleEndian.Uint64(sBL[:8]) + 1
        	        b_val := binary.LittleEndian.Uint64(sBL[8:16]) 

			// Server A must have tA[0] = 1 and tA[1] = 0 --> XORs in scw0
	                // Set c to what server A should get: (a || b)
        	        binary.LittleEndian.PutUint64(c[:8], a_val)
                	binary.LittleEndian.PutUint64(c[8:16], b_val)

	                // Set scw0 to what server A should XOR in
        	        aes.Xor16(&scw0[0], &c[0], &sAL[0])

			// Server C must have tC[0] = 1 and tC[1] = 1 --> XORs in scw0 and scw1
			// Set c to what server C should get: (a || b-1)
			binary.LittleEndian.PutUint64(c[:8], a_val)
	                binary.LittleEndian.PutUint64(c[8:16], b_val-1)

			// Set scw1 to what server C should XOR in
                	aes.Xor16(&scw1[0], &c[0], &sCL[0])
	                aes.Xor16(&scw1[0], &scw1[0], &scw0[0])
		}

		if (tA[1] == 1) && (tA[0] == 1) {
			// Parse sAL XOR sBL XOR sCL as (a-1 || b-1)
			copy(c[:], sAL[:])
			aes.Xor16(&c[0], &c[0], &sBL[0])
			aes.Xor16(&c[0], &c[0], &sCL[0])
			a_val := binary.LittleEndian.Uint64(c[:8]) + 1
	                b_val := binary.LittleEndian.Uint64(c[8:16]) + 1

			// Server B must have tB[1] = 1 and tB[0] = 0 --> XORs in scw1
			// Set c to what server B should get: (a-1 || b)
			binary.LittleEndian.PutUint64(c[:8], a_val-1)
			binary.LittleEndian.PutUint64(c[8:16], b_val)

			// Set scw1 to what server B should XOR in
			aes.Xor16(&scw1[0], &c[0], &sBL[0])

			// Server C must have tC[1] = 0 and tC[0] = 1 --> XORs in scw0
			// Set c to what server C should get: (a || b-1)
			binary.LittleEndian.PutUint64(c[:8], a_val)
                	binary.LittleEndian.PutUint64(c[8:16], b_val-1)

			// Set scw0 to what server C should XOR in
        	        aes.Xor16(&scw0[0], &c[0], &sCL[0])
		}

		// At the end of this: parsing the 128-bit output as two 64-bit values (a, b) should give CNF shares of 1

		CW = append(CW, scw0[:]...)
		CW = append(CW, scw1[:]...)
		kA = append(kA, CW...)
		kB = append(kB, CW...)
		kC = append(kC, CW...)
	} else {
		// output_bitlen is 128
                // Set up so that servers A, B, C get 128-bit CNF shares of 1, at the distinguished point.
		tcw0 := new(Block)
        	tcw1 := new(Block)

                if (tA[1] == 0) && (tA[0] == 0) {
                        // Server A's value determines (a, b), since it will not get CW added in
			a_val := BytesToUint128(sAL[:])
			b_val := BytesToUint128(sAR[:])

                        // Server C must have tC[1] = tA[1] ^ 1 = 1 --> XORs in scw1
                        // Set c to what server C should get: (a || b-1)
			copy(c[:], sAL[:]) // copy over a
			copy(d[:], Uint128ToBytes(SubOne(b_val))) // copy over b-1

                        // Set scw1 to what server C should XOR in 
                        aes.Xor16(&scw1[0], &c[0], &sCL[0])
                        aes.Xor16(&tcw1[0], &d[0], &sCR[0])

                        // Server B must have tB[0] = tA[0] ^ 1 = 1 --> XORs in scw0
                        // Set c to what server B should get: (a-1 || b)
			copy(c[:], Uint128ToBytes(SubOne(a_val))) // copy over a-1
			copy(d[:], sAR[:]) // copy over b

                        // Set scw0 to what server B should XOR in
                        aes.Xor16(&scw0[0], &c[0], &sBL[0])
                        aes.Xor16(&tcw0[0], &d[0], &sBR[0])
                } 

                if (tA[1] == 1) && (tA[0] == 0) {
                        // Server C has ^tA[1] = 0 and tA[0] = 0 --> determines (a, b-1)
                        a_val := BytesToUint128(sCL[:])
                        b_val := AddOne(BytesToUint128(sCR[:]))

                        // Server A must have tA[0] = 0 and tA[1] = 1 --> XORs in scw1
                        // Set c to what server A should get: (a || b)
			copy(c[:], sCL[:])
			copy(d[:], Uint128ToBytes(b_val))

                        // Set scw1 to what server A should XOR in
                        aes.Xor16(&scw1[0], &c[0], &sAL[0])
                        aes.Xor16(&tcw1[0], &d[0], &sAR[0])

                        // Server B must have tB[0] = 1 and tB[1] = 1 --> XORs in scw0 and scw1
                        // Set c to what server B should get: (a-1 || b)
			copy(c[:], Uint128ToBytes(SubOne(a_val)))
			copy(d[:], Uint128ToBytes(b_val))

                        // Set scw0 to what server B should XOR in
                        aes.Xor16(&scw0[0], &c[0], &sBL[0])
                        aes.Xor16(&scw0[0], &scw0[0], &scw1[0])
                        aes.Xor16(&tcw0[0], &d[0], &sBR[0])
                        aes.Xor16(&tcw0[0], &tcw0[0], &tcw1[0])
                }

                if (tA[1] == 0) && (tA[0] == 1) {
                        // Server B must have tB[1] = 0 and tB[0] = 0 --> determines (a-1, b)
			a_val := AddOne(BytesToUint128(sBL[:]))
			b_val := BytesToUint128(sBR[:])

                        // Server A must have tA[0] = 1 and tA[1] = 0 --> XORs in scw0
                        // Set c to what server A should get: (a || b)
			copy(c[:], Uint128ToBytes(a_val))
			copy(d[:], sBR[:]) // copies over B

                        // Set scw0 to what server A should XOR in
                        aes.Xor16(&scw0[0], &c[0], &sAL[0])
                        aes.Xor16(&tcw0[0], &d[0], &sAR[0])

                        // Server C must have tC[0] = 1 and tC[1] = 1 --> XORs in scw0 and scw1
                        // Set c to what server C should get: (a || b-1)
			copy(c[:], Uint128ToBytes(a_val))
			copy(d[:], Uint128ToBytes(SubOne(b_val)))

                        // Set scw1 to what server C should XOR in
                        aes.Xor16(&scw1[0], &c[0], &sCL[0])
                        aes.Xor16(&scw1[0], &scw1[0], &scw0[0])
                        aes.Xor16(&tcw1[0], &d[0], &sCR[0])
                        aes.Xor16(&tcw1[0], &tcw1[0], &tcw0[0])
                }

                if (tA[1] == 1) && (tA[0] == 1) {
                        // Parse sA XOR sB XOR sC as (a-1 || b-1)
                        copy(c[:], sAL[:])
                        copy(d[:], sAR[:])
                        aes.Xor16(&c[0], &c[0], &sBL[0])
                        aes.Xor16(&d[0], &d[0], &sBR[0])
                        aes.Xor16(&c[0], &c[0], &sCL[0])
                        aes.Xor16(&d[0], &d[0], &sCR[0])

                        a_val := AddOne(BytesToUint128(c[:]))
                        b_val := AddOne(BytesToUint128(d[:]))

                        // Server B must have tB[1] = 1 and tB[0] = 0 --> XORs in scw1
                        // Set c to what server B should get: (a-1 || b)
			copy(c[:], Uint128ToBytes(SubOne(a_val)))
			copy(d[:], Uint128ToBytes(b_val))

                        // Set scw1 to what server B should XOR in
                        aes.Xor16(&scw1[0], &c[0], &sBL[0])
                        aes.Xor16(&tcw1[0], &d[0], &sBR[0])

                        // Server C must have tC[1] = 0 and tC[0] = 1 --> XORs in scw0
                        // Set c to what server C should get: (a || b-1)
			copy(c[:], Uint128ToBytes(a_val))
			copy(d[:], Uint128ToBytes(SubOne(b_val)))

                        // Set scw0 to what server C should XOR in
                        aes.Xor16(&scw0[0], &c[0], &sCL[0])
                        aes.Xor16(&tcw0[0], &d[0], &sCR[0])
                }

                CW = append(CW, scw0[:]...)
                CW = append(CW, tcw0[:]...)
                CW = append(CW, scw1[:]...)
                CW = append(CW, tcw1[:]...)
                kA = append(kA, CW...)
                kB = append(kB, CW...)
                kC = append(kC, CW...)
	}

	return kA, kB, kC
}

func Eval64(k DPFkey, x uint64, logN uint64, server_id int) (uint64, uint64) {
	if !(server_id == 0 || server_id == 1 || server_id == 2) {
		panic("Invalid server_id in Eval")
	}

	s := new(Block)
	sL := new(Block)
	sR := new(Block)
	copy(s[:], k[:16])
	t0 := (k[16] & 2) >> 1
	t1 := k[16] & 1

	// a DPF key is an array of bytes
        // The first two corection bits: stored in byte 16

	stop := logN

	// DPF key: seed (1-15); bit1 (16); bit2 (16); CW (17, onwards)
	// where CW = (scw0 [16 bits], scw1 [16 bits], tL00, tL01, tL10, tL11, 
	//             tR00, tR01, tR10, tR11 [each 1 bit, packed into same byte]) for each level
	// (length of each level = 16*2 + 1 = 32 + 1 = 33,
	// followed by final (scw0, scw1)

	for i := uint64(0); i < stop; i++ {
		tL, tR := prg(&s[0], &sL[0], &sR[0])

                sCW0 := k[17+i*33    : 17+i*33+16]
                sCW1 := k[17+i*33+16 : 17+i*33+32]
                all_bits := k[17+i*33+32]

                tLCW00 := (all_bits >> 7) & 1
                tLCW01 := (all_bits >> 6) & 1
                tLCW10 := (all_bits >> 5) & 1
                tLCW11 := (all_bits >> 4) & 1
                tRCW00 := (all_bits >> 3) & 1
                tRCW01 := (all_bits >> 2) & 1
                tRCW10 := (all_bits >> 1) & 1
                tRCW11 := all_bits & 1

		if t0 != 0 {
			aes.Xor16(&sL[0], &sL[0], &sCW0[0])
			aes.Xor16(&sR[0], &sR[0], &sCW0[0])

			tL[0] ^= tLCW00
			tL[1] ^= tLCW01
			tR[0] ^= tRCW00
			tR[1] ^= tRCW01 
		}

		if t1 != 0 {
                        aes.Xor16(&sL[0], &sL[0], &sCW1[0])
                        aes.Xor16(&sR[0], &sR[0], &sCW1[0])

                        tL[0] ^= tLCW10
			tL[1] ^= tLCW11
                        tR[0] ^= tRCW10
                        tR[1] ^= tRCW11
		}

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

	if t0 != 0 {
		aes.Xor16(&s[0], &s[0], &k[len(k)-32])
	}

	if t1 != 0 {
		aes.Xor16(&s[0], &s[0], &k[len(k)-16])
	}

	first := binary.LittleEndian.Uint64(s[:8])
	second := binary.LittleEndian.Uint64(s[8:16])

	if server_id == 0 {
		return second, first
	} else if server_id == 1 {
		return -first-second, second
	} else {
		// server_id == 2
		return first, -first-second
	}
}

func Eval128(k DPFkey, x uint64, logN uint64, server_id int) (Uint128, Uint128) {
        if !(server_id == 0 || server_id == 1 || server_id == 2) {
                panic("Invalid server_id in Eval")
        }

        s := new(Block)
        sL := new(Block)
        sR := new(Block)
        copy(s[:], k[:16])
        t0 := (k[16] & 2) >> 1
        t1 := k[16] & 1

        // a DPF key is an array of bytes
        // The first two corection bits: stored in byte 16

        stop := logN

        // DPF key: seed (1-15); bit1 (16); bit2 (16); CW (17, onwards)
        // where CW = (scw0 [16 bits], scw1 [16 bits], tL00, tL01, tL10, tL11,
        //             tR00, tR01, tR10, tR11 [each 1 bit, packed into same byte]) for each level
        // (length of each level = 16*2 + 1 = 32 + 1 = 33,
        // followed by final (scw0, scw1)

        for i := uint64(0); i < stop; i++ {
                tL, tR := prg(&s[0], &sL[0], &sR[0])

                all_bits := k[17+i*33+32]

                if t0 != 0 {
                	sCW0 := k[17+i*33    : 17+i*33+16]
                        aes.Xor16(&sL[0], &sL[0], &sCW0[0])
                        aes.Xor16(&sR[0], &sR[0], &sCW0[0])

			tLCW00 := (all_bits >> 7) & 1
                	tLCW01 := (all_bits >> 6) & 1
			tRCW00 := (all_bits >> 3) & 1
                	tRCW01 := (all_bits >> 2) & 1

                        tL[0] ^= tLCW00
                        tL[1] ^= tLCW01
                        tR[0] ^= tRCW00
                        tR[1] ^= tRCW01
                }

                if t1 != 0 {
                	sCW1 := k[17+i*33+16 : 17+i*33+32]
                        aes.Xor16(&sL[0], &sL[0], &sCW1[0])
                        aes.Xor16(&sR[0], &sR[0], &sCW1[0])

			tLCW10 := (all_bits >> 5) & 1
                	tLCW11 := (all_bits >> 4) & 1
                	tRCW10 := (all_bits >> 1) & 1
                	tRCW11 := all_bits & 1

                        tL[0] ^= tLCW10
                        tL[1] ^= tLCW11
                        tR[0] ^= tRCW10
                        tR[1] ^= tRCW11
                }

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

        if t0 != 0 {
                aes.Xor16(&sL[0], &sL[0], &k[len(k)-64])
                aes.Xor16(&sR[0], &sR[0], &k[len(k)-48])
        }

        if t1 != 0 {
                aes.Xor16(&sL[0], &sL[0], &k[len(k)-32])
                aes.Xor16(&sR[0], &sR[0], &k[len(k)-16])
        }

        first := BytesToUint128(sL[:])
        second := BytesToUint128(sR[:])

        if server_id == 0 {
                return *second, *first
        } else if server_id == 1 {
		first.NegateInPlace()
		first.SubInPlace(second)
		return *first, *second
        } else {
                // server_id == 2
		second.NegateInPlace()
		second.SubInPlace(first)
                return *first, *second
        }
}

func evalFullRecursive64(BlockStack [][2]*Block, k DPFkey, s *Block, t0, t1 byte, lvl uint64, stop uint64, res *bytearr, server_id int) {
	if lvl == stop {
		ss := BlockStack[lvl][0]
		*ss = *s
		aes.Aes128MMO(&keyL[0], &ss[0], &ss[0])

		// XOR in data
		if t0 != 0 {
			aes.Xor16(&ss[0], &ss[0], &k[len(k)-32]) 
		}

		if t1 != 0 {
			aes.Xor16(&ss[0], &ss[0], &k[len(k)-16]) 
		}

		first := binary.LittleEndian.Uint64(ss[:8]) // TODO: Use unsafe casting to make faster
		second := binary.LittleEndian.Uint64(ss[8:16])

		if server_id == 0 {
			res.data[res.index] = second
			res.data[res.index+1] = first
		} else if server_id == 1 {
			res.data[res.index] = -first-second
			res.data[res.index+1] = second
		} else {
			// server_id == 2
			res.data[res.index] = first
			res.data[res.index+1] = -first-second
		}

		res.index += 2 // copied over data in two 64-bit ints (same as 16 bytes)
		return
	}

	sL := BlockStack[lvl][0]
	sR := BlockStack[lvl][1]
	tL, tR := prg(&s[0], &sL[0], &sR[0])

	sCW0 := k[17+lvl*33   :17+lvl*33+16]
	sCW1 := k[17+lvl*33+16:17+lvl*33+32]
	all_bits := k[17+lvl*33+32]

	tLCW00 := (all_bits >> 7) & 1
        tLCW01 := (all_bits >> 6) & 1
        tLCW10 := (all_bits >> 5) & 1
        tLCW11 := (all_bits >> 4) & 1
        tRCW00 := (all_bits >> 3) & 1
        tRCW01 := (all_bits >> 2) & 1
        tRCW10 := (all_bits >> 1) & 1
        tRCW11 := all_bits & 1

	if t0 != 0 {
		aes.Xor16(&sL[0], &sL[0], &sCW0[0])
		aes.Xor16(&sR[0], &sR[0], &sCW0[0])

		tL[0] ^= tLCW00
		tL[1] ^= tLCW01
		tR[0] ^= tRCW00
		tR[1] ^= tRCW01
	}

	if t1 != 0 {
		aes.Xor16(&sL[0], &sL[0], &sCW1[0])
                aes.Xor16(&sR[0], &sR[0], &sCW1[0])

		tL[0] ^= tLCW10
                tL[1] ^= tLCW11
                tR[0] ^= tRCW10
                tR[1] ^= tRCW11
	}

	evalFullRecursive64(BlockStack, k, sL, tL[0], tL[1], lvl+1, stop, res, server_id)
	evalFullRecursive64(BlockStack, k, sR, tR[0], tR[1], lvl+1, stop, res, server_id)
}

func evalFullRecursive128(BlockStack [][2]*Block, k DPFkey, s *Block, t0, t1 byte, lvl uint64, stop uint64, res *bytearr128, server_id int) {
        if lvl == stop {
                ss0 := BlockStack[lvl][0]
                ss1 := BlockStack[lvl][1]

		// Build first and second 128 bits
                aes.Aes128MMO(&keyL[0], &ss0[0], &s[0])
                aes.Aes128MMO(&keyR[0], &ss1[0], &s[0])

                // XOR in data
                if t0 != 0 {
                        aes.Xor16(&ss0[0], &ss0[0], &k[len(k)-64])
                        aes.Xor16(&ss1[0], &ss1[0], &k[len(k)-48])
                }

                if t1 != 0 {
                        aes.Xor16(&ss0[0], &ss0[0], &k[len(k)-32])
                        aes.Xor16(&ss1[0], &ss1[0], &k[len(k)-16])
                }

                first := BytesToUint128(ss0[:]) // TODO: Use unsafe casting to make faster
                second := BytesToUint128(ss1[:]) // TODO: Use unsafe casting to make faster

                if server_id == 0 {
                        res.data[res.index].AddInPlace(second)
                        res.data[res.index+1].AddInPlace(first)
                } else if server_id == 1 {
                        res.data[res.index].SubInPlace(first)
			res.data[res.index].SubInPlace(second)
                        res.data[res.index+1].AddInPlace(second)
                } else {
                        // server_id == 2
                        res.data[res.index].AddInPlace(first)
                        res.data[res.index+1].SubInPlace(first)
			res.data[res.index+1].SubInPlace(second)
                }

                res.index += 2 // copied over data in two 128-bit ints
                return
        }

        sL := BlockStack[lvl][0]
        sR := BlockStack[lvl][1]
        tL, tR := prg(&s[0], &sL[0], &sR[0])
        all_bits := k[17+lvl*33+32]

        if t0 != 0 {
        	sCW0 := k[17+lvl*33   :17+lvl*33+16]
		tLCW00 := (all_bits >> 7) & 1
        	tLCW01 := (all_bits >> 6) & 1
		tRCW00 := (all_bits >> 3) & 1
        	tRCW01 := (all_bits >> 2) & 1

                aes.Xor16(&sL[0], &sL[0], &sCW0[0])
                aes.Xor16(&sR[0], &sR[0], &sCW0[0])

                tL[0] ^= tLCW00
                tL[1] ^= tLCW01
                tR[0] ^= tRCW00
                tR[1] ^= tRCW01
        }

        if t1 != 0 {
        	sCW1 := k[17+lvl*33+16:17+lvl*33+32]
        	tLCW10 := (all_bits >> 5) & 1
        	tLCW11 := (all_bits >> 4) & 1
        	tRCW10 := (all_bits >> 1) & 1
        	tRCW11 := all_bits & 1

                aes.Xor16(&sL[0], &sL[0], &sCW1[0])
                aes.Xor16(&sR[0], &sR[0], &sCW1[0])

                tL[0] ^= tLCW10
                tL[1] ^= tLCW11
                tR[0] ^= tRCW10
                tR[1] ^= tRCW11
        }

        evalFullRecursive128(BlockStack, k, sL, tL[0], tL[1], lvl+1, stop, res, server_id)
        evalFullRecursive128(BlockStack, k, sR, tR[0], tR[1], lvl+1, stop, res, server_id)
}

// Outputs an array of uint64 of length 2 * N, where N = (1 << log N)
// This is because we are using replicated secret sharing -- so every value is represented
// via two shares.
func EvalFull64(key DPFkey, logN uint64, server_id int) []uint64 {
	if !(server_id == 0 || server_id == 1 || server_id == 2) {
		panic("Invalid server_id in EvallFull")
	}

	s := new(Block)
	copy(s[:], key[:16])
	t0 := (key[16] & 2) >> 1
	t1 := key[16] & 1

	stop := logN

	buf := make([]uint64, (1<<logN) * 2) // Output: 2N uint64s 
	var b = bytearr{buf, 0}

	var BlockStack = make([][2]*Block, logN+1)
	for i := uint64(0); i < logN + 1; i++ {
		BlockStack[i][0] = new(Block)
		BlockStack[i][1] = new(Block)
	}

	evalFullRecursive64(BlockStack, key, s, t0, t1, 0, stop, &b, server_id)

	return b.data
}

// Outputs an array of uint128 of length 2 * N, where N = (1 << log N)
// This is because we are using replicated secret sharing -- so every value is represented
// via two shares.
func EvalFull128(key DPFkey, logN uint64, server_id int) []Uint128 {
        buf := make([]Uint128, (1<<logN) * 2) // Output: 2N uint128s
	return EvalFull128Into(key, logN, server_id, buf)
}

func EvalFull128Into(key DPFkey, logN uint64, server_id int, into []Uint128) []Uint128 {
        if !(server_id == 0 || server_id == 1 || server_id == 2) {
                panic("Invalid server_id in EvallFull128")
        }

        s := new(Block)
        copy(s[:], key[:16])
        t0 := (key[16] & 2) >> 1
        t1 := key[16] & 1

        stop := logN

        var b = bytearr128{into, 0}

        var BlockStack = make([][2]*Block, logN+1) 
        for i := uint64(0); i < logN+1; i++ {
                BlockStack[i][0] = new(Block)
                BlockStack[i][1] = new(Block)
        }

        evalFullRecursive128(BlockStack, key, s, t0, t1, 0, stop, &b, server_id)

        return b.data
}
