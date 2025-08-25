package dcf

import (
        "crypto/rand"
        . "private-recs/uint128"
        aes "private-recs/aes"
)

// DCF where the shares at each level are just bits

func bitPrg128(seed *block, s0, s1 *byte) (byte, byte, byte) {
        aes.Aes128MMO(&keyL[0], s0, &seed[0]) // inputs: key, dst, src
        t0 := getBit(s0)
        clr(s0)

        aes.Aes128MMO(&keyR[0], s1, &seed[0])
        t1 := getBit(s1)
        clr(s1)

        var buf [16]byte
        aes.Aes128MMO(&keyExtra[0], &buf[0], &seed[0])
	t2 := getBit(&buf[0])

        return t0, t1, t2
}

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

        stop := logN - 7 // early stopping optimization, because output is just bits!
	if logN < 7 {
		stop = 0
	}

        sAL := new(block)
        sAR := new(block)
        sBL := new(block)
        sBR := new(block)

        for i := uint64(0); i < stop; i++ {
                //fmt.Printf(" gen level %d: bits %d, %d and CW %d\n", i, tA[0], tB[0], binary.LittleEndian.Uint64(scw[:8]))

                tAL, tAR, bA := bitPrg128(sA, &sAL[0], &sAR[0]) // inputs: seed, left child, right child
                tBL, tBR, bB := bitPrg128(sB, &sBL[0], &sBR[0])

                if (alpha & (uint64(1) << (logN - 1 - i)) != 0) {
                        //KEEP = R, LOSE = L
                        aes.Xor16(&scw[0], &sAL[0], &sBL[0])

                        tLCW := tAL ^ tBL
                        tRCW := tAR ^ tBR ^ 1

                        bR := bA ^ bB

                        CW = append(CW, scw[:]...)
                        CW = append(CW, (tLCW << 2) | (tRCW << 1) | bR) 

                        *sA = *sAR
                        if tA != 0 {
                                aes.Xor16(&sA[0], &sA[0], &scw[0])
                        }

                        *sB = *sBR
                        if tB != 0 {
                                aes.Xor16(&sB[0], &sB[0], &scw[0])
                        }

                        if tA != 0 {
                                tA = tAR ^ tRCW
                        } else {
                                tA = tAR
                        }

                        if tB != 0 {
                                tB = tBR ^ tRCW
                        } else {
                                tB = tBR
                        }

                } else {
                        //KEEP = L, LOSE = R
                        aes.Xor16(&scw[0], &sAR[0], &sBR[0])

                        tLCW := tAL ^ tBL ^ 1
                        tRCW := tAR ^ tBR
			bR := bA ^ bB ^ 1 // shares of 1, leaving to left

                        CW = append(CW, scw[:]...)
                        CW = append(CW, (tLCW << 2) | (tRCW << 1) | bR) 

                        *sA = *sAL
                        if tA != 0 {
                                aes.Xor16(&sA[0], &sA[0], &scw[0])
                        }
                        *sB = *sBL
                        if tB != 0 {
                                aes.Xor16(&sB[0], &sB[0], &scw[0])
                        }
                        if tA != 0 {
                                tA = tAL ^ tLCW
                        } else {
                                tA = tAL
                        }
                        if tB != 0 {
                                tB = tBL ^ tLCW
                        } else {
                                tB = tBL
                        }
                }
        }

        aes.Aes128MMO(&keyL[0], &sAL[0], &sA[0]) // inputs: key, dst, src
        aes.Aes128MMO(&keyL[0], &sBL[0], &sB[0])

        var start uint64
        if leq {
                start = alpha % (1 << 7) // last 8 bits of alpha
        } else {
                start = (alpha+1) % (1 << 7)
        }

	idx := start / 8
	offset := start % 8

	//fmt.Printf("Alpha is %d; start is %d; idx is %d; offset is %d\n", alpha, start, idx, offset)

	for b := 0; b < 16; b++ {
		last := sAL[b] ^ sBL[b]
	
		if b == int(idx) {
			//fmt.Printf("  byte %d: XORing in %b\n", b, byte((1 << (8-offset)) - 1))
			last ^= byte((1 << (8-offset)) - 1)
		} else if b > int(idx) {
			//fmt.Printf("  byte %d: XORing in %b\n", b, (^byte(0)))
			last ^= (^byte(0))
		}

		CW = append(CW, last)
	}

        kA = append(kA, CW...)
        kB = append(kB, CW...)

        return kA, kB
}

func EvalSmallOutput128(k DCFkey, x uint64, logN uint64, server_id int) Uint128 {
        if !(server_id == 0 || server_id == 1) {
                panic("Invalid server_id in Eval")
        }

        s := new(block)
        sL := new(block)
        sR := new(block)
        copy(s[:], k[:16])
        t := k[16] // a DPF key is an array of bytes

        stop := logN - 7
	if logN < 7 {
		stop = 0
	}

	var sum byte

        for i := uint64(0); i < stop; i++ {
                tL, tR, b := bitPrg128(s, &sL[0], &sR[0])

                if t != 0 {
                        sCW  := k[17+i*17 : 17+i*17+16]
                        tLCW := (k[17+i*17+16] & 0x4) >> 2
                        tRCW := (k[17+i*17+16] & 0x2) >> 1
			bCW  := k[17+i*17+16] & 0x1

                        aes.Xor16(&sL[0], &sL[0], &sCW[0])
                        aes.Xor16(&sR[0], &sR[0], &sCW[0])

                        tL ^= tLCW
                        tR ^= tRCW
			b  ^= bCW
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

	at := int(x % (1 << 7))
	idx := int(at / 8)
	offset := (at % 8)

        aes.Aes128MMO(&keyL[0], &sL[0], &s[0])
	last := sL[idx] 

        if t != 0 {
		last ^= k[len(k) - 16 + idx]
        }

	if (last & (1 << (7-offset))) != 0 {
		sum ^= 1
	}

	liftedSum := MakeUint128(0, uint64(sum))
        if server_id == 0 {
                return *liftedSum
        } else {
                liftedSum.NegateInPlace()
                return *liftedSum
        }
}
