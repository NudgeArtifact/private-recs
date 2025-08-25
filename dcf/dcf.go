// Code adapted from: https://github.com/dkales/dpf-go/blob/master/dpf/dpf.go
//                    https://github.com/dimakogan/dpf-go/blob/master/dpf/dpf.go
//

package dcf

import (
        "fmt"
	"bytes"
        "crypto/rand"
	"encoding/gob"
        "encoding/binary"

        . "private-recs/uint128"
        aes "private-recs/aes"
)

type DCFkey []byte
type block [16]byte

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
var prfExtra *aes.AesPrf // used to recover shares of DCF values
var keyL = make([]uint32, 11*4)
var keyR = make([]uint32, 11*4)
var keyExtra = make([]uint32, 11*4)


// Implements a two-party, additive DCF 
// The DCF goes LEFT: At each level, get shares of [1] if diverge from the special path to the left.
// This is equivalent to getting [1] when evaluating at a point x for x >= alpha.
// The shares themselves are either 64-bit or 128-bit values.

func init() {
        // Hard-codes the left and right PRF keys
        var prfkeyL = []byte{36, 156, 50, 234, 92, 230, 49, 9, 174, 170, 205, 160, 98, 236, 29, 243}
        var prfkeyR = []byte{209, 12, 199, 173, 29, 74, 44, 128, 194, 224, 14, 44, 2, 201, 110, 28}
        var prfkeyExtra = []byte{210, 12, 199, 173, 29, 74, 44, 128, 194, 224, 14, 44, 2, 201, 110, 28}
        var errL, errR, errExtra error

        prfL, errL = aes.NewCipher(prfkeyL)
        if errL != nil {
                panic("dcf: can't init AES")
        }

        prfR, errR = aes.NewCipher(prfkeyR)
        if errR != nil {
                panic("dcf: can't init AES")
        }

	prfExtra, errExtra = aes.NewCipher(prfkeyExtra)
	if errExtra != nil {
		panic("dcf: can't init AES")
	}

        aes.ExpandKeyAsm(&prfkeyL[0], &keyL[0])
        aes.ExpandKeyAsm(&prfkeyR[0], &keyR[0])
        aes.ExpandKeyAsm(&prfkeyExtra[0], &keyExtra[0])

        //if cpu.X86.HasSSE2 == false || cpu.X86.HasAVX2 == false {
        //      panic("we need sse2 and avx")
        //}
}

// Returns the two lowest-order bits of in, each stored in a separate byte
func getBit(in *byte) byte {
	bit0 := *in & 1
	return bit0
}

// Bitwise AND-and-NOT: Clears out lowest-order two bits
func clr(in *byte) {
	*in &^= 0x1
}

func prg64(seed *block, s0, s1 *byte) (byte, byte, uint64) {
        aes.Aes128MMO(&keyL[0], s0, &seed[0]) // inputs: key, dst, src
        t0 := getBit(s0)
        clr(s0)

        aes.Aes128MMO(&keyR[0], s1, &seed[0])
        t1 := getBit(s1)
        clr(s1)

	var buf [16]byte
	aes.Aes128MMO(&keyExtra[0], &buf[0], &seed[0])

	return t0, t1, binary.LittleEndian.Uint64(buf[:8]) 
}

func prg128(seed *block, s0, s1 *byte) (byte, byte, *Uint128) {
        aes.Aes128MMO(&keyL[0], s0, &seed[0]) // inputs: key, dst, src
        t0 := getBit(s0)
        clr(s0)

        aes.Aes128MMO(&keyR[0], s1, &seed[0])
        t1 := getBit(s1)
        clr(s1)

	var buf [16]byte
	aes.Aes128MMO(&keyExtra[0], &buf[0], &seed[0])

	return t0, t1, BytesToUint128(buf[:16])
}

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

        stop := logN
        sAL := new(block)
        sAR := new(block)
        sBL := new(block)
        sBR := new(block)

	hi, lo := Uint128ToLimbs(alpha)
	at := hi
	index := uint64(0)

        for i := uint64(0); i < stop; i++ {
		//fmt.Printf(" gen level %d: bits %d, %d and CW %d\n", i, tA[0], tB[0], binary.LittleEndian.Uint64(scw[:8]))

                tAL, tAR, aAR := prg128(sA, &sAL[0], &sAR[0]) // inputs: seed, left child, right child
                tBL, tBR, aBR := prg128(sB, &sBL[0], &sBR[0])

                if (at & (1 << (63 - index))) != 0 {
                        //KEEP = R, LOSE = L
                        aes.Xor16(&scw[0], &sAL[0], &sBL[0])

			tLCW := tAL ^ tBL
			tRCW := tAR ^ tBR ^ 1

                        bR := Sub(aAR, aBR)
                        if tA == 1 {
                                bR.NegateInPlace()
                        }

			CW = append(CW, scw[:]...)
			CW = append(CW, tLCW, tRCW) // TODO: Pack into single byte
			CW = append(CW, Uint128ToBytes(bR)[:]...) // TODO: Pack 4 bits into a single byte!

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

                        bR := Sub(aAR, aBR) // shares of 1, leaving to left
			bR.SubOneInPlace()
                        if tA == 1 {
				bR.NegateInPlace()
                        }

			CW = append(CW, scw[:]...)
			CW = append(CW, tLCW, tRCW)
                        CW = append(CW, Uint128ToBytes(bR)[:]...) // TODO: Pack 4 bits into a single byte!

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

		index += 1
		if index == 64 {
			at = lo
			index = 0
		}
        }

        aes.Aes128MMO(&keyL[0], &sAL[0], &sA[0]) // inputs: key, dst, src
        aes.Aes128MMO(&keyL[0], &sBL[0], &sB[0]) 

	a_val := BytesToUint128(sAL[:16])
	b_val := BytesToUint128(sBL[:16])
	cw_val := Sub(a_val, b_val)
	if leq {
        	cw_val.SubOneInPlace()
	}

        if tA == 1 {
		cw_val.NegateInPlace()
        }

	Uint128ToBytesDst(cw_val, scw[:16])
	CW = append(CW, scw[:]...)

	kA = append(kA, CW...)
	kB = append(kB, CW...)
	return kA, kB
}

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

        tA := getBit(&sA[0])
        tB := tA ^ 1      // bit 0: shares of [1] iff on path
        // bit 1: shares of [1] iff on path and leaving it to the left

        clr(&sA[0])
        clr(&sB[0])

        kA = append(kA, sA[:]...)
        kA = append(kA, tA)
        kB = append(kB, sB[:]...)
        kB = append(kB, tB)

        stop := logN
        sAL := new(block)
        sAR := new(block)
        sBL := new(block)
        sBR := new(block)

        for i := uint64(0); i < stop; i++ {
                //fmt.Printf(" gen level %d: bits %d, %d and CW %d\n", i, tA[0], tB[0], binary.LittleEndian.Uint64(scw[:8]))

                tAL, tAR, aAR := prg64(sA, &sAL[0], &sAR[0]) // inputs: seed, left child, right child
                tBL, tBR, aBR := prg64(sB, &sBL[0], &sBR[0])

                if (alpha & (1 << (logN - 1 - i))) != 0 {
                        //KEEP = R, LOSE = L
                        aes.Xor16(&scw[0], &sAL[0], &sBL[0])

                        tLCW := tAL ^ tBL
                        tRCW := tAR ^ tBR ^ 1

			bR := aAR - aBR
			if tA == 1 {
				bR = -bR
			}

                        CW = append(CW, scw[:]...)
                        CW = append(CW, tLCW, tRCW) // TODO: Pack 4 bits into a single byte!
			
			binary.LittleEndian.PutUint64(buf[:8], bR)
			CW = append(CW, buf[:8]...)

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

                        bR := aAR - aBR - 1 // shares of 1, leaving to left
                        if tA == 1 {
                        //        bL = -bL
                                bR = -bR
                        }

                        CW = append(CW, scw[:]...)
                        CW = append(CW, tLCW, tRCW)

                        binary.LittleEndian.PutUint64(buf[:8], bR)
                        CW = append(CW, buf[:8]...)

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

        cw_val := binary.LittleEndian.Uint64(sAL[:8]) - binary.LittleEndian.Uint64(sBL[:8])
	if leq {
		cw_val -= 1
	}
        if tA == 1 {
                cw_val = -cw_val
        }

        binary.LittleEndian.PutUint64(scw[:8], cw_val)
        CW = append(CW, scw[:8]...)
        //fmt.Printf(" gen final level: bits %d, %d and CW %d\n", tA[0], tB[0], cw_val)

        kA = append(kA, CW...)
        kB = append(kB, CW...)
        return kA, kB
}

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
	tB := tA ^ 1      // bit 0: shares of [1] iff on path
	// bit 1: shares of [1] iff on path and leaving it to the left

        clr(&sA[0])
        clr(&sB[0])

        kA = append(kA, sA[:]...)
        kA = append(kA, tA)
        kB = append(kB, sB[:]...)
        kB = append(kB, tB)

        stop := logN
        sAL := new(block)
        sAR := new(block)
        sBL := new(block)
        sBR := new(block)

        for i := uint64(0); i < stop; i++ {
		//fmt.Printf(" gen level %d: bits %d, %d and CW %d\n", i, tA[0], tB[0], binary.LittleEndian.Uint64(scw[:8]))

                tAL, tAR, aAR := prg128(sA, &sAL[0], &sAR[0]) // inputs: seed, left child, right child
                tBL, tBR, aBR := prg128(sB, &sBL[0], &sBR[0])

                if (alpha & (1 << (logN - 1 - i))) != 0 {
                        //KEEP = R, LOSE = L
                        aes.Xor16(&scw[0], &sAL[0], &sBL[0])

			tLCW := tAL ^ tBL
			tRCW := tAR ^ tBR ^ 1

                        bR := Sub(aAR, aBR)
                        if tA == 1 {
                                bR.NegateInPlace()
                        }

			CW = append(CW, scw[:]...)
			CW = append(CW, tLCW, tRCW) // TODO: Pack into single byte
			CW = append(CW, Uint128ToBytes(bR)[:]...) // TODO: Pack 4 bits into a single byte!

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

                        bR := Sub(aAR, aBR) // shares of 1, leaving to left
			bR.SubOneInPlace()
                        if tA == 1 {
				bR.NegateInPlace()
                        }

			CW = append(CW, scw[:]...)
			CW = append(CW, tLCW, tRCW)
                        CW = append(CW, Uint128ToBytes(bR)[:]...) // TODO: Pack 4 bits into a single byte!

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

	a_val := BytesToUint128(sAL[:16])
	b_val := BytesToUint128(sBL[:16])
	cw_val := Sub(a_val, b_val)
	if leq {
        	cw_val.SubOneInPlace()
	}

        if tA == 1 {
		cw_val.NegateInPlace()
        }

	Uint128ToBytesDst(cw_val, scw[:16])
	CW = append(CW, scw[:]...)

	kA = append(kA, CW...)
	kB = append(kB, CW...)
	return kA, kB
}

func Eval64(k DCFkey, x uint64, logN uint64, server_id int) uint64 {
        if !(server_id == 0 || server_id == 1) {
                panic("Invalid server_id in Eval")
        }

        s := new(block)
        sL := new(block)
        sR := new(block)
        copy(s[:], k[:16])
	t := k[16] // a DPF key is an array of bytes

        stop := logN
	sum := uint64(0)

        // DCF key: seed (0-15); start_bit (16); CW (17, onwards)
        // where CW = (scw [16 bits], tLCW, tRCW [each 1 byte], bR [64 bits = 8 bytes] for each level) 
        // (length of each level = 16 + 2 + 8 = 26 bytes,
        // followed by final scw

        for i := uint64(0); i < stop; i++ {
                tL, tR, aR := prg64(s, &sL[0], &sR[0])
		if t != 0 {
			sCW  := k[17+i*26 : 17+i*26+16]
			tLCW := k[17+i*26+16]
			tRCW := k[17+i*26+17]

			bR := binary.LittleEndian.Uint64(k[17+i*26+18 : 17+i*26+26])

			aes.Xor16(&sL[0], &sL[0], &sCW[0])
			aes.Xor16(&sR[0], &sR[0], &sCW[0])

			tL ^= tLCW
			tR ^= tRCW

			aR += bR
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
		res += binary.LittleEndian.Uint64(k[len(k)-8:len(k)])
	}

	if server_id == 0 {
		return sum + res
	} else {
		return -sum - res
	}
}

func Eval128(k DCFkey, x uint64, logN uint64, server_id int) Uint128 {
        if !(server_id == 0 || server_id == 1) {
                panic("Invalid server_id in Eval")
        }

        s := new(block)
        sL := new(block)
        sR := new(block)
        copy(s[:], k[:16])
	t := k[16] // a DPF key is an array of bytes

        stop := logN
	sum := ToUint128(0)

        for i := uint64(0); i < stop; i++ {
                tL, tR, aR := prg128(s, &sL[0], &sR[0])

		if t != 0 {
			sCW  := k[17+i*34 : 17+i*34+16]
			tLCW := k[17+i*34+16]
			tRCW := k[17+i*34+17]
			bR   := BytesToUint128(k[17+i*34+18 : 17+i*34+34])

			aes.Xor16(&sL[0], &sL[0], &sCW[0])
			aes.Xor16(&sR[0], &sR[0], &sCW[0])
			tL ^= tLCW
			tR ^= tRCW
			aR.AddInPlace(bR)
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
                res.AddInPlace(BytesToUint128(k[len(k)-16:len(k)]))
        }

        if server_id == 0 {
		res.AddInPlace(sum)
                return *res
        } else {
                res.NegateInPlace()
		res.SubInPlace(sum)
		return *res
        }
}

func EvalLargeInput128(k DCFkey, x *Uint128, logN uint64, server_id int) Uint128 {
        if !(server_id == 0 || server_id == 1) {
                panic("Invalid server_id in Eval")
        }

	if logN != 128 {
		panic("Not supported")
	}

        s := new(block)
        sL := new(block)
        sR := new(block)
        copy(s[:], k[:16])
	t := k[16] // a DPF key is an array of bytes

        stop := logN
	sum := ToUint128(0)

        hi, lo := Uint128ToLimbs(x)
        at := hi
        index := uint64(0)

        for i := uint64(0); i < stop; i++ {
                tL, tR, aR := prg128(s, &sL[0], &sR[0])

		if t != 0 {
			sCW  := k[17+i*34 : 17+i*34+16]
			tLCW := k[17+i*34+16]
			tRCW := k[17+i*34+17]
			bR   := BytesToUint128(k[17+i*34+18 : 17+i*34+34])

			aes.Xor16(&sL[0], &sL[0], &sCW[0])
			aes.Xor16(&sR[0], &sR[0], &sCW[0])
			tL ^= tLCW
			tR ^= tRCW
			aR.AddInPlace(bR)
		}

		if (at & (uint64(1) << (63 - index))) != 0 {
			*s = *sR
			t = tR
			sum.AddInPlace(aR)
		} else {
			*s = *sL
			t = tL
		}

		index += 1
		if index == 64 {
			index = 0
			at = lo
		}
        }


        aes.Aes128MMO(&keyL[0], &s[0], &s[0])
	res := BytesToUint128(s[:16])

        if t != 0 {
                res.AddInPlace(BytesToUint128(k[len(k)-16:len(k)]))
        }
	
        if server_id == 0 {
		res.AddInPlace(sum)
                return *res
        } else {
                res.NegateInPlace()
		res.SubInPlace(sum)
		return *res
        }
}

func evalFullRecursive64(blockStack [][2]*block, k DCFkey, s *block, t byte, lvl uint64, stop uint64, res *bytearr, sum uint64, server_id int) {
        if lvl == stop {
                aes.Aes128MMO(&keyL[0], &s[0], &s[0])
        	val := binary.LittleEndian.Uint64(s[:8])

        	if t != 0 {
                	val += binary.LittleEndian.Uint64(k[len(k)-8:len(k)])
        	}

       		if server_id == 0 {
                	res.data[res.index] = sum + val
        	} else {
                	res.data[res.index] = -sum -val
        	}

                res.index += 1
                return
        }

        sL := blockStack[lvl][0]
        sR := blockStack[lvl][1]
        tL, tR, aR := prg64(s, &sL[0], &sR[0])

	if t != 0 {
		sCW  := k[17+lvl*26   : 17+lvl*26+16]
		tLCW := k[17+lvl*26+16]
		tRCW := k[17+lvl*26+17]
		bR   := binary.LittleEndian.Uint64(k[17+lvl*26+18: 17+lvl*26+26])

		aes.Xor16(&sL[0], &sL[0], &sCW[0])
		aes.Xor16(&sR[0], &sR[0], &sCW[0])
		tL ^= tLCW
		tR ^= tRCW
		aR += bR
	}

        evalFullRecursive64(blockStack, k, sL, tL, lvl+1, stop, res, sum, server_id)
        evalFullRecursive64(blockStack, k, sR, tR, lvl+1, stop, res, sum + aR, server_id)
}

func evalFullRecursive128(blockStack [][2]*block, k DCFkey, s *block, t byte, lvl uint64, stop uint64, res *bytearr128, sum *Uint128, server_id int) {
        if lvl == stop {
        	aes.Aes128MMO(&keyL[0], &s[0], &s[0])
        	val := BytesToUint128(s[:16])

        	if t != 0 {
                	val.AddInPlace(BytesToUint128(k[len(k)-16:len(k)]))
        	}

		val.AddInPlace(sum)

        	if server_id == 1 {
                	val.NegateInPlace()
        	}

                res.data[res.index] = *val
                res.index += 1 
                return
        }

        sL := blockStack[lvl][0]
        sR := blockStack[lvl][1]
        tL, tR, aR := prg128(s, &sL[0], &sR[0])

	if t != 0 {
		sCW := k[17+lvl*34 : 17+lvl*34+16]
		tLCW := k[17+lvl*34+16]
		tRCW := k[17+lvl*34+17]
		bR   := BytesToUint128(k[17+lvl*34+18 : 17+lvl*34+34])

		aes.Xor16(&sL[0], &sL[0], &sCW[0])
		aes.Xor16(&sR[0], &sR[0], &sCW[0])
		tL ^= tLCW
		tR ^= tRCW
		aR.AddInPlace(bR)
	}

        evalFullRecursive128(blockStack, k, sL, tL, lvl+1, stop, res, sum, server_id)
        evalFullRecursive128(blockStack, k, sR, tR, lvl+1, stop, res, Add(sum, aR), server_id)
}

// Outputs an array of uint64 of length 2 * N, where N = (1 << log N)
// This is because we are using replicated secret sharing -- so every value is represented
// via two shares.
func EvalFull64(key DCFkey, logN uint64, server_id int) []uint64 {
        if !(server_id == 0 || server_id == 1) {
                panic("Invalid server_id in EvallFull")
        }

        s := new(block)
        copy(s[:], key[:16])
	t := key[16]
        stop := logN

        buf := make([]uint64, (1<<logN)) // Output: N uint64s 
        var b = bytearr{buf, 0}

        var blockStack = make([][2]*block, 64) 
        for i := 0; i < 64; i++ {
                blockStack[i][0] = new(block)
                blockStack[i][1] = new(block)
        }

        evalFullRecursive64(blockStack, key, s, t, 0, stop, &b, 0, server_id)

        return b.data
}

// Outputs an array of uint128 of length 2 * N, where N = (1 << log N)
// This is because we are using replicated secret sharing -- so every value is represented
// via two shares.
func EvalFull128(key DCFkey, logN uint64, server_id int) []Uint128 {
        if !(server_id == 0 || server_id == 1) {
                panic("Invalid server_id in EvallFull128")
        }

        s := new(block)
        copy(s[:], key[:16])
	t := key[16]
        stop := logN

        buf := make([]Uint128, (1<<logN)) // Output: N uint128s
        var b = bytearr128{buf, 0}

        var blockStack = make([][2]*block, 128) 
        for i := 0; i < 128; i++ {
                blockStack[i][0] = new(block)
                blockStack[i][1] = new(block)
        }

	sum := ToUint128(0)
        evalFullRecursive128(blockStack, key, s, t, 0, stop, &b, sum, server_id)

        return b.data
}

func ByteLen(mod uint64, logN uint64, small bool) uint64 {
	var key DCFkey
	if mod == 64 {
		key, _ = Gen64(0, logN, true)
	} else if mod == 128 {
		if !small {
			key, _ = Gen128(0, logN, true)
		} else {
			key, _ = GenSmallOutput128(0, logN, true)
		}
	} else {
		panic("Bad input to ByteLen")
	}

	var buf bytes.Buffer
        enc := gob.NewEncoder(&buf)
        err := enc.Encode(key)
        if err != nil {
                panic(fmt.Sprintf("Failed to encode message: %v", err))
        }

        return uint64(len(buf.Bytes()))
}
