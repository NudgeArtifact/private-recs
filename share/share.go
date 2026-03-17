package share

// #cgo CFLAGS: -O3 -march=native -I../uint128
// #include "uint128.h"
import "C"

import (
	"fmt"
	"math"
	"github.com/NudgeArtifact/private-recs/dcf"
	. "github.com/NudgeArtifact/private-recs/rand"
	. "github.com/NudgeArtifact/private-recs/uint128"
)

const MIN_BORDER_64 = uint64(1 << 32)
const MAX_BORDER_64 = uint64((1 << 64) - (1 << 32))

// Implement share computations, as described in:
// "High-Throughput Semi-Honest Secure 3-Party Computation with an Honest Majority"

type share struct {
	First  uint64
	Second uint64
}

type Share128 struct {
	First  Uint128
	Second Uint128
}

type TruncKey struct {
	Dcf    dcf.DCFkey
	Share  Uint128
	Share2 Uint128
}

func (s *Share128) Print() {
	fmt.Printf("First: ")
	s.First.Print()
	fmt.Printf("Second: ")
	s.Second.Print()
}

func (s *Share128) ShareSum() *Uint128 {
	return Add(&s.First, &s.Second)
}

func (s *Share128) shareFirst() *Uint128 {
	return &s.First
}

func shareAdditive(v uint64, reader *BufPRGReader, num_shares int) []uint64 {
	if num_shares < 2 {
		panic("Invalid number of shares in shareAdditive")
	}

	shares := make([]uint64, num_shares)
	sum := uint64(0)

	for i := 0; i < num_shares-1; i++ {
		shares[i] = reader.Uint64()
		sum += shares[i]
	}

	shares[num_shares-1] = v - sum

	return shares
}

func recoverAdditive(nums ...uint64) uint64 {
	sum := uint64(0)
	for _, num := range nums {
		sum += num
	}
	return sum
}

// Takes as input a 64-bit value. Additively secret-shares it into 'num_shares' 128-bit values.
// Note: needs to sign extend, so that Additive preserves the correct functionality.
func shareAdditive128(v uint64, reader *BufPRGReader, num_shares int) []Uint128 {
	if num_shares < 2 {
		panic("Invalid number of shares in shareAdditive128")
	}

	shares := make([]Uint128, num_shares)
	sum := MakeUint128(0, 0)

	for i := 0; i < num_shares-1; i++ {
		hi, lo := reader.TwoUint64()
		SetUint128(hi, lo, &shares[i])
		sum.AddInPlace(&shares[i])
	}

	val := ToUint128(v)
	SubDst(val, sum, &shares[num_shares-1]) // equiv to: shares[num_shares-1] = val - sum

	return shares
}

// Outputs the 64-bit integer that is Additively secret-shared among 128-bit values
func recoverAdditive128(nums ...*Uint128) uint64 {
	sum := MakeUint128(0, 0)
	for _, num := range nums {
		sum.AddInPlace(num)
	}

	if !CheckUint64(sum) {
		fmt.Printf("Recovered value: ")
		sum.Print()
		panic("recoverAdditive128: secret shared value does not fit in 64 bits")
	}

	return ToUint64(sum)
}

func ShareRSS(v uint64, reader *BufPRGReader) (*share, *share, *share) {
	a, b := reader.TwoUint64()

	s0 := new(share)
	s1 := new(share)
	s2 := new(share)

	s0.First = b
	s0.Second = a

	s1.First = -a - b + v
	s1.Second = b

	s2.First = a
	s2.Second = -a - b + v

	return s0, s1, s2
}

func ShareRSS128(v uint64, reader *BufPRGReader) (*Share128, *Share128, *Share128) {
	s0 := new(Share128)
	s1 := new(Share128)
	s2 := new(Share128)

	ShareRSS128Dst(v, s0, s1, s2, reader)

	return s0, s1, s2
}

func ShareRSS128Dst(v uint64, s0, s1, s2 *Share128, reader *BufPRGReader) {
	hi_a, lo_a := reader.TwoUint64()
	hi_b, lo_b := reader.TwoUint64()

	c := ToUint128Sub(v, hi_a, lo_a, hi_b, lo_b)

	// Shares: (b, a)
	SetUint128(hi_b, lo_b, &s0.First)
	SetUint128(hi_a, lo_a, &s0.Second)

	// Shares: (v - a - b, b)
	Copy(c, &s1.First)
	Copy(&s0.First, &s1.Second)

	// Shares: (a, v - a - b)
	Copy(&s0.Second, &s2.First)
	Copy(c, &s2.Second)
}

func AddRSS(s0, s1 *share) *share {
	s := new(share)
	s.First = s0.First + s1.First
	s.Second = s0.Second + s1.Second
	return s
}

func SubRSS(s0, s1 *share) *share {
	s := new(share)
	s.First = s0.First - s1.First
	s.Second = s0.Second - s1.Second
	return s
}

func AddRSS128(s0, s1 *Share128) *Share128 {
	s := new(Share128)
	s.First.AddInPlace(&s0.First)
	s.First.AddInPlace(&s1.First)
	s.Second.AddInPlace(&s0.Second)
	s.Second.AddInPlace(&s1.Second)
	return s
}

func SubRSS128(s0, s1 *Share128) *Share128 {
	s := new(Share128)
	s.First.AddInPlace(&s0.First)
	s.First.SubInPlace(&s1.First)
	s.Second.AddInPlace(&s0.Second)
	s.Second.SubInPlace(&s1.Second)
	return s
}

func AddRSSInPlace(s0, s1 *share) {
	s0.First += s1.First
	s0.Second += s1.Second
}

func SubRSSInPlace(s0, s1 *share) {
	s0.First -= s1.First
	s0.Second -= s1.Second
}

func AddRSSInPlace128(s0, s1 *Share128) {
	s0.First.AddInPlace(&s1.First)
	s0.Second.AddInPlace(&s1.Second)
}

func SubRSSInPlace128(s0, s1 *Share128) {
	s0.First.SubInPlace(&s1.First)
	s0.Second.SubInPlace(&s1.Second)
}

// compute secret shares of v - x
func PtxtSubRSSInPlace128(s *Share128, v *Uint128, share_id int) {
	PtxtSubRSSDst128(s, v, share_id, s)
}

// compute secret shares of v - x
func PtxtSubRSSDst128(s *Share128, v *Uint128, share_id int, dst *Share128) {
	NegateDst(&s.First, &dst.First)
	NegateDst(&s.Second, &dst.Second)
	if share_id == 0 {
		return
	} else if share_id == 1 {
		dst.First.AddInPlace(v)
		return
	} else if share_id == 2 {
		dst.Second.AddInPlace(v)
		return
	}

	panic("Invalid share ID")
}

func PtxtMulRSS(s *share, v uint64) *share {
	t := new(share)
	t.First = s.First * v
	t.Second = s.Second * v
	return t
}

func PtxtMulRSS128(s *Share128, v uint64) *Share128 {
	if (v>>63)&1 == 1 {
		panic("Warning: this method gives the wrong answer on negative values. Cast Ptxt to Uint128 instead.")
	}

	t := new(Share128)
	Mul64Dst(&s.First, v, &t.First) // computes t.First = s.First * v
	Mul64Dst(&s.Second, v, &t.Second)
	return t
}

func largePtxtMulRSS128(s *Share128, v *Uint128) *Share128 {
	t := new(Share128)
	MulDst(&s.First, v, &t.First)
	MulDst(&s.Second, v, &t.Second)
	return t
}

func largePtxtMulRSSInPlace128(s *Share128, v *Uint128) {
	MulDst(&s.First, v, &s.First)
	MulDst(&s.Second, v, &s.Second)
}

func mulRSS(s0, s1 *share) uint64 {
	return s0.First*s1.First + s0.Second*s1.First + s1.Second*s0.First
}

func MulRSS128(s0, s1 *Share128) *Uint128 {
	interm := Mul(&s0.First, &s1.First)
	interm.MulAddInPlace(&s0.Second, &s1.First)
	interm.MulAddInPlace(&s1.Second, &s0.First)
	return interm
}

func MulRSS128Dst(s0, s1 *Share128, dst *Uint128) {
	MulDst(&s0.First, &s1.First, dst)
	dst.MulAddInPlace(&s0.Second, &s1.First)
	dst.MulAddInPlace(&s1.Second, &s0.First)
}

func recoverRSS(s0, s1, s2 *share) uint64 {
	if (s0.Second != s2.First) || (s0.First != s1.Second) || (s1.First != s2.Second) {
		panic("Bad RSS share in recoverRSS")
	}

	return s0.First + s0.Second + s1.First
}

func recoverRSS128(s0, s1, s2 *Share128) uint64 {
	if (!s0.Second.Equals(&s2.First)) || (!s0.First.Equals(&s1.Second)) || (!s1.First.Equals(&s2.Second)) {
		panic("Bad RSS share in recoverRSS128")
	}

	interm := Add(&s0.First, &s0.Second)
	interm.AddInPlace(&s1.First)

	if !CheckUint64(interm) {
		interm.Print()
		panic("recoverRSS128: secret shared value does not fit in 64 bits")
	}

	return ToUint64(interm)
}

func AdditiveToRSS(a0, a1, a2 uint64, reader *BufPRGReader) (*share, *share, *share) {
	r01, r02 := reader.TwoUint64() // pairwise shared secrets
	r12 := reader.Uint64()         // (in real protocol, derive with pairwise seeds)

	s0 := new(share)
	s0.First = a1 - r01 - r12  // re-shared from server 1
	s0.Second = a0 + r01 + r02 // known

	s1 := new(share)
	s1.First = a2 + r12 - r02  // re-shared from server 2
	s1.Second = a1 - r01 - r12 // known

	s2 := new(share)
	s2.First = a0 + r01 + r02  // re-shared from server 0
	s2.Second = a2 + r12 - r02 // known

	return s0, s1, s2
}

func AdditiveToRSS128(a0, a1, a2 *Uint128, reader *BufPRGReader) (*Share128, *Share128, *Share128) {
	s0 := new(Share128)
	s1 := new(Share128)
	s2 := new(Share128)

	AdditiveToRSS128Dst(a0, a1, a2, s0, s1, s2, reader)

	return s0, s1, s2
}

func AdditiveToRSS128Dst(a0, a1, a2 *Uint128, s0, s1, s2 *Share128, reader *BufPRGReader) {
	r01_hi, r01_lo := reader.TwoUint64() // pairwise shared secrets
	r12_hi, r12_lo := reader.TwoUint64()
	r02_hi, r02_lo := reader.TwoUint64()

	SubTwoHalvesDst(a1, r01_hi, r01_lo, r12_hi, r12_lo, &s0.First)  // re-shared from server 1
	AddTwoHalvesDst(a0, r01_hi, r01_lo, r02_hi, r02_lo, &s0.Second) // known

	AddSubTwoHalvesDst(a2, r12_hi, r12_lo, r02_hi, r02_lo, &s1.First) // re-shared from server 2
	SubTwoHalvesDst(a1, r01_hi, r01_lo, r12_hi, r12_lo, &s1.Second)   // known

	AddTwoHalvesDst(a0, r01_hi, r01_lo, r02_hi, r02_lo, &s2.First)     // re-shared from server 0
	AddSubTwoHalvesDst(a2, r12_hi, r12_lo, r02_hi, r02_lo, &s2.Second) // known
}

// Note: server 1 decides whether to truncate (x-r1) or (x-r2), depending on
// whether r1 or r2 falls in a bad interval (i.e., is within 2^(-64) of the
// min or max possible value. This reduces the probability of a truncation
// failure.
func truncateRSSToAdditive(s0, s1, s2 *share, decimals uint, reader *BufPRGReader) (uint64, uint64, uint64) {
	Delta := uint64(1 << 63)
	if DebugMode {
		secret := recoverRSS(s0, s1, s2)

		// Assert that secret is at least 1 bit shorter than modulus (in signed representation)
		if !((secret < Delta/2) || (secret >= uint64(-Delta/2))) {
			panic("TruncateRSS: shared secert is not in correct range (i.e., 1 bit shorter than modulus!)")
		}
	}

	// s0 = (a, b), s1 = (b, x-a-b), s2 = (x-a-b, a)
	// In this protocol, take r := (-a-b)

	r := -s0.First - s0.Second
	y := s1.First
	if DebugMode && !(y == s2.Second) {
		panic("TruncateRSS: should not happen")
	}

	// Computed on server 0
	r_trunc := r >> decimals
	r_trunc_2 := (r + Delta) >> decimals
	r_rem := r % (1 << decimals)

	dcfL, dcfR := dcf.Gen64(r_rem, uint64(decimals) /* logN */, true /* >= */)
	mask, mask_2 := reader.TwoUint64()

	// Server 0 sends to server 1: dcfL, mask, mask_2
	messageL := mask
	messageL_2 := mask_2

	// Server 0 sends to server 1: dcfR, r_trunc-mask, rtrunc_2 - mask2
	messageR := r_trunc - mask
	messageR_2 := r_trunc_2 - mask_2

	// Computed on servers 1 and 2
	y_trunc := y >> decimals
	y_trunc_2 := (y + Delta) >> decimals
	y_rem := y % (1 << decimals)

	// Output on server 1
	corrL := dcf.Eval64(dcfL, y_rem, uint64(decimals), 0)
	zL := uint64(0)
	if (y >= Delta/2) && (y <= math.MaxUint64-uint64(Delta/2)+1) {
		zL = y_trunc - messageL - (1 - corrL) // (1-x) to flip DCF from >= to <
	} else {
		zL = y_trunc_2 - messageL_2 - (1 - corrL)
	}

	// Output on server 2
	corrR := dcf.Eval64(dcfR, y_rem, uint64(decimals), 1)
	zR := uint64(0)

	if (y >= Delta/2) && (y <= math.MaxUint64-uint64(Delta/2)+1) {
		zR = -messageR + corrR // (1-x) to flip DCF from >= to <
	} else {
		zR = -messageR_2 + corrR
	}

	return 0, zL, zR
}

func DealerTruncateRSSToAdditive128(s *Share128, decimals uint, reader *BufPRGReader) (*TruncKey, *TruncKey) {
	if decimals >= 64 {
		panic("Not yet supported")
	}

	r := s.ShareSum()
	r.NegateInPlace()

	// Computed on server 0
	Delta := MakeUint128((1 << 63), 0)
	r_padded := Add(r, Delta)
	r_trunc := RshSignExtend(r, decimals)
	r_trunc_2 := RshSignExtend(r_padded, decimals)
	r_rem := ToUint64(r) % (1 << decimals)

	//fmt.Printf("  build DCF at %d\n", r_rem)
	dcfL, dcfR := dcf.GenSmallOutput128(r_rem, uint64(decimals) /* logN */, true /* >= */)
	mask_hi, mask_lo := reader.TwoUint64()
	mask_2_hi, mask_2_lo := reader.TwoUint64()

	// Server 0 sends to server 1: dcfL, mask, mask_2
	messageL := MakeUint128(mask_hi, mask_lo)
	messageL_2 := MakeUint128(mask_2_hi, mask_2_lo)

	// Server 0 sends to server 1: dcfR, r_trunc-mask, rtrunc_2 - mask2
	messageR := Sub(r_trunc, messageL)
	messageR_2 := Sub(r_trunc_2, messageL_2)

	keyL := TruncKey{
		Dcf:    dcfL,
		Share:  *messageL,
		Share2: *messageL_2,
	}

	keyR := TruncKey{
		Dcf:    dcfR,
		Share:  *messageR,
		Share2: *messageR_2,
	}

	return &keyL, &keyR
}

func ServerLTruncateRSSToAdditive128Dst(truncKey *TruncKey, s *Share128, dst, dstSq *Uint128, decimals uint) {
	if decimals >= 64 {
		panic("Not yet supported")
	}

	// s0 = (a, b), s1 = (b, x-a-b), s2 = (x-a-b, a)
	// In this protocol, take r := (-a-b)
	y := &s.First

	// Computed on servers 1 and 2
	Delta := MakeUint128((1 << 63), 0)
	y_padded := Add(y, Delta)
	y_trunc := RshSignExtend(y, decimals)
	y_trunc_2 := RshSignExtend(y_padded, decimals)
	y_rem := ToUint64(y) % (1 << decimals)

	// Output on server 1
	//fmt.Printf("  eval DCF at %d\n", y_rem)
	corrL := dcf.EvalSmallOutput128(truncKey.Dcf, y_rem, uint64(decimals) /* logN */, 0)
	Clear(dst)
	Clear(dstSq)

	if !(y.NearBorder()) {
		dst.AddInPlace(y_trunc)
		dst.SubInPlace(&truncKey.Share)
		dst.SubOneInPlace()
		dstSq.AddInPlace(&corrL)
	} else {
		dst.AddInPlace(y_trunc_2)
		dst.SubInPlace(&truncKey.Share2)
		dst.SubOneInPlace()
		dstSq.AddInPlace(&corrL)
	}
}

func ServerRTruncateRSSToAdditive128Dst(truncKey *TruncKey, s *Share128, dst, dstSq *Uint128, decimals uint) {
	if decimals >= 64 {
		panic("Not yet supported")
	}

	y := &s.Second
	y_rem := ToUint64(y) % (1 << decimals)

	// Output on server 2
	corrR := dcf.EvalSmallOutput128(truncKey.Dcf, y_rem, uint64(decimals) /* logN */, 1)
	Clear(dst)
	Clear(dstSq)

	if !(y.NearBorder()) {
		dst.SubInPlace(&truncKey.Share)
		dstSq.AddInPlace(&corrR)
	} else {
		dst.SubInPlace(&truncKey.Share2)
		dstSq.AddInPlace(&corrR)
	}
}

func truncateRSSToAdditive128(s0, s1, s2 *Share128, decimals uint, reader *BufPRGReader) (*Uint128, *Uint128, *Uint128) {
	z := MakeUint128(0, 0)
	yL := MakeUint128(0, 0)
	zL := MakeUint128(0, 0)
	yR := MakeUint128(0, 0)
	zR := MakeUint128(0, 0)

	keyL, keyR := DealerTruncateRSSToAdditive128(s0, decimals, reader)
	ServerLTruncateRSSToAdditive128Dst(keyL, s1, yL, zL, decimals)
	ServerRTruncateRSSToAdditive128Dst(keyR, s2, yR, zR, decimals)

	AdditiveToRSS128Dst(z, zL, zR, s0, s1, s2, reader) // convert additive --> RSS

	// Square
	MulRSS128Dst(s0, s0, z)
	MulRSS128Dst(s1, s1, zL)
	MulRSS128Dst(s2, s2, zR)

	zL.AddInPlace(yL)
	zR.AddInPlace(yR)

	return z, zL, zR
}

func DealerTruncateAdditive2To3Inplace128(s *Uint128, decimals uint, reader *BufPRGReader) (*TruncKey, *TruncKey) {
	if decimals >= 64 {
		panic("Not yet supported")
	}

	r := s
	r.NegateInPlace()
	Delta := MakeUint128((1 << 63), 0)
	r_padded := Add(r, Delta)
	r_trunc := RshSignExtend(r, decimals)
	r_trunc_2 := RshSignExtend(r_padded, decimals)
	r_rem := ToUint64(r) % (1 << decimals)

	dcfL, dcfR := dcf.GenSmallOutput128(r_rem, uint64(decimals) /* logN */, true /* >= */) // NOTE: FLIPPED!!
	mask_hi, mask_lo := reader.TwoUint64()
	mask_2_hi, mask_2_lo := reader.TwoUint64()

	// Dealer sends to server L: dcfL, mask, mask_2
	messageL := MakeUint128(mask_hi, mask_lo)
	messageL_2 := MakeUint128(mask_2_hi, mask_2_lo)

	// Dealer sends to server R: dcfR, r_trunc-mask, rtrunc_2 - mask2
	messageR := Sub(r_trunc, messageL)
	messageR_2 := Sub(r_trunc_2, messageL_2)

	keyL := TruncKey{
		Dcf:    dcfL,
		Share:  *messageL,
		Share2: *messageL_2,
	}

	keyR := TruncKey{
		Dcf:    dcfR,
		Share:  *messageR,
		Share2: *messageR_2,
	}

	return &keyL, &keyR
}

func ServerLTruncateAdditive2To3Dst128(key *TruncKey, s, dst, dstSq *Uint128, decimals uint) {
	if decimals >= 64 {
		panic("Not yet supported")
	}

	y := s
	Delta := MakeUint128((1 << 63), 0)

	// Computed on servers L and R
	y_padded := Add(y, Delta)
	y_trunc := RshSignExtend(y, decimals)
	y_trunc_2 := RshSignExtend(y_padded, decimals)
	y_rem := ToUint64(y) % (1 << decimals)

	// Output on server L
	corrL := dcf.EvalSmallOutput128(key.Dcf, y_rem, uint64(decimals) /* logN */, 0)
	Clear(dst)
	Clear(dstSq)

	if !(y.NearBorder()) {
		dst.AddInPlace(y_trunc)
		dst.SubInPlace(&key.Share)
		dst.SubOneInPlace()
		dstSq.AddInPlace(&corrL)
	} else {
		dst.AddInPlace(y_trunc_2)
		dst.SubInPlace(&key.Share2)
		dst.SubOneInPlace()
		dstSq.AddInPlace(&corrL)
	}
}

func ServerRTruncateAdditive2To3Dst128(key *TruncKey, s, dst, dstSq *Uint128, decimals uint) {
	if decimals >= 64 {
		panic("Not yet supported")
	}

	y := s
	y_rem := ToUint64(y) % (1 << decimals)

	// Output on server R
	corrR := dcf.EvalSmallOutput128(key.Dcf, y_rem, uint64(decimals) /* logN */, 1)
	Clear(dst)
	Clear(dstSq)

	if !(y.NearBorder()) {
		dst.SubInPlace(&key.Share)
		dstSq.AddInPlace(&corrR)
	} else {
		dst.SubInPlace(&key.Share2)
		dstSq.AddInPlace(&corrR)
	}
}

func truncateAdditive2To3Inplace128(s0, s1, s2 *Uint128, decimals, dealer uint, reader *BufPRGReader) {
	if decimals >= 64 {
		panic("Not yet supported")
	}

	zL := MakeUint128(0, 0)
	zR := MakeUint128(0, 0)

	if dealer == 0 {
		keyL, keyR := DealerTruncateAdditive2To3Inplace128(s0, decimals, reader)
		ServerLTruncateAdditive2To3Dst128(keyL, s1, zL, s1, decimals)
		ServerRTruncateAdditive2To3Dst128(keyR, s2, zR, s2, decimals)

		Clear(s0)

	} else if dealer == 1 {
		keyL, keyR := DealerTruncateAdditive2To3Inplace128(s1, decimals, reader)
		ServerLTruncateAdditive2To3Dst128(keyL, s2, zL, s2, decimals)
		ServerRTruncateAdditive2To3Dst128(keyR, s0, zR, s0, decimals)

		Clear(s1)

	} else if dealer == 2 {
		keyL, keyR := DealerTruncateAdditive2To3Inplace128(s2, decimals, reader)
		ServerLTruncateAdditive2To3Dst128(keyL, s0, zL, s0, decimals)
		ServerRTruncateAdditive2To3Dst128(keyR, s1, zR, s1, decimals)

		Clear(s2)
	}

	t0, t1, t2 := AdditiveToRSS128(s0, s1, s2, reader)

	// Square
	MulRSS128Dst(t0, t0, s0)
	MulRSS128Dst(t1, t1, s1)
	MulRSS128Dst(t2, t2, s2)

	if dealer == 0 {
		s1.AddInPlace(zL)
		s2.AddInPlace(zR)
	} else if dealer == 1 {
		s2.AddInPlace(zL)
		s0.AddInPlace(zR)
	} else if dealer == 2 {
		s0.AddInPlace(zL)
		s1.AddInPlace(zR)
	}
}
