// Adapted from: source file src/net/netip/Uint128.go

package share

// #cgo CFLAGS: -O3 -march=native -msse4.1 -maes -mavx2 -mavx
// #include "uint128.h"
import "C"


import (
	"fmt"
	"encoding/binary"
)

type Uint128 = C.Elem128

func Clear(u *Uint128) {
	C.setToZero(u)
}

func (u *Uint128) Print() {
	var hi, lo C.Elem64
	C.getLimbs(u, &hi, &lo) 
        fmt.Printf("%d %d\n", hi, lo)
}

func MakeUint128(hi, lo uint64) *Uint128 {
	u := new(Uint128)
	C.fromLimbs(u, C.Elem64(hi), C.Elem64(lo))
	return u
}

func MakeUint128C(hi, lo C.Elem64) *Uint128 {
        u := new(Uint128)
	C.fromLimbs(u, hi, lo)
        return u
}

func SetUint128(hi, lo uint64, u *Uint128) {
	C.fromLimbs(u, C.Elem64(hi), C.Elem64(lo))
}

func SetUint128C(hi, lo C.Elem64, u *Uint128) {
	C.fromLimbs(u, hi, lo)
}

func Copy(src, dst *Uint128) {
	*dst = *src
}

// Note: needs to sign-extend, so that addition preserves correct functionality
func ToUint128(val uint64) *Uint128 {
	dst := new(Uint128)
	C.toUint128(C.Elem64(val), dst)
	return dst
}

func ToUint128C(val C.Elem64) *Uint128 {
        dst := new(Uint128)
        C.toUint128(val, dst)
	return dst
}

func ToUint128Dst(val uint64, u *Uint128) {
        C.toUint128(C.Elem64(val), u)
}

func ToUint128DstC(val C.Elem64, u *Uint128) {
        C.toUint128(val, u)
}

func (u *Uint128) NearBorder() bool {
	return bool(C.nearBorder(u))
}

func ToUint128Sub(val, hi_a, lo_a, hi_b, lo_b uint64) *Uint128 {
	dst := new(Uint128)
        C.toUint128Sub(C.Elem64(val), C.Elem64(hi_a), C.Elem64(lo_a), C.Elem64(hi_b), C.Elem64(lo_b), dst)
	return dst
}

func SubTwoHalvesDst(val *Uint128, hi_a, lo_a, hi_b, lo_b uint64, dst *Uint128) {
        C.subTwoHalves(val, C.Elem64(hi_a), C.Elem64(lo_a), C.Elem64(hi_b), C.Elem64(lo_b), dst)
}

func AddTwoHalvesDst(val *Uint128, hi_a, lo_a, hi_b, lo_b uint64, dst *Uint128) {
        C.addTwoHalves(val, C.Elem64(hi_a), C.Elem64(lo_a), C.Elem64(hi_b), C.Elem64(lo_b), dst)
}

func AddSubTwoHalvesDst(val *Uint128, hi_a, lo_a, hi_b, lo_b uint64, dst *Uint128) {
        C.addSubTwoHalves(val, C.Elem64(hi_a), C.Elem64(lo_a), C.Elem64(hi_b), C.Elem64(lo_b), dst)
}

func CheckPositiveUint64(u *Uint128) bool {
	return bool(C.checkPositiveUint64(u))
}

func CheckUint64(u *Uint128) bool {
	return bool(C.checkUint64(u))
}

func ToUint64(u *Uint128) uint64 {
        var hi, lo C.Elem64
        C.getLimbs(u, &hi, &lo)
	return uint64(lo)
}

func ToUint64C(u *Uint128) C.Elem64 {
	var hi, lo C.Elem64
        C.getLimbs(u, &hi, &lo)
        return lo
}

func IsZero(u *Uint128) bool { return bool(C.isZero(u)) }
func IsOne(u *Uint128) bool { return bool(C.isOne(u)) }
func IsNegativeOne(u *Uint128) bool { return bool(C.isNegativeOne(u)) }

// sub returns u-v with wraparound semantics.
func Sub(u, v *Uint128) *Uint128 {
	dst := new(Uint128)
	C.sub(u, v, dst)
	return dst 
}

func (u *Uint128) SubInPlace(v *Uint128) {
	C.sub(u, v, u)
}

func SubDst(u, v, dst *Uint128) {
	C.sub(u, v, dst)
}

func (u *Uint128) SubFromHalves(hi, lo uint64) {
	C.subFromHalves(u, C.Elem64(hi), C.Elem64(lo), u)
}

func SubOne(u *Uint128) *Uint128 {
	dst := new(Uint128)
	C.subOne(u, dst)
	return dst
}

func (u *Uint128) SubOneInPlace() {
        C.subOne(u, u)
}

func AddOne(u *Uint128) *Uint128 {
	dst := new(Uint128)
	C.addOne(u, dst)
	return dst
}

func (u *Uint128) AddOneInPlace() {
	C.addOne(u, u)
}

// add returns u+v with wraparound semantics
func Add(u, v *Uint128) *Uint128 {
	dst := new(Uint128)
	C.add(u, v, dst)
	return dst
}

func (u *Uint128) AddInPlace(v *Uint128) {
	C.add(u, v, u)
}

func AddDst(u, v, dst *Uint128) {
	C.add(u, v, dst)
}

func (u *Uint128) AddFromHalves(hi, lo uint64) {
	C.addFromHalves(u, C.Elem64(hi), C.Elem64(lo), u)
}

// mul returns u*v with wraparound semantics
func Mul(u, v *Uint128) *Uint128 {
	dst := new(Uint128)
	C.mul(u, v, dst)
	return dst
}

func (u *Uint128) MulInPlace(v *Uint128) {
	C.mul(u, v, u)
}

func MulDst(u, v, dst *Uint128) {
	C.mul(u, v, dst)
}

// u += v1*v2
func (u *Uint128) MulAddInPlace(v1, v2 *Uint128) {
	C.mulAddInPlace(u, v1, v2)
}

// u -= v1*v2
func (u *Uint128) MulSubInPlace(v1, v2 *Uint128) {
	C.mulSubInPlace(u, v1, v2)
}

func Mul64(u *Uint128, v uint64) *Uint128 {
        dst := new(Uint128)
        C.mul64(u, (*C.Elem64)(&v), dst)
        return dst
}

func (u *Uint128) Mul64InPlace(v uint64) {
        C.mul64(u, (*C.Elem64)(&v), u)
}

func Mul64Dst(u *Uint128, v uint64, dst *Uint128) {
        C.mul64(u, (*C.Elem64)(&v), dst)
}

func Div64(u *Uint128, v uint64) *Uint128 {
        dst := new(Uint128)
        C.div64(u, (*C.Elem64)(&v), dst)
        return dst
}

func (u *Uint128) Div64InPlace(v uint64) {
        C.div64(u, (*C.Elem64)(&v), u)
}

func Div64Dst(u *Uint128, v uint64, dst *Uint128) {
        C.div64(u, (*C.Elem64)(&v), dst)
}

// mul64 returns u*v with wraparound semantics
func Mul64C(u *Uint128, v C.Elem64) *Uint128 {
	dst := new(Uint128)
	C.mul64(u, &v, dst)
	return dst
}

func (u *Uint128) Mul64InPlaceC(v C.Elem64) {
	C.mul64(u, &v, u)
}

func Mul64DstC(u *Uint128, v C.Elem64, dst *Uint128) {
	C.mul64(u, &v, dst)
}

// div64 returns u/v with wraparound semantics
func Div64C(u *Uint128, v C.Elem64) *Uint128 {
	dst := new(Uint128)
	C.div64(u, &v, dst)
	return dst
}

func (u *Uint128) Div64InPlaceC(v C.Elem64) {
	C.div64(u, &v, u)
}

func Div64DstC(u *Uint128, v C.Elem64, dst *Uint128) {
	C.div64(u, &v, dst)
}

// Equals returns true if u == v.
func (u *Uint128) Equals(v *Uint128) bool {
	return bool(C.equal(u, v))
}

func (u *Uint128) GreaterThan(v *Uint128) bool {
        return bool(C.greaterThan(u, v))
}

// Uses two's completement negation: invert all bits, then add one
func Negate(u *Uint128) *Uint128 {
	dst := new(Uint128)
	C.negate(u, dst)
	return dst
}

// v = ^u
func NegateDst(u, v *Uint128)  {
	C.negate(u, v)
}

func (u *Uint128) NegateInPlace() {
	C.negate(u, u)
}

// Lsh returns u<<n.
func Lsh(u *Uint128, n uint) *Uint128 {
	dst := new(Uint128)
	C.lsh(u, C.Elem64(n), dst)
	return dst
}

func (u *Uint128) LshInPlace(n uint) {
	C.lsh(u, C.Elem64(n), u)
}

// Rsh returns u>>n.
func Rsh(u *Uint128, n uint) *Uint128 {
	dst := new(Uint128)
	C.rsh(u, C.Elem64(n), dst)
	return dst
}

func RshDst(u *Uint128, n uint, dst *Uint128) {
	C.rsh(u, C.Elem64(n), dst)
}

func (u *Uint128) RshInPlace(n uint) {
	C.rsh(u, C.Elem64(n), u)
}

// RshSignExtend returns u>>n with sign extending.
func RshSignExtend(u *Uint128, n uint) *Uint128 {
	dst := new(Uint128)
	C.rshSignExtend(u, C.Elem64(n), dst)
	return dst
}

func (u *Uint128) RshSignExtendInPlace(n uint) {
	C.rshSignExtend(u, C.Elem64(n), u)
}

func RshSignExtendDst(u *Uint128, n uint, dst *Uint128) {
	C.rshSignExtend(u, C.Elem64(n), dst)
}

func TruncateRight(a *Uint128, decimals uint, dst *Uint128) {
        C.truncateRight(a, C.Elem64(decimals), dst)
}

func BytesToUint128(bytes []byte) *Uint128 {
	if len(bytes) != 16 {
		panic("BytesToUint128: input array does not have length 16")
	}

	hi := binary.LittleEndian.Uint64(bytes[:8])
	lo := binary.LittleEndian.Uint64(bytes[8:16])
	return MakeUint128(hi, lo)
}

func BytesToUint128Dst(bytes []byte, dst *Uint128) {
        if len(bytes) != 16 {
                panic("BytesToUint128: input array does not have length 16")
        }

        hi := binary.LittleEndian.Uint64(bytes[:8])
        lo := binary.LittleEndian.Uint64(bytes[8:16])
	C.fromLimbs(dst, C.Elem64(hi), C.Elem64(lo))
}

func Uint128ToBytes(u *Uint128) []byte {
	b := make([]byte, 16)
	Uint128ToBytesDst(u, b)
	return b
}

func Uint128ToBytesDst(u *Uint128, b []byte) {
        var hi, lo C.Elem64
        C.getLimbs(u, &hi, &lo)

        binary.LittleEndian.PutUint64(b[:8], uint64(hi))
        binary.LittleEndian.PutUint64(b[8:16], uint64(lo))
}

func Uint128ToLimbs(u *Uint128) (uint64, uint64) {
        var hi, lo C.Elem64
        C.getLimbs(u, &hi, &lo)
	return uint64(hi), uint64(lo)
}

func LowestOrderBits(u *Uint128, nBits uint) uint64 {
	if nBits >= 64 {
		panic("Not supported")
	}

	C.lowestOrderBits(u, C.Elem64(nBits))

	return ToUint64(u)
}
