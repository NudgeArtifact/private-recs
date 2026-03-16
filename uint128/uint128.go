// Adapted from: source file src/net/netip/Uint128.go

package share

// #cgo CFLAGS: -O3 -march=native -msse4.1 -maes -mavx2 -mavx
// #include "uint128.h"
import "C"

import (
	"encoding/binary"
	"fmt"
	"unsafe"
)

type Uint128 C.Elem128

// e casts *Uint128 to *C.Elem128 for passing to C functions.
func e(u *Uint128) *C.Elem128 {
	return (*C.Elem128)(unsafe.Pointer(u))
}

func Clear(u *Uint128) {
	C.setToZero(e(u))
}

func (u *Uint128) Print() {
	var hi, lo C.Elem64
	C.getLimbs(e(u), &hi, &lo)
	fmt.Printf("%d %d\n", hi, lo)
}

func MakeUint128(hi, lo uint64) *Uint128 {
	u := new(Uint128)
	C.fromLimbs(e(u), C.Elem64(hi), C.Elem64(lo))
	return u
}

func SetUint128(hi, lo uint64, u *Uint128) {
	C.fromLimbs(e(u), C.Elem64(hi), C.Elem64(lo))
}

func Copy(src, dst *Uint128) {
	*dst = *src
}

// Note: needs to sign-extend, so that addition preserves correct functionality
func ToUint128(val uint64) *Uint128 {
	dst := new(Uint128)
	C.toUint128(C.Elem64(val), e(dst))
	return dst
}

func ToUint128Dst(val uint64, u *Uint128) {
	C.toUint128(C.Elem64(val), e(u))
}

func (u *Uint128) NearBorder() bool {
	return bool(C.nearBorder(e(u)))
}

func ToUint128Sub(val, hi_a, lo_a, hi_b, lo_b uint64) *Uint128 {
	dst := new(Uint128)
	C.toUint128Sub(C.Elem64(val), C.Elem64(hi_a), C.Elem64(lo_a), C.Elem64(hi_b), C.Elem64(lo_b), e(dst))
	return dst
}

func SubTwoHalvesDst(val *Uint128, hi_a, lo_a, hi_b, lo_b uint64, dst *Uint128) {
	C.subTwoHalves(e(val), C.Elem64(hi_a), C.Elem64(lo_a), C.Elem64(hi_b), C.Elem64(lo_b), e(dst))
}

func AddTwoHalvesDst(val *Uint128, hi_a, lo_a, hi_b, lo_b uint64, dst *Uint128) {
	C.addTwoHalves(e(val), C.Elem64(hi_a), C.Elem64(lo_a), C.Elem64(hi_b), C.Elem64(lo_b), e(dst))
}

func AddSubTwoHalvesDst(val *Uint128, hi_a, lo_a, hi_b, lo_b uint64, dst *Uint128) {
	C.addSubTwoHalves(e(val), C.Elem64(hi_a), C.Elem64(lo_a), C.Elem64(hi_b), C.Elem64(lo_b), e(dst))
}

func CheckPositiveUint64(u *Uint128) bool {
	return bool(C.checkPositiveUint64(e(u)))
}

func CheckUint64(u *Uint128) bool {
	return bool(C.checkUint64(e(u)))
}

func ToUint64(u *Uint128) uint64 {
	var hi, lo C.Elem64
	C.getLimbs(e(u), &hi, &lo)
	return uint64(lo)
}

func IsZero(u *Uint128) bool        { return bool(C.isZero(e(u))) }
func IsOne(u *Uint128) bool         { return bool(C.isOne(e(u))) }
func IsNegativeOne(u *Uint128) bool { return bool(C.isNegativeOne(e(u))) }

// sub returns u-v with wraparound semantics.
func Sub(u, v *Uint128) *Uint128 {
	dst := new(Uint128)
	C.sub(e(u), e(v), e(dst))
	return dst
}

func (u *Uint128) SubInPlace(v *Uint128) {
	C.sub(e(u), e(v), e(u))
}

func SubDst(u, v, dst *Uint128) {
	C.sub(e(u), e(v), e(dst))
}

func SubOne(u *Uint128) *Uint128 {
	dst := new(Uint128)
	C.subOne(e(u), e(dst))
	return dst
}

func (u *Uint128) SubOneInPlace() {
	C.subOne(e(u), e(u))
}

func AddOne(u *Uint128) *Uint128 {
	dst := new(Uint128)
	C.addOne(e(u), e(dst))
	return dst
}

func (u *Uint128) AddOneInPlace() {
	C.addOne(e(u), e(u))
}

// add returns u+v with wraparound semantics
func Add(u, v *Uint128) *Uint128 {
	dst := new(Uint128)
	C.add(e(u), e(v), e(dst))
	return dst
}

func (u *Uint128) AddInPlace(v *Uint128) {
	C.add(e(u), e(v), e(u))
}

func AddDst(u, v, dst *Uint128) {
	C.add(e(u), e(v), e(dst))
}

// mul returns u*v with wraparound semantics
func Mul(u, v *Uint128) *Uint128 {
	dst := new(Uint128)
	C.mul(e(u), e(v), e(dst))
	return dst
}

func (u *Uint128) MulInPlace(v *Uint128) {
	C.mul(e(u), e(v), e(u))
}

func MulDst(u, v, dst *Uint128) {
	C.mul(e(u), e(v), e(dst))
}

// u += v1*v2
func (u *Uint128) MulAddInPlace(v1, v2 *Uint128) {
	C.mulAddInPlace(e(u), e(v1), e(v2))
}

func Mul64(u *Uint128, v uint64) *Uint128 {
	dst := new(Uint128)
	C.mul64(e(u), (*C.Elem64)(&v), e(dst))
	return dst
}

func Mul64Dst(u *Uint128, v uint64, dst *Uint128) {
	C.mul64(e(u), (*C.Elem64)(&v), e(dst))
}

// Equals returns true if u == v.
func (u *Uint128) Equals(v *Uint128) bool {
	return bool(C.equal(e(u), e(v)))
}

func (u *Uint128) GreaterThan(v *Uint128) bool {
	return bool(C.greaterThan(e(u), e(v)))
}

// v = ^u
func NegateDst(u, v *Uint128) {
	C.negate(e(u), e(v))
}

func (u *Uint128) NegateInPlace() {
	C.negate(e(u), e(u))
}

func (u *Uint128) LshInPlace(n uint) {
	C.lsh(e(u), C.Elem64(n), e(u))
}

func (u *Uint128) RshInPlace(n uint) {
	C.rsh(e(u), C.Elem64(n), e(u))
}

// RshSignExtend returns u>>n with sign extending.
func RshSignExtend(u *Uint128, n uint) *Uint128 {
	dst := new(Uint128)
	C.rshSignExtend(e(u), C.Elem64(n), e(dst))
	return dst
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
	C.fromLimbs(e(dst), C.Elem64(hi), C.Elem64(lo))
}

func Uint128ToBytes(u *Uint128) []byte {
	b := make([]byte, 16)
	Uint128ToBytesDst(u, b)
	return b
}

func Uint128ToBytesDst(u *Uint128, b []byte) {
	var hi, lo C.Elem64
	C.getLimbs(e(u), &hi, &lo)

	binary.LittleEndian.PutUint64(b[:8], uint64(hi))
	binary.LittleEndian.PutUint64(b[8:16], uint64(lo))
}

func Uint128ToLimbs(u *Uint128) (uint64, uint64) {
	var hi, lo C.Elem64
	C.getLimbs(e(u), &hi, &lo)
	return uint64(hi), uint64(lo)
}
