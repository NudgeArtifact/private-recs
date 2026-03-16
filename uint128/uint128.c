#include "uint128.h"
#include <stdio.h>

#define MAX_64 (~(Elem64) 0)
#define MAX_128 (~(Elem128) 0)

#define MAX_POS64 ((1ULL << 63) - 1)
#define MAX_NEG64 MAX_128 - MAX_POS64
#define CLEAR_TOP_BIT MAX_POS64

#define LOWER_BORDER (((Elem128) 1) << 126)
#define UPPER_BORDER (Elem128)(-((__int128)1 << 126))

void getLimbs(const Elem128* big, Elem64 *hi, Elem64 *lo) {
	*hi = (Elem64) ((*big) >> 64);
	*lo = (Elem64) ((*big) & MAX_64);
}

void fromLimbs(Elem128 *big, Elem64 hi, Elem64 lo) {
	*big = (((Elem128) hi) << 64) | lo;
}

// Cast to signed first to get sign extension right
void toUint128(Elem64 val, Elem128* dst) {
	*dst = (unsigned __int128)((__int128) ((int64_t) val));
}

bool isZero(const Elem128* big) {
	return *big == 0;
}

bool isOne(const Elem128* big) {
	return *big == 1;
}

bool isNegativeOne(const Elem128* big) {
        return *big == -1;
}

bool equal(const Elem128* a, const Elem128* b) {
	return *a == *b;
}

bool greaterThan(const Elem128* a, const Elem128* b) {
        return (*a) > (*b);
}

void setToZero(Elem128* big) {
	*big = 0;
}

bool nearBorder(const Elem128* big) {
	return ((*big <= LOWER_BORDER) || (*big >= UPPER_BORDER));
}

void add(const Elem128* a, const Elem128* b, Elem128* dst) {
	*dst = (*a) + (*b);
}

void sub(const Elem128* a, const Elem128* b, Elem128* dst) {
	*dst = (*a) - (*b);
}

void mul(const Elem128* a, const Elem128* b, Elem128* dst) {
	*dst = (*a) * (*b);
}

void mul64(const Elem128* a, const Elem64* b, Elem128* dst) {
        *dst = (*a) * (*b);
}

void addOne(const Elem128* a, Elem128* dst) {
	*dst = (*a) + 1;
}

void subOne(const Elem128* a, Elem128* dst) {
	*dst = (*a) - 1;
}

void addTwoHalves(const Elem128* val, Elem64 hi_a, Elem64 lo_a, Elem64 hi_b, Elem64 lo_b, Elem128* dst) {
	*dst = (*val) + (((Elem128) hi_a) << 64) + ((Elem128) lo_a) + (((Elem128) hi_b) << 64) + ((Elem128) lo_b);
}

void subTwoHalves(const Elem128* val, Elem64 hi_a, Elem64 lo_a, Elem64 hi_b, Elem64 lo_b, Elem128* dst) {
        *dst = (*val) - (((Elem128) hi_a) << 64) - ((Elem128) lo_a) - (((Elem128) hi_b) << 64) - ((Elem128) lo_b);
}

void addSubTwoHalves(const Elem128* val, Elem64 hi_a, Elem64 lo_a, Elem64 hi_b, Elem64 lo_b, Elem128* dst) {
        *dst = (*val) + (((Elem128) hi_a) << 64) + ((Elem128) lo_a) - (((Elem128) hi_b) << 64) - ((Elem128) lo_b);
}

void mulAddInPlace(Elem128* src, const Elem128* a, const Elem128* b) {
	*src += (*a) * (*b);
}

void negate(const Elem128* src, Elem128* dst) {
	*dst = ~(*src) + 1;
}

void lsh(const Elem128* src, Elem64 n, Elem128* dst) {
	*dst = ((*src) << n);
}

void rsh(const Elem128* src, Elem64 n, Elem128* dst) {
	*dst = ((*src) >> n);
}

void rshSignExtend(const Elem128* src, Elem64 n, Elem128* dst) {
	*dst = (Elem128)(((__int128) *src) >> n);
}

bool checkPositiveUint64(const Elem128* big) {
	return *big <= MAX_POS64;
}

bool checkUint64(const Elem128* big) {
	return (*big <= MAX_POS64) | (*big >= MAX_NEG64);
}

void toUint128Sub(Elem64 v, Elem64 hiA, Elem64 loA, Elem64 hiB, Elem64 loB, Elem128* dst) {
	*dst = (unsigned __int128)((__int128) ((int64_t) v));
	*dst -= (((Elem128) hiA) << 64) + (((Elem128) hiB) << 64) + loA + loB;
}
