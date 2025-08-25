#include <stdint.h>
#include <stddef.h>
#include "uint128.h"

void matSub(Elem64 *a, const Elem64 *b, uint64_t rows, uint64_t cols);
void matSubRSS(Elem128 *a, const Elem128 *b, uint64_t rows, uint64_t cols);

void matMul(const Elem128 *a, const Elem128 *b, Elem128 *out, uint64_t aRows, uint64_t aCols, uint64_t bCols);
void matMulMixed(const Elem64 *a, const Elem128 *b, Elem128 *out, uint64_t aRows, uint64_t aCols, uint64_t bCols);
void matMulRSS(const Elem128 *a, const Elem128 *b, Elem128 *out, uint64_t aRows, uint64_t aCols, uint64_t bCols);
void matEntrywiseMulRSS(const Elem128 *a, const Elem128 *b, Elem128 *out, uint64_t aRows, uint64_t aCols);
void matMulRSSPtxt(const Elem128 *a, const Elem64 *b, Elem128 *out, uint64_t aRows, uint64_t aCols, uint64_t bCols);
void scalarMulPtxtRSS(const Elem64 val, const Elem128 *b, Elem128 *out, uint64_t bRange);
void matMulPtxtRSS(const Elem64 *a, const Elem128 *b, Elem128 *out, uint64_t aRows, uint64_t aCols, uint64_t bCols);
void matTransposeMul(const Elem128 *a, const Elem128 *b, Elem128 *out, uint64_t aRows, uint64_t aCols, uint64_t bCols, uint64_t aOffset, uint64_t aStretch);
void matTransposeMulRSS(const Elem128 *a, const Elem128 *b, Elem128 *out, uint64_t aRows, uint64_t aCols, uint64_t bCols, uint64_t aOffset, uint64_t aStretch);
void matTransposeMulPtxtRSS(const Elem64 *a, const Elem128 *b, Elem128 *out, uint64_t aRows, uint64_t aCols, uint64_t bCols, uint64_t aOffset, uint64_t aStretch);
void matMulSubRSSAt(const Elem128 *a, const Elem64 *b, Elem128 *out, uint64_t aRows, uint64_t aCols, uint64_t bCols, uint64_t outCols);

void mulByConstantInPlace(Elem128* a, uint64_t cons, uint64_t aRows, uint64_t aCols);
void divByConstantInPlace(Elem128* a, uint64_t cons, uint64_t aRows, uint64_t aCols);
void mulByConstantInPlaceRSS(Elem128* a, uint64_t cons, uint64_t aRows, uint64_t aCols);
void selectBit(Elem64* src, Elem64* dst, uint64_t bit, uint64_t rows, uint64_t cols);
void matRshSigned(const Elem128* src, Elem128* dst, uint64_t rows, uint64_t cols, uint64_t digits);
