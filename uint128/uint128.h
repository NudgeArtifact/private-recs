#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// NOTE: Requires a compiler that supports unsigned __int128

typedef uint64_t Elem64;
typedef unsigned __int128 Elem128;

void getLimbs(const Elem128* big, Elem64 *hi, Elem64 *lo);
void fromLimbs(Elem128* big, Elem64 hi, Elem64 lo);
void toUint128(Elem64 val, Elem128* dst);

void setToZero(Elem128* big);
bool isZero(const Elem128* big);
bool isOne(const Elem128* big);
bool isNegativeOne(const Elem128* big);
bool equal(const Elem128* a, const Elem128* b);
bool greaterThan(const Elem128* a, const Elem128* b);
bool nearBorder(const Elem128* big);

void add(const Elem128* a, const Elem128* b, Elem128* dst);
void addOne(const Elem128* a, Elem128* dst);
void addFromHalves(const Elem128* a, Elem64 hi, Elem64 lo, Elem128* dst);
void sub(const Elem128* a, const Elem128* b, Elem128* dst);
void subOne(const Elem128* a, Elem128* dst);
void subFromHalves(const Elem128* a, Elem64 hi, Elem64 lo, Elem128* dst);
void mul(const Elem128* a, const Elem128* b, Elem128* dst);
void mul64(const Elem128* a, const Elem64* b, Elem128* dst);
void div(const Elem128* a, const Elem128* b, Elem128* dst);
void div64(const Elem128* a, const Elem64* b, Elem128* dst);

void mulAddInPlace(Elem128* src, const Elem128* a, const Elem128* b);
void mulSubInPlace(Elem128* src, const Elem128* a, const Elem128* b);

void lowestOrderBits(Elem128* big, Elem64 n_bits);
void negate(const Elem128* src, Elem128* dst);
void lsh(const Elem128* src, Elem64 n, Elem128* dst);
void rsh(const Elem128* src, Elem64 n, Elem128* dst);
void rshSignExtend(const Elem128* src, Elem64 n, Elem128* dst);
void truncateRight(const Elem128* src, Elem64 n, Elem128* dst);

bool checkPositiveUint64(const Elem128* big);
bool checkUint64(const Elem128* big);

void toUint128Sub(Elem64 v, Elem64 hiA, Elem64 loA, Elem64 hiB, Elem64 loB, Elem128* dst);
void subTwoHalves(const Elem128* val, Elem64 hi_a, Elem64 lo_a, Elem64 hi_b, Elem64 lo_b, Elem128* dst);
void addTwoHalves(const Elem128* val, Elem64 hi_a, Elem64 lo_a, Elem64 hi_b, Elem64 lo_b, Elem128* dst);
void addSubTwoHalves(const Elem128* val, Elem64 hi_a, Elem64 lo_a, Elem64 hi_b, Elem64 lo_b, Elem128* dst);
