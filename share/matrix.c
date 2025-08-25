#include "matrix.h"
#include <stdio.h>
#include <assert.h>

// NOTE: This requires guessing the memory layout. May change on other systems.

void matSub(Elem64 *a, const Elem64 *b, uint64_t rows, uint64_t cols) {
    for (uint64_t i = 0; i < rows; i++) {
        for (uint64_t j = 0; j < cols; j++) {
            a[cols*i+j] -= b[cols*i+j];
        }
    }
}


void matSubRSS(Elem128 *a, const Elem128 *b, uint64_t rows, uint64_t cols) {
    cols *= 2;

    for (uint64_t i = 0; i < rows; i++) {
        for (uint64_t j = 0; j < cols; j++) {
            a[cols*i+j] -= b[cols*i+j];
	}
    }
}

// a, b, c are each an array of Uint128
void matMul(const Elem128 *a, const Elem128 *b, Elem128 *out, uint64_t aRows, uint64_t aCols, uint64_t bCols) {
    Elem128 interm = 0;

    for (uint64_t i = 0; i < aRows; i++) {
        for (uint64_t k = 0; k < aCols; k++) {
            for (uint64_t j = 0; j < bCols; j++) {
                out[bCols*i + j] += a[aCols*i + k] * b[bCols*k + j];     
            }
        }
    }
}

void matMulMixed(const Elem64 *a, const Elem128 *b, Elem128 *out, uint64_t aRows, uint64_t aCols, uint64_t bCols) {
    Elem128 interm = 0;

    for (uint64_t i = 0; i < aRows; i++) {
        for (uint64_t k = 0; k < aCols; k++) {
	    interm = (unsigned __int128)((__int128) ((int64_t) a[aCols*i + k]));
            for (uint64_t j = 0; j < bCols; j++) {
                out[bCols*i + j] += interm * b[bCols*k + j];
            }
        }
    }
}

// a and b are each array of share128: each "share" consists of 2 Elem128
// c is an array of Uint128
void matMulRSS(const Elem128 *a, const Elem128 *b, Elem128 *out, uint64_t aRows, uint64_t aCols, uint64_t bCols) {
    Elem128 interm0, interm1, interm2, interm3, interm4;

    for (uint64_t j = 0; j < bCols; j++) { 
        for (uint64_t i = 0; i < aRows; i += 4) {
	    interm0 = 0;
	    interm1 = 0;
	    interm2 = 0;
	    interm3 = 0;

            for (uint64_t k = 0; k < aCols; k++) {
		interm0 += a[2*aCols*i + 2*k] * b[2*bCols*k + 2*j];      // equiv to: a[aCols*i + k].first * b[bCols*k + j].first
		interm0 += a[2*aCols*i + 2*k + 1] * b[2*bCols*k + 2*j]; // equiv to: a[aCols*i + k].second * b[bCols*k + j].first
		interm0 += a[2*aCols*i + 2*k] * b[2*bCols*k + 2*j + 1]; // equiv to: a[aCols*i + k].first * b[bCols*k + j].second
                
		interm1 += a[2*aCols*(i+1) + 2*k] * b[2*bCols*k + 2*j];      // equiv to: a[aCols*i + k].first * b[bCols*k + j].first
                interm1 += a[2*aCols*(i+1) + 2*k + 1] * b[2*bCols*k + 2*j]; // equiv to: a[aCols*i + k].second * b[bCols*k + j].first
                interm1 += a[2*aCols*(i+1) + 2*k] * b[2*bCols*k + 2*j + 1]; // equiv to: a[aCols*i + k].first * b[bCols*k + j].second

                interm2 += a[2*aCols*(i+2) + 2*k] * b[2*bCols*k + 2*j];      // equiv to: a[aCols*i + k].first * b[bCols*k + j].first
                interm2 += a[2*aCols*(i+2) + 2*k + 1] * b[2*bCols*k + 2*j]; // equiv to: a[aCols*i + k].second * b[bCols*k + j].first
                interm2 += a[2*aCols*(i+2) + 2*k] * b[2*bCols*k + 2*j + 1]; // equiv to: a[aCols*i + k].first * b[bCols*k + j].second

                interm3 += a[2*aCols*(i+3) + 2*k] * b[2*bCols*k + 2*j];      // equiv to: a[aCols*i + k].first * b[bCols*k + j].first
                interm3 += a[2*aCols*(i+3) + 2*k + 1] * b[2*bCols*k + 2*j]; // equiv to: a[aCols*i + k].second * b[bCols*k + j].first
                interm3 += a[2*aCols*(i+3) + 2*k] * b[2*bCols*k + 2*j + 1]; // equiv to: a[aCols*i + k].first * b[bCols*k + j].second
            }

	    out[bCols*i + j] += interm0;
	    if (i + 1 >= aRows) break;
	    out[bCols*(i+1) + j] += interm1;
	    if (i + 2 >= aRows) break;
	    out[bCols*(i+2) + j] += interm2;
	    if (i + 3 >= aRows) break;
	    out[bCols*(i+3) + j] += interm3;
        }
    }
}

// a and b are each array of share128: each "share" consists of 2 Elem128
// c is an array of Uint128
void matEntrywiseMulRSS(const Elem128 *a, const Elem128 *b, Elem128 *out, uint64_t aRows, uint64_t aCols) {
    for (uint64_t i = 0; i < aRows; i++) {
        for (uint64_t j = 0; j < aCols; j++) { 
            out[aCols*i + j]  = a[2*aCols*i + 2*j    ] * b[2*aCols*i + 2*j];
	    out[aCols*i + j] += a[2*aCols*i + 2*j + 1] * b[2*aCols*i + 2*j]; 
            out[aCols*i + j] += a[2*aCols*i + 2*j    ] * b[2*aCols*i + 2*j + 1];
        }
    }
}

void matMulRSSPtxt(const Elem128 *a, const Elem64 *b, Elem128 *out, uint64_t aRows, uint64_t aCols, uint64_t bCols) {
    Elem128 interm;
    Elem128 tmp0A, tmp0B, tmp1A, tmp1B, tmp2A, tmp2B, tmp3A, tmp3B;

    for (uint64_t j = 0; j < bCols; j++) { 
       for (uint64_t i = 0; i < aRows; i += 4) { 
	    tmp0A = 0;
            tmp0B = 0;
            tmp1A = 0;
            tmp1B = 0;
            tmp2A = 0;
            tmp2B = 0;
            tmp3A = 0;
            tmp3B = 0;

            for (uint64_t k = 0; k < aCols; k++) {
		interm = (unsigned __int128)((__int128) ((int64_t) b[k*bCols+j]));
		
		tmp0A += interm * a[2*aCols*i + 2*k];
		tmp0B += interm * a[2*aCols*i + 2*k + 1];

		tmp1A += interm * a[2*aCols*(i+1) + 2*k];
                tmp1B += interm * a[2*aCols*(i+1) + 2*k + 1];

		tmp2A += interm * a[2*aCols*(i+2) + 2*k];
                tmp2B += interm * a[2*aCols*(i+2) + 2*k + 1];

		tmp3A += interm * a[2*aCols*(i+3) + 2*k];
                tmp3B += interm * a[2*aCols*(i+3) + 2*k + 1];
            }

	    out[2*bCols*i + 2*j] += tmp0A;
	    out[2*bCols*i + 2*j + 1] += tmp0B;

	    if (i + 1 >= aRows) break;
            out[2*bCols*(i+1) + 2*j] += tmp1A;
            out[2*bCols*(i+1) + 2*j + 1] += tmp1B;

	    if (i + 2 >= aRows) break;
            out[2*bCols*(i+2) + 2*j] += tmp2A;
            out[2*bCols*(i+2) + 2*j + 1] += tmp2B;

	    if (i + 3 >= aRows) break;
            out[2*bCols*(i+3) + 2*j] += tmp3A;
            out[2*bCols*(i+3) + 2*j + 1] += tmp3B;
        }
    }
}

void scalarMulPtxtRSS(const Elem64 val, const Elem128 *restrict b, Elem128 *restrict out, uint64_t bRange) {
    uint64_t bStride = 2 * bRange;

    Elem128 interm = (unsigned __int128)((__int128) ((int64_t) val));
    
    for (uint64_t j = 0; j < bStride; j += 2) {
       out[j] += interm * b[j];
       out[j + 1] += interm * b[j + 1];
    }
}

void matMulPtxtRSS(const Elem64 *restrict a, const Elem128 *restrict b, Elem128 *restrict out, 
		   uint64_t aRows, uint64_t aCols, uint64_t bCols) {

    Elem128 interm0, interm1, interm2, interm3, interm4, interm5, interm6, interm7;
    uint64_t bStride = 2 * bCols;
    uint64_t at0 = 0;
    uint64_t at1 = 0;
    uint64_t offset = 0;

    uint64_t i = 0;
    for (uint64_t i = 0; i < aRows; i += 1) {
        for (uint64_t k = 0; k < aCols; k += 1) {
            interm0 = (unsigned __int128)((__int128) ((int64_t) a[aCols*i + k + 0]));

	    if (interm0 == 0) {
	        continue;
	    }

	    at0 = bStride*k;
	    uint64_t j = 0;

            for ( ; j + 7 < bStride; j += 8) {
                out[offset + j + 0] += interm0 * b[at0];
                out[offset + j + 1] += interm0 * b[at0 + 1];
                out[offset + j + 2] += interm0 * b[at0 + 2];
                out[offset + j + 3] += interm0 * b[at0 + 3];
                out[offset + j + 4] += interm0 * b[at0 + 4];
                out[offset + j + 5] += interm0 * b[at0 + 5];
                out[offset + j + 6] += interm0 * b[at0 + 6];
                out[offset + j + 7] += interm0 * b[at0 + 7];

		at0 += 8;
            }

	    for ( ; j < bStride; j += 2) {
                out[offset + j + 0] += interm0 * b[at0];
                out[offset + j + 1] += interm0 * b[at0 + 1];

                at0 += 2;
            }
        }
	offset += bStride;
    }
}

void matTransposeMul(const Elem128 *a, const Elem128 *b, Elem128 *out, uint64_t aRows, uint64_t aCols, uint64_t bCols, uint64_t aOffset, uint64_t aStretch) {
    __int128 interm = 0; // is signed

    for (uint64_t i = aOffset; i < aOffset + aStretch; i++) {
        for (uint64_t k = 0; k < aRows; k++) {
            for (uint64_t j = 0; j < bCols; j++) {
                interm = ((__int128) a[aCols*k + i]) * ((__int128) b[bCols*k + j]); 
                out[bCols*i + j] = (Elem128)(((__int128)out[bCols*i + j]) + interm);
            }
        }
    }
}

void matTransposeMulRSS(const Elem128 *a, const Elem128 *b, Elem128 *out, uint64_t aRows, uint64_t aCols, uint64_t bCols, uint64_t aOffset, uint64_t aStretch) {
    Elem128 interm = 0;

    for (uint64_t i = aOffset; i < aOffset + aStretch; i++) {
        for (uint64_t k = 0; k < aRows; k++) {
	    for (uint64_t j = 0; j < bCols; j++) {
	        interm = a[2*aCols*k + 2*i] * b[2*bCols*k + 2*j];      // equiv to: a[aCols*i + k].first * b[bCols*k + j].first
                interm += a[2*aCols*k + 2*i + 1] * b[2*bCols*k + 2*j]; // equiv to: a[aCols*i + k].second * b[bCols*k + j].first
                interm += a[2*aCols*k + 2*i] * b[2*bCols*k + 2*j + 1]; // equiv to: a[aCols*i + k].first * b[bCols*k + j].second
                out[bCols*i + j] += interm;
            }
        }
    }
}

void matTransposeMulPtxtRSS(const Elem64 *a, const Elem128 *b, Elem128 *out, uint64_t aRows, uint64_t aCols, uint64_t bCols, uint64_t aOffset, uint64_t aStretch) {
    Elem128 interm = 0;
    bCols *= 2;

    for (uint64_t i = aOffset; i < aOffset + aStretch; i++) {
        for (uint64_t j = 0; j < bCols; j++) { 
	    out[bCols*i + j] = 0;

            for (uint64_t k = 0; k < aRows; k++) { 
		// cast to signed to get sign extension right
		interm = (unsigned __int128)((__int128) ((int64_t) a[aCols*k + i]));
		out[bCols*i + j] += interm * b[bCols*k + j];
            }
        }
    }
}

void matMulSubRSSAt(const Elem128 *a, const Elem64 *b, Elem128 *out, uint64_t aRows, uint64_t aCols, uint64_t bCols, uint64_t outCols) {
    Elem128 interm = 0;

    for (uint64_t i = 0; i < aRows; i++) {
        for (uint64_t j = 0; j < outCols; j++) {
            for (uint64_t k = 0; k < aCols; k++) {
		interm = (unsigned __int128)((__int128) ((int64_t) b[k*bCols+j]));
		out[2*i*outCols + 2*j] -= a[2*i*aCols + 2*k] * interm;
		out[2*i*outCols + 2*j + 1] -= a[2*i*aCols + 2*k + 1] * interm;
            }
        }
    }
}

void mulByConstantInPlace(Elem128* a, uint64_t cons, uint64_t aRows, uint64_t aCols) {
    Elem128 mulBy = (unsigned __int128)((__int128) ((int64_t) cons));
    for (uint64_t i = 0; i < aRows; i++) {
        for (uint64_t j = 0; j < aCols; j++) {
            a[aCols*i + j] *= mulBy;
        }
    }
}

void divByConstantInPlace(Elem128* a, uint64_t cons, uint64_t aRows, uint64_t aCols) {
    Elem128 mulBy = (unsigned __int128)((__int128) ((int64_t) cons));
    __int128 tmp = 0; // is signed

    for (uint64_t i = 0; i < aRows; i++) {
        for (uint64_t j = 0; j < aCols; j++) {
	    tmp = (__int128) a[aCols*i + j];
            a[aCols*i + j] = (Elem128)(tmp / cons); 
        }
    }
}

// a is a matrix of RSS shares
void mulByConstantInPlaceRSS(Elem128* a, uint64_t cons, uint64_t aRows, uint64_t aCols) {
    Elem128 mulBy = (unsigned __int128)((__int128) ((int64_t) cons)); 
    for (uint64_t i = 0; i < aRows; i++) {
        for (uint64_t j = 0; j < 2*aCols; j++) {
            a[2*aCols*i + j] *= mulBy;
        }
    }
}

void selectBit(Elem64* src, Elem64* dst, uint64_t bit, uint64_t rows, uint64_t cols) {
    for (uint64_t i = 0; i < rows; i++) {
        for (uint64_t j = 0; j < cols; j++) {
            dst[cols*i + j] = (src[cols*i + j] >> bit) & 1;
        }
    }
}

void matRshSigned(const Elem128* src, Elem128* dst, uint64_t rows, uint64_t cols, uint64_t digits) {
    for (uint64_t i = 0; i < rows; i++) {
        for (uint64_t j = 0; j < cols; j++) {
            dst[cols*i + j] = (unsigned __int128)(((__int128)src[cols*i + j]) >> digits);
        }
    }
}
