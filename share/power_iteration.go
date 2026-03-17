package share

import (
	"fmt"
	"math"
	"time"

	. "github.com/NudgeArtifact/private-recs/params"
	. "github.com/NudgeArtifact/private-recs/rand"
	. "github.com/NudgeArtifact/private-recs/uint128"
)

// Implements power iteration to find the rank-k approximation to a matrix

// Input: 3 matrices of RSS shares of dimensions m-by-n. Let U be the shared matrix.
// Output: rank-k approximation to the matrix, consisting of:
// (1) 3 additive shares of a matrix A of dimensions m-by-k (the user vectors).
// (2) a plaintext matrix B of dimensions k-by-n (the item vectors).
// The matrices satisfy that A*B \approx U.

func PowerIteration(U0, U1, U2 *Matrix[Share128], params *PowerItParams, pool *PrgPool, shift_up bool) (*Matrix[uint64], bool, *PerfLog) {
	if !(U1.NRows() == U0.NRows() && U1.NCols() == U0.NCols() && U2.NRows() == U0.NRows() && U2.NCols() == U0.NCols()) {
		panic("PowerIteration: Input matrices do not have same dimensions.")
	}

	fmt.Printf("Starting secret-shared power iteration: %d components, %d iters, %d decimal bits of precision\n",
		params.K, params.N_iters, params.N_decimals)
	perf := new(PerfLog)
	transposed := false

	pad := uint64(1 << params.N_decimals)
	if shift_up {
		MulByConstantInPlaceRSS128(U0, pad)
		MulByConstantInPlaceRSS128(U1, pad)
		MulByConstantInPlaceRSS128(U2, pad)
	}
	fmt.Println("Multiplied by constants in place")

	// Initialize right singular vectors
	B := MatrixZeros[uint64](uint64(params.K), U0.NCols())

	// Trigger memory allocations once upfront, then not anymore throughout
	v0 := MatrixZeros[Share128](U0.NCols(), 1)
	v1 := MatrixZeros[Share128](U0.NCols(), 1)
	v2 := MatrixZeros[Share128](U0.NCols(), 1)

	v0_add := MatrixZeros[Uint128](U0.NCols(), 1)
	v1_add := MatrixZeros[Uint128](U0.NCols(), 1)
	v2_add := MatrixZeros[Uint128](U0.NCols(), 1)
	v := MatrixZeros[uint64](U0.NCols(), 1)

	u0 := MatrixZeros[Share128](U0.NRows(), 1)
	u1 := MatrixZeros[Share128](U0.NRows(), 1)
	u2 := MatrixZeros[Share128](U0.NRows(), 1)

	u0_add := MatrixZeros[Uint128](U0.NRows(), 1)
	u1_add := MatrixZeros[Uint128](U0.NRows(), 1)
	u2_add := MatrixZeros[Uint128](U0.NRows(), 1)

	v_init := MatrixZeros[Uint128](U0.NCols(), 1)
	v_init_sm := MatrixZeros[uint64](U0.NCols(), 1)
	sub := MatrixZeros[uint64](U0.NCols(), 1)
	inner_prod := MatrixZeros[uint64](1, 1)
	norm_sq := MatrixZeros[Uint128](1, 1)

	inner_prod0 := MatrixZeros[Share128](1, 1)
	inner_prod1 := MatrixZeros[Share128](1, 1)
	inner_prod2 := MatrixZeros[Share128](1, 1)

	sub0 := MatrixZeros[Share128](U0.NCols(), 1)
	sub1 := MatrixZeros[Share128](U0.NCols(), 1)
	sub2 := MatrixZeros[Share128](U0.NCols(), 1)

	for component := 0; component < params.K; component++ {
		fmt.Printf("  building factor %d of %d\n", component, params.K)

		if params.Start_random {
			// Init with random values in {-1, 0, 1}
			SetRand[uint64](v_init_sm, U0.NCols(), 1, 0, 3, pool)
			MatrixSubScalarInPlace(v_init_sm, 1)
		} else {
			SetOnes[uint64](v_init_sm, U0.NCols(), 1)
		}

		MulByConstantInPlace64(v_init_sm, pad)

		// Force orthogonality to already-computed factors
		for factor := 0; factor < component; factor++ {
			factor_vector := B.GetRowsPointer(uint64(factor), uint64(factor+1))
			MatrixMulDst(factor_vector, v_init_sm, inner_prod)
			MatrixRshSignedInPlace(inner_prod, params.N_decimals)

			MatrixTransposeMulDst(factor_vector, inner_prod, sub)
			MatrixRshSignedInPlace(sub, params.N_decimals)
			MatrixSubInPlace(v_init_sm, sub)
		}

		// Normalize v_init (still all plaintext)
		ToMatrix128Dst(v_init_sm, v_init) // Map to huge array to prevent overflow
		MatrixTransposeMul128Dst(v_init, v_init, norm_sq)
		shifted_by := 0
		norm_sq_int := norm_sq.Get(0, 0)
		for !CheckPositiveUint64(norm_sq_int) {
			if shifted_by > 128 {
				panic("Should not happen")
			}
			norm_sq_int.RshInPlace(uint(params.N_decimals))
			shifted_by += params.N_decimals
		}

		norm_sq_shifted_int := ToUint64(norm_sq_int)
		norm := uint64(math.Sqrt(float64(norm_sq_shifted_int)))

		shifted_by_after_sqrt := shifted_by / 2

		if norm > 0 {
			if shifted_by_after_sqrt <= params.N_decimals {
				MulByConstantInPlace128(v_init, (pad >> shifted_by_after_sqrt))
				DivByConstantInPlace128(v_init, norm)
			} else {
				DivByConstantInPlace128(v_init, norm<<(shifted_by_after_sqrt-params.N_decimals))
			}
		}

		ToMatrix64Dst(v_init, v_init_sm)
		if params.Start_random {
			// Noise the lowest-order bits
			u := RandMatrix[uint64](U0.NCols(), 1, 1, 10001, pool)
			MatrixAddInPlace64(v_init_sm, u)
		}

		// First step in Mul
		MatrixMulRSSPtxtDst(U0, v_init_sm, u0)
		MatrixMulRSSPtxtDst(U1, v_init_sm, u1)
		MatrixMulRSSPtxtDst(U2, v_init_sm, u2)

		var trunc_saved uint
		if !params.Save_truncate {
			MatrixTruncateRSSInPlace(u0, u1, u2, uint(params.N_decimals), pool, perf)
			trunc_saved = 0
		} else {
			trunc_saved += 1
		}

		for iter := 0; iter < params.N_iters; iter++ {
			fmt.Printf("Iter %d\n", iter)
			start := time.Now()

			// Pulled out the very first operation (performed right above), because v starts out as plaintext
			// Also: avoid truncation by just not scaling up v_init by pad in the first place
			if iter > 0 {
				// Matrix-vector product on shared data: [u] = [U] * [v]
				MatrixMulRSSDst(U0, v0, u0_add)
				MatrixMulRSSDst(U1, v1, u1_add)
				MatrixMulRSSDst(U2, v2, u2_add)

				if !params.Save_truncate {
					dealer := perf.IdentifyDealer()
					MatrixAdditive3To2InPlace(u0_add, u1_add, u2_add, dealer, pool, perf)
					MatrixTruncateAdditiveInPlace(u0_add, u1_add, u2_add, uint(params.N_decimals), dealer, pool, perf)
					trunc_saved = 0
				} else {
					trunc_saved += 1
				}

				// Re-sharing: turn additive shares of [u] into RSS ones
				MatrixAdditiveToRSSDst(u0_add, u1_add, u2_add, u0, u1, u2, pool, perf)
			}

			// Matrix-vector product on shared data: [v] = [U.transpose] * [u]
			MatrixTransposeMulRSSDst(U0, u0, v0_add) // same as U0.T * u0
			MatrixTransposeMulRSSDst(U1, u1, v1_add)
			MatrixTransposeMulRSSDst(U2, u2, v2_add)

			MatrixAdditiveToRSSDst(v0_add, v1_add, v2_add, v0, v1, v2, pool, perf)

			if !params.Save_truncate {
				MatrixTruncateRSSInPlace(v0, v1, v2, uint(params.N_decimals), pool, perf)
			} else {
				MatrixTruncateRSSInPlace(v0, v1, v2, uint(params.N_decimals)*(trunc_saved+1), pool, perf)
			}
			trunc_saved = 0

			// Force orthogonality to already-computed factors
			MulByConstantInPlaceRSS128(v0, pad)
			MulByConstantInPlaceRSS128(v1, pad)
			MulByConstantInPlaceRSS128(v2, pad)

			for factor := 0; factor < component; factor++ {
				factor_vector := B.GetRowsPointer(uint64(factor), uint64(factor+1))
				MatrixPtxtMulDst(factor_vector, v0, inner_prod0)
				MatrixPtxtMulDst(factor_vector, v1, inner_prod1)
				MatrixPtxtMulDst(factor_vector, v2, inner_prod2)

				MatrixTruncateRSSInPlace(inner_prod0, inner_prod1, inner_prod2, uint(params.N_decimals*2), pool, perf)

				MatrixTransposePtxtMulDst(factor_vector, inner_prod0, sub0)
				MatrixTransposePtxtMulDst(factor_vector, inner_prod1, sub1)
				MatrixTransposePtxtMulDst(factor_vector, inner_prod2, sub2)

				MatrixSubRSSInPlace(v0, sub0)
				MatrixSubRSSInPlace(v1, sub1)
				MatrixSubRSSInPlace(v2, sub2)
			}

			MatrixTruncateRSSInPlace(v0, v1, v2, uint(params.N_decimals), pool, perf)
			trunc_saved = 0

			// Normalize the vector
			VectorNormalizeRSSInPlace(v0, v1, v2, uint(params.N_decimals), uint(params.Norm_decimals), uint(params.Newton_iters), pool, perf)

			duration := time.Since(start)
			fmt.Printf("    took %v\n", duration)
		}

		// At this point: share and reveal the vector v (which leaks as part of the output anyways)
		// TODO: Save one round of communication, reveal with additive sharing instead
		MatrixRecoverFromRSSDst(v0, v1, v2, v, perf)

		B.SetRow(uint64(component), v)
		fmt.Printf("Recovered component %d\n", component)
	}

	fmt.Println("Returing from power iteration...")
	return B, transposed, perf
}
