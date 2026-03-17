package share

import (
	"fmt"
	"math"
	"github.com/NudgeArtifact/private-recs/multdpf"
	. "github.com/NudgeArtifact/private-recs/rand"
	. "github.com/NudgeArtifact/private-recs/uint128"
	"testing"
)

func TestMain(m *testing.M) {
	if DebugMode {
		fmt.Println("Debug mode is ON")
	} else {
		fmt.Println("Debug mode is OFF")
	}
	m.Run()
}

func TestAdditive64(test *testing.T) {
	fmt.Println("TestAdditive64")

	seed := RandomPRGKey()
	bPRG := NewBufPRG(NewPRG(seed))

	for iter := 0; iter < 100; iter++ {
		v := uint64(1 + iter)
		a := shareAdditive(v, bPRG, 3)

		if recoverAdditive(a[0], a[1], a[2]) != v {
			fmt.Println("recoverAdditive failed")
			test.Fail()
		}
	}
}

func TestAdditive128(test *testing.T) {
	fmt.Println("TestAdditive128")

	seed := RandomPRGKey()
	bPRG := NewBufPRG(NewPRG(seed))

	for iter := 0; iter < 100; iter++ {
		v := uint64(1 + iter)
		a := shareAdditive128(v, bPRG, 3)

		if recoverAdditive128(&a[0], &a[1], &a[2]) != v {
			fmt.Println("recoverAdditive128 failed")
			test.Fail()
		}
	}
}

func TestRSS64(test *testing.T) {
	fmt.Println("TestRSS64")

	seed := RandomPRGKey()
	bPRG := NewBufPRG(NewPRG(seed))

	for iter := 0; iter < 100; iter++ {
		v := uint64(1 + iter)
		s0, s1, s2 := ShareRSS(v, bPRG)

		if (s0.Second != s2.First) || (s0.First != s1.Second) || (s1.First != s2.Second) {
			test.Fail()
		}

		sum := s0.First + s0.Second + s1.First
		if sum != v {
			test.Fail()
		}

		if recoverRSS(s0, s1, s2) != v {
			fmt.Println("RSS recover failed")
			test.Fail()
		}
	}
}

func TestRSS128(test *testing.T) {
	fmt.Println("TestRSS128")

	seed := RandomPRGKey()
	bPRG := NewBufPRG(NewPRG(seed))

	for iter := 0; iter < 100; iter++ {
		v := uint64(1 + iter)
		s0, s1, s2 := ShareRSS128(v, bPRG)

		if recoverRSS128(s0, s1, s2) != v {
			fmt.Println("recoverRSS128 recover failed")
			test.Fail()
		}
	}
}

func TestRSSDPF64(test *testing.T) {
	fmt.Println("TestRSSDPF64")

	logN := uint64(8)
	alpha := uint64(123)
	a, b, c := multdpf.Gen(alpha, logN, 64)

	for i := uint64(0); i < (uint64(1) << logN); i++ {
		aa1, aa2 := multdpf.Eval64(a, i, logN, 0)
		bb1, bb2 := multdpf.Eval64(b, i, logN, 1)
		cc1, cc2 := multdpf.Eval64(c, i, logN, 2)

		sa := share{First: aa1, Second: aa2}
		sb := share{First: bb1, Second: bb2}
		sc := share{First: cc1, Second: cc2}

		if (i != alpha) && (recoverRSS(&sa, &sb, &sc) != 0) {
			fmt.Printf("Did not sum to 0 at index %d: %d\n", i, recoverRSS(&sa, &sb, &sc))
			test.Fail()
		}
		if (i == alpha) && (recoverRSS(&sa, &sb, &sc) != 1) {
			fmt.Printf("Did not sum to 1 at index %d: %d\n", i, recoverRSS(&sa, &sb, &sc))
			test.Fail()
		}
	}
}

func TestRSSDPF128(test *testing.T) {
	fmt.Println("TestRSSDPF128")
	logN := uint64(8)
	alpha := uint64(123)
	a, b, c := multdpf.Gen(alpha, logN, 128)

	for i := uint64(0); i < (uint64(1) << logN); i++ {
		aa1, aa2 := multdpf.Eval128(a, i, logN, 0)
		bb1, bb2 := multdpf.Eval128(b, i, logN, 1)
		cc1, cc2 := multdpf.Eval128(c, i, logN, 2)

		sa := Share128{First: aa1, Second: aa2}
		sb := Share128{First: bb1, Second: bb2}
		sc := Share128{First: cc1, Second: cc2}

		if (i != alpha) && (recoverRSS128(&sa, &sb, &sc) != 0) {
			fmt.Printf("Did not sum to 0 at index %d: %d\n", i, recoverRSS128(&sa, &sb, &sc))
			test.Fail()
		}
		if (i == alpha) && (recoverRSS128(&sa, &sb, &sc) != 1) {
			fmt.Printf("Did not sum to 1 at index %d: %d\n", i, recoverRSS128(&sa, &sb, &sc))
			test.Fail()
		}
	}
}

func TestRSSAdd64(test *testing.T) {
	fmt.Println("TestRSSAdd64")

	seed := RandomPRGKey()
	bPRG := NewBufPRG(NewPRG(seed))

	for iter := 0; iter < 100; iter++ {
		v := uint64(123 + iter)
		u := uint64(456 + iter)

		s0, s1, s2 := ShareRSS(v, bPRG)
		t0, t1, t2 := ShareRSS(u, bPRG)

		// test regular Add
		r0 := AddRSS(s0, t0)
		r1 := AddRSS(s1, t1)
		r2 := AddRSS(s2, t2)

		if recoverRSS(r0, r1, r2) != u+v {
			fmt.Printf("Add: summed to %d instead of %d\n", recoverRSS(s0, s1, s2), u+v)
			test.Fail()
		}

		// test in-place Add
		AddRSSInPlace(s0, t0)
		AddRSSInPlace(s1, t1)
		AddRSSInPlace(s2, t2)

		if recoverRSS(s0, s1, s2) != u+v {
			fmt.Printf("In-place Add: summed to %d instead of %d\n", recoverRSS(s0, s1, s2), u+v)
			test.Fail()
		}
	}
}

func TestRSSSub64(test *testing.T) {
	fmt.Println("TestRSSSub64")

	seed := RandomPRGKey()
	bPRG := NewBufPRG(NewPRG(seed))

	for iter := 0; iter < 100; iter++ {
		v := uint64(123 + iter)
		u := uint64(456 + iter)

		s0, s1, s2 := ShareRSS(v, bPRG)
		t0, t1, t2 := ShareRSS(u, bPRG)

		// test regular sub
		r0 := SubRSS(s0, t0)
		r1 := SubRSS(s1, t1)
		r2 := SubRSS(s2, t2)

		if recoverRSS(r0, r1, r2) != v-u {
			fmt.Printf("Sub: got %d instead of %d\n", recoverRSS(r0, r1, r2), v-u)
			test.Fail()
		}

		// test in-place sub
		SubRSSInPlace(s0, t0)
		SubRSSInPlace(s1, t1)
		SubRSSInPlace(s2, t2)

		if recoverRSS(s0, s1, s2) != v-u {
			fmt.Printf("Sub (in-place): got %d instead of %d\n", recoverRSS(r0, r1, r2), v-u)
			test.Fail()
		}
	}
}

func TestRSSAdd128(test *testing.T) {
	fmt.Println("TestRSSAdd128")

	seed := RandomPRGKey()
	bPRG := NewBufPRG(NewPRG(seed))

	for iter := 0; iter < 100; iter++ {
		v := uint64(123 + iter)
		u := uint64(456 + iter)

		s0, s1, s2 := ShareRSS128(v, bPRG)
		t0, t1, t2 := ShareRSS128(u, bPRG)

		// test regular Add
		r0 := AddRSS128(s0, t0)
		r1 := AddRSS128(s1, t1)
		r2 := AddRSS128(s2, t2)

		if recoverRSS128(r0, r1, r2) != u+v {
			fmt.Printf("Add: summed to %d instead of %d\n", recoverRSS128(r0, r1, r2), u+v)
			test.Fail()
		}

		// test in-place Add
		AddRSSInPlace128(s0, t0)
		AddRSSInPlace128(s1, t1)
		AddRSSInPlace128(s2, t2)

		if recoverRSS128(s0, s1, s2) != u+v {
			fmt.Printf("In-place Add: summed to %d instead of %d\n", recoverRSS128(s0, s1, s2), u+v)
			test.Fail()
		}
	}
}

func TestRSSSub128(test *testing.T) {
	fmt.Println("TestRSSSub128")

	seed := RandomPRGKey()
	bPRG := NewBufPRG(NewPRG(seed))

	for iter := 0; iter < 100; iter++ {
		v := uint64(123 + iter)
		u := uint64(456 + iter)

		s0, s1, s2 := ShareRSS128(v, bPRG)
		t0, t1, t2 := ShareRSS128(u, bPRG)

		r0 := SubRSS128(s0, t0)
		r1 := SubRSS128(s1, t1)
		r2 := SubRSS128(s2, t2)

		if recoverRSS128(r0, r1, r2) != v-u {
			test.Fail()
		}

		SubRSSInPlace128(s0, t0)
		SubRSSInPlace128(s1, t1)
		SubRSSInPlace128(s2, t2)

		if recoverRSS128(s0, s1, s2) != v-u {
			test.Fail()
		}
	}
}

func TestRSSMul64(test *testing.T) {
	fmt.Println("TestRSSMul64")

	seed := RandomPRGKey()
	bPRG := NewBufPRG(NewPRG(seed))

	for iter := 0; iter < 100; iter++ {
		v := uint64(123 + iter)
		u := uint64(456 + iter)

		s0, s1, s2 := ShareRSS(v, bPRG)
		t0, t1, t2 := ShareRSS(u, bPRG)

		r0 := mulRSS(s0, t0)
		r1 := mulRSS(s1, t1)
		r2 := mulRSS(s2, t2)

		if recoverAdditive(r0, r1, r2) != u*v {
			fmt.Printf("Mul: multiplied to %d instead of %d\n", recoverAdditive(r0, r1, r2), u*v)
			test.Fail()
		}
	}
}

func TestRSSMul128(test *testing.T) {
	fmt.Println("TestRSSMul128")

	seed := RandomPRGKey()
	bPRG := NewBufPRG(NewPRG(seed))

	for iter := 0; iter < 100; iter++ {
		v := uint64(123 + iter)
		u := uint64(456 + iter)

		s0, s1, s2 := ShareRSS128(v, bPRG)
		t0, t1, t2 := ShareRSS128(u, bPRG)

		r0 := MulRSS128(s0, t0)
		r1 := MulRSS128(s1, t1)
		r2 := MulRSS128(s2, t2)

		if recoverAdditive128(r0, r1, r2) != u*v {
			fmt.Printf("Mul: multiplied to %d instead of %d\n", recoverAdditive128(r0, r1, r2), u*v)
			test.Fail()
		}
	}
}

func TestRSSMulAdd64(test *testing.T) {
	fmt.Println("TestRSSMulAdd64")

	seed := RandomPRGKey()
	bPRG := NewBufPRG(NewPRG(seed))

	r0 := uint64(0)
	r1 := uint64(0)
	r2 := uint64(0)
	sum := uint64(0)

	for iter := 0; iter < 100; iter++ {
		v := uint64(123 + iter)
		u := uint64(456 + iter)

		s0, s1, s2 := ShareRSS(v, bPRG)
		t0, t1, t2 := ShareRSS(u, bPRG)

		r0 += mulRSS(s0, t0)
		r1 += mulRSS(s1, t1)
		r2 += mulRSS(s2, t2)

		sum += (u * v)
	}

	if recoverAdditive(r0, r1, r2) != sum {
		fmt.Printf("Mul then Add: got %d instead of %d\n", recoverAdditive(r0, r1, r2), sum)
		test.Fail()
	}
}

func TestRSSMulAdd128(test *testing.T) {
	fmt.Println("TestRSSMulAdd128")

	seed := RandomPRGKey()
	bPRG := NewBufPRG(NewPRG(seed))

	r0 := MakeUint128(0, 0)
	r1 := MakeUint128(0, 0)
	r2 := MakeUint128(0, 0)
	sum := uint64(0)

	for iter := 0; iter < 100; iter++ {
		v := uint64(123 + iter)
		u := uint64(456 + iter)

		s0, s1, s2 := ShareRSS128(v, bPRG)
		t0, t1, t2 := ShareRSS128(u, bPRG)

		r0.AddInPlace(MulRSS128(s0, t0))
		r1.AddInPlace(MulRSS128(s1, t1))
		r2.AddInPlace(MulRSS128(s2, t2))

		sum += (u * v)
	}

	if recoverAdditive128(r0, r1, r2) != sum {
		fmt.Printf("Mul then Add: got %d instead of %d\n", recoverAdditive128(r0, r1, r2), sum)
		test.Fail()
	}
}

func TestRSSMatrixVec64(test *testing.T) {
	fmt.Println("TestRSSMatrixVec64")

	seed := RandomPRGKey()
	bPRG := NewBufPRG(NewPRG(seed))

	nRows := 100
	nCols := 100
	matrix := make([]uint64, nRows*nCols)
	shares0 := make([]share, nRows*nCols)
	shares1 := make([]share, nRows*nCols)
	shares2 := make([]share, nRows*nCols)
	vector := make([]uint64, nRows)

	for i := 0; i < nRows; i++ {
		vector[i] = uint64(nRows - i)
		for j := 0; j < nCols; j++ {
			matrix[i*nCols+j] = uint64(i*nCols + j)
			s0, s1, s2 := ShareRSS(matrix[i*nCols+j], bPRG)
			shares0[i*nCols+j] = *s0
			shares1[i*nCols+j] = *s1
			shares2[i*nCols+j] = *s2
		}
	}

	// Correctness check
	for i := 0; i < nRows; i++ {
		for j := 0; j < nCols; j++ {
			if recoverRSS(&shares0[i*nCols+j], &shares1[i*nCols+j], &shares2[i*nCols+j]) != matrix[i*nCols+j] {
				fmt.Printf("Correctness check 1 failed at %d, %d\n", i, j)
				test.Fail()
			}
		}
	}

	// Matrix-vector product between secret-shared matrix and plaintext vector
	vector2_share0 := make([]share, nRows)
	vector2_share1 := make([]share, nRows)
	vector2_share2 := make([]share, nRows)
	vector2_ptxt := make([]uint64, nRows)
	for i := 0; i < nRows; i++ {
		for j := 0; j < nCols; j++ {
			vector2_ptxt[i] += (matrix[i*nCols+j] * vector[j])
			s0 := PtxtMulRSS(&shares0[i*nCols+j], vector[j])
			s1 := PtxtMulRSS(&shares1[i*nCols+j], vector[j])
			s2 := PtxtMulRSS(&shares2[i*nCols+j], vector[j])
			AddRSSInPlace(&vector2_share0[i], s0)
			AddRSSInPlace(&vector2_share1[i], s1)
			AddRSSInPlace(&vector2_share2[i], s2)
		}
	}

	// Correctness check
	for i := 0; i < nRows; i++ {
		if recoverRSS(&vector2_share0[i], &vector2_share1[i], &vector2_share2[i]) != vector2_ptxt[i] {
			fmt.Printf("Correctness check 2 failed at %d\n", i)
			test.Fail()
		}
	}

	// Matrix-vector product between secret-shared matrix and secret-shared vector
	vector3_share0 := make([]uint64, nRows)
	vector3_share1 := make([]uint64, nRows)
	vector3_share2 := make([]uint64, nRows)
	vector3_ptxt := make([]uint64, nRows)
	for i := 0; i < nRows; i++ {
		for j := 0; j < nCols; j++ {
			vector3_ptxt[i] += (matrix[i*nCols+j] * vector2_ptxt[j])
			vector3_share0[i] += mulRSS(&shares0[i*nCols+j], &vector2_share0[j])
			vector3_share1[i] += mulRSS(&shares1[i*nCols+j], &vector2_share1[j])
			vector3_share2[i] += mulRSS(&shares2[i*nCols+j], &vector2_share2[j])
		}
	}

	// Correctness check
	for i := 0; i < nRows; i++ {
		if recoverAdditive(vector3_share0[i], vector3_share1[i], vector3_share2[i]) != vector3_ptxt[i] {
			fmt.Printf("Correctness check 3 failed at %d\n", i)
			test.Fail()
		}
	}

	// Re-sharing: turn Additive shares into RSS shares
	vector3_rss_share0 := make([]share, nRows)
	vector3_rss_share1 := make([]share, nRows)
	vector3_rss_share2 := make([]share, nRows)
	for i := 0; i < nRows; i++ {
		s0, s1, s2 := AdditiveToRSS(vector3_share0[i], vector3_share1[i], vector3_share2[i], bPRG)
		vector3_rss_share0[i] = *s0
		vector3_rss_share1[i] = *s1
		vector3_rss_share2[i] = *s2
	}

	// Matrix-vector product between secret-shared matrix and secret-shared vector
	vector4_share0 := make([]uint64, nRows)
	vector4_share1 := make([]uint64, nRows)
	vector4_share2 := make([]uint64, nRows)
	vector4_ptxt := make([]uint64, nRows)
	for i := 0; i < nRows; i++ {
		for j := 0; j < nCols; j++ {
			vector4_ptxt[i] += (matrix[i*nCols+j] * vector3_ptxt[j])
			vector4_share0[i] += mulRSS(&shares0[i*nCols+j], &vector3_rss_share0[j])
			vector4_share1[i] += mulRSS(&shares1[i*nCols+j], &vector3_rss_share1[j])
			vector4_share2[i] += mulRSS(&shares2[i*nCols+j], &vector3_rss_share2[j])
		}
	}

	// Correctness check
	for i := 0; i < nRows; i++ {
		if recoverAdditive(vector4_share0[i], vector4_share1[i], vector4_share2[i]) != vector4_ptxt[i] {
			fmt.Printf("Correctness check 4 failed at %d\n", i)
			test.Fail()
		}
	}
}

func TestRSSMatrixVec128(test *testing.T) {
	fmt.Println("TestRSSMatrixVec128")

	seed := RandomPRGKey()
	bPRG := NewBufPRG(NewPRG(seed))

	nRows := 100
	nCols := 100
	matrix := make([]uint64, nRows*nCols)
	vector := make([]uint64, nRows)
	shares0 := make([]Share128, nRows*nCols)
	shares1 := make([]Share128, nRows*nCols)
	shares2 := make([]Share128, nRows*nCols)

	for i := 0; i < nRows; i++ {
		vector[i] = uint64(nRows - i)
		for j := 0; j < nCols; j++ {
			matrix[i*nCols+j] = uint64(i*nCols + j)
			s0, s1, s2 := ShareRSS128(matrix[i*nCols+j], bPRG)
			shares0[i*nCols+j] = *s0
			shares1[i*nCols+j] = *s1
			shares2[i*nCols+j] = *s2
		}
	}

	// Correctness check
	for i := 0; i < nRows; i++ {
		for j := 0; j < nCols; j++ {
			if recoverRSS128(&shares0[i*nCols+j], &shares1[i*nCols+j], &shares2[i*nCols+j]) != matrix[i*nCols+j] {
				fmt.Printf("Correctness check 1 failed at %d, %d\n", i, j)
				test.Fail()
			}
		}
	}

	// Matrix-vector product between secret-shared matrix and plaintext vector
	vector2_share0 := make([]Share128, nRows)
	vector2_share1 := make([]Share128, nRows)
	vector2_share2 := make([]Share128, nRows)
	vector2_ptxt := make([]uint64, nRows)
	for i := 0; i < nRows; i++ {
		for j := 0; j < nCols; j++ {
			vector2_ptxt[i] += (matrix[i*nCols+j] * vector[j])
			s0 := PtxtMulRSS128(&shares0[i*nCols+j], vector[j])
			s1 := PtxtMulRSS128(&shares1[i*nCols+j], vector[j])
			s2 := PtxtMulRSS128(&shares2[i*nCols+j], vector[j])
			AddRSSInPlace128(&vector2_share0[i], s0)
			AddRSSInPlace128(&vector2_share1[i], s1)
			AddRSSInPlace128(&vector2_share2[i], s2)
		}
	}

	// Correctness check
	for i := 0; i < nRows; i++ {
		if recoverRSS128(&vector2_share0[i], &vector2_share1[i], &vector2_share2[i]) != vector2_ptxt[i] {
			fmt.Printf("Correctness check 2 failed at %d\n", i)
			test.Fail()
		}
	}

	// Matrix-vector product between secret-shared matrix and secret-shared vector
	vector3_share0 := make([]Uint128, nRows)
	vector3_share1 := make([]Uint128, nRows)
	vector3_share2 := make([]Uint128, nRows)
	vector3_ptxt := make([]uint64, nRows)
	for i := 0; i < nRows; i++ {
		for j := 0; j < nCols; j++ {
			vector3_ptxt[i] += (matrix[i*nCols+j] * vector2_ptxt[j])
			vector3_share0[i].AddInPlace(MulRSS128(&shares0[i*nCols+j], &vector2_share0[j]))
			vector3_share1[i].AddInPlace(MulRSS128(&shares1[i*nCols+j], &vector2_share1[j]))
			vector3_share2[i].AddInPlace(MulRSS128(&shares2[i*nCols+j], &vector2_share2[j]))
		}
	}

	// Correctness check
	for i := 0; i < nRows; i++ {
		if recoverAdditive128(&vector3_share0[i], &vector3_share1[i], &vector3_share2[i]) != vector3_ptxt[i] {
			fmt.Printf("Correctness check 3 failed at %d\n", i)
			test.Fail()
		}
	}

	// Re-sharing: turn Additive shares into RSS shares
	vector3_rss_share0 := make([]Share128, nRows)
	vector3_rss_share1 := make([]Share128, nRows)
	vector3_rss_share2 := make([]Share128, nRows)
	for i := 0; i < nRows; i++ {
		s0, s1, s2 := AdditiveToRSS128(&vector3_share0[i], &vector3_share1[i], &vector3_share2[i], bPRG)
		vector3_rss_share0[i] = *s0
		vector3_rss_share1[i] = *s1
		vector3_rss_share2[i] = *s2
	}

	// Truncation: divide everything by 4 (else, entire computation overflows past 2^64)
	for i := 0; i < nRows; i++ {
		vector3_ptxt[i] /= 4
		a0, a1, a2 := truncateRSSToAdditive128(&vector3_rss_share0[i], &vector3_rss_share1[i], &vector3_rss_share2[i], 2, bPRG)
		s0, s1, s2 := AdditiveToRSS128(a0, a1, a2, bPRG)
		vector3_rss_share0[i] = *s0
		vector3_rss_share1[i] = *s1
		vector3_rss_share2[i] = *s2
	}

	// Correctness check
	for i := 0; i < nRows; i++ {
		recovered := recoverRSS128(&vector3_rss_share0[i], &vector3_rss_share1[i], &vector3_rss_share2[i])
		if !(recovered == vector3_ptxt[i]) {
			fmt.Printf("Correctness check 4 failed at %d: got %d instead of %d\n", i, recovered, vector3_ptxt[i])
			test.Fail()
		}
		if recovered == vector3_ptxt[i]+1 {
			vector3_ptxt[i] += 1
		}
	}

	// Matrix-vector product between secret-shared matrix and secret-shared vector
	vector4_share0 := make([]Uint128, nRows)
	vector4_share1 := make([]Uint128, nRows)
	vector4_share2 := make([]Uint128, nRows)
	vector4_ptxt := make([]uint64, nRows)
	for i := 0; i < nRows; i++ {
		for j := 0; j < nCols; j++ {
			vector4_ptxt[i] += (matrix[i*nCols+j] * vector3_ptxt[j])
			vector4_share0[i].AddInPlace(MulRSS128(&shares0[i*nCols+j], &vector3_rss_share0[j]))
			vector4_share1[i].AddInPlace(MulRSS128(&shares1[i*nCols+j], &vector3_rss_share1[j]))
			vector4_share2[i].AddInPlace(MulRSS128(&shares2[i*nCols+j], &vector3_rss_share2[j]))
		}
	}

	// Correctness check
	for i := 0; i < nRows; i++ {
		if recoverAdditive128(&vector4_share0[i], &vector4_share1[i], &vector4_share2[i]) != vector4_ptxt[i] {
			fmt.Printf("Correctness check 5 failed at %d\n", i)
			test.Fail()
		}
	}
}

func TestRSSTruncate64(test *testing.T) {
	fmt.Println("TestRSSTruncate64")
	decimals := uint(16)

	seed := RandomPRGKey()
	bPRG := NewBufPRG(NewPRG(seed))

	// In this test: the portion rounded away is always 0
	for iter := 0; iter < 1000; iter++ {
		v := uint64((1 + iter) * 12736876358)
		s0, s1, s2 := ShareRSS(v, bPRG)

		// Test that Additive shares are generated correctly
		if recoverRSS(s0, s1, s2) != v {
			fmt.Printf("TestRSSTruncate failed (test 1, before truncate): got %d but should be %d\n",
				recoverRSS(s0, s1, s2), v)
			test.Fail()
		}

		// Test that truncation works correctly
		a0, a1, a2 := truncateRSSToAdditive(s0, s1, s2, decimals, bPRG)
		t0, t1, t2 := AdditiveToRSS(a0, a1, a2, bPRG)
		truncated := v >> 16
		recovered := recoverRSS(t0, t1, t2)

		if !(recovered == truncated) {
			fmt.Printf("Truncating %d by %d digits: should get %d\n", v, decimals, truncated)
			fmt.Printf("TestRSSTruncate failed (test 1, after truncate): got %d but should be %d\n",
				recovered, truncated)
			test.Fail()
			panic("FAIL")

		}

	}

	// In this test: the portion rounded away is NOT always 0
	for iter := 0; iter < 1000; iter++ {
		v := uint64((1 + iter) * 234678)
		s0, s1, s2 := ShareRSS(v, bPRG)

		// Test that Additive shares are generated correctly
		if recoverRSS(s0, s1, s2) != v {
			fmt.Printf("TestRSSTruncate failed (test 2, before truncate): got %d but should be %d\n",
				recoverRSS(s0, s1, s2), v)
			test.Fail()
			panic("FAIL")
		}

		// Test that truncation works correctly
		a0, a1, a2 := truncateRSSToAdditive(s0, s1, s2, decimals, bPRG)
		t0, t1, t2 := AdditiveToRSS(a0, a1, a2, bPRG)
		truncated := v >> 16
		recovered := recoverRSS(t0, t1, t2)

		if !(recovered == truncated) {
			fmt.Printf("Truncating %d by %d digits: should get %d\n", v, decimals, truncated)
			fmt.Printf("TestRSSTruncate failed (test 2, after truncate): got %d but should be %d\n",
				recovered, truncated)
			test.Fail()
			panic("FAIL")
		}

	}

	for iter := 0; iter < 1000; iter++ {
		v := uint64((1 + iter) << 60)
		v = v % (1 << 62) // This is necessary for correctness!

		truncated := uint64(int64(v) >> 16)
		s0, s1, s2 := ShareRSS(v, bPRG)

		// Test that Additive shares are generated correctly
		if recoverRSS(s0, s1, s2) != v {
			fmt.Printf("TestRSSTruncate failed (test 3, before truncate): got %d but should be %d\n",
				recoverRSS(s0, s1, s2), v)
			test.Fail()
			panic("FAIL")
		}

		// Test that truncation works correctly
		a0, a1, a2 := truncateRSSToAdditive(s0, s1, s2, decimals, bPRG)
		t0, t1, t2 := AdditiveToRSS(a0, a1, a2, bPRG)
		recovered := recoverRSS(t0, t1, t2)

		if !(recovered == truncated) {
			fmt.Printf("Truncating %d by %d digits: should get %d\n", v, decimals, truncated)
			fmt.Printf("TestRSSTruncate failed (test 3, after truncate): got %d but should be %d\n",
				recovered, truncated)
			test.Fail()
			panic("FAIL")
		}

	}

	for iter := 0; iter < 1000; iter++ {
		v := uint64((1 + iter) << 60)
		v = v % (1 << 62) // This is necessary for correctness!
		v = -v

		truncated := uint64(int64(v) >> 16)
		s0, s1, s2 := ShareRSS(v, bPRG)

		// Test that Additive shares are generated correctly
		if recoverRSS(s0, s1, s2) != v {
			fmt.Printf("TestRSSTruncate failed (test 4, before truncate): got %d but should be %d\n",
				recoverRSS(s0, s1, s2), v)
			test.Fail()
			panic("FAIL")
		}

		// Test that truncation works correctly
		a0, a1, a2 := truncateRSSToAdditive(s0, s1, s2, decimals, bPRG)
		t0, t1, t2 := AdditiveToRSS(a0, a1, a2, bPRG)
		recovered := recoverRSS(t0, t1, t2)

		if !(recovered == truncated) {
			fmt.Printf("Truncating %d by %d digits: should get %d\n", v, decimals, truncated)
			fmt.Printf("TestRSSTruncate failed (test 4, after truncate): got %d but should be %d\n",
				recovered, truncated)
			test.Fail()
			panic("FAIL")
		}

	}

	// In this test: generate deliberately bad shares (i.e., that overflow) by sharing x into (-1, x+1)
	for iter := 0; iter < 1000; iter++ {
		v := uint64((1 + iter) * 23487)
		truncated := uint64(int64(v) >> 16)
		s0 := &share{First: math.MaxUint64, Second: 0}
		s1 := &share{First: v + 1, Second: math.MaxUint64} // math.MaxUint64 = -1
		s2 := &share{First: 0, Second: v + 1}

		// Test that Additive shares are generated correctly
		if recoverRSS(s0, s1, s2) != v {
			fmt.Printf("TestRSSTruncate failed (test 5, before truncate): got %d but should be %d\n",
				recoverRSS(s0, s1, s2), v)
			test.Fail()
			panic("FAIL")
		}

		// Test that truncation works correctly
		a0, a1, a2 := truncateRSSToAdditive(s0, s1, s2, decimals, bPRG)
		t0, t1, t2 := AdditiveToRSS(a0, a1, a2, bPRG)
		recovered := recoverRSS(t0, t1, t2)

		if !(recovered == truncated) {
			fmt.Printf("Truncating %d by %d digits: should get %d\n", v, decimals, truncated)
			fmt.Printf("TestRSSTruncate failed (test 5, after truncate): got %d but should be %d\n",
				recovered, truncated)
			test.Fail()
			panic("FAIL")
		}

	}
}

func TestRSSTruncate128(test *testing.T) {
	fmt.Println("TestRSSTruncate128")
	decimals := uint(16)

	seed := RandomPRGKey()
	bPRG := NewBufPRG(NewPRG(seed))

	// In this test: the portion rounded away is always 0
	for iter := 0; iter < 1000; iter++ {
		v := uint64(25769803776 * iter)
		s0, s1, s2 := ShareRSS128(v, bPRG)

		// Test that Additive shares are generated correctly
		if recoverRSS128(s0, s1, s2) != v {
			fmt.Printf("TestRSSTruncate128 failed (test 1, before truncate): got %d but should be %d\n",
				recoverRSS128(s0, s1, s2), v)
			test.Fail()
		}

		// Test that truncation works correctly
		a0, a1, a2 := truncateRSSToAdditive128(s0, s1, s2, decimals, bPRG)
		t0, t1, t2 := AdditiveToRSS128(a0, a1, a2, bPRG)
		truncated := v >> 16
		recovered := recoverRSS128(t0, t1, t2)

		if recovered != truncated {
			fmt.Printf("TestRSSTruncate128 failed (test 1, after truncate): got %d but should be %d\n",
				recovered, truncated)
			test.Fail()
		}

	}

	// In this test: the portion rounded away is NOT always 0
	for iter := 0; iter < 1000; iter++ {
		v := uint64((1 + iter) << 15)
		s0, s1, s2 := ShareRSS128(v, bPRG)

		// Test that Additive shares are generated correctly
		if recoverRSS128(s0, s1, s2) != v {
			fmt.Printf("TestRSSTruncate128 failed (test 2, before truncate): got %d but should be %d\n",
				recoverRSS128(s0, s1, s2), v)
			test.Fail()
		}

		// Test that truncation works correctly
		a0, a1, a2 := truncateRSSToAdditive128(s0, s1, s2, decimals, bPRG)
		t0, t1, t2 := AdditiveToRSS128(a0, a1, a2, bPRG)
		truncated := v >> 16
		recovered := recoverRSS128(t0, t1, t2)

		if !(recovered == truncated) {
			fmt.Printf("TestRSSTruncate128 failed (test 2, after truncate): got %d but should be %d\n",
				recovered, truncated)
			test.Fail()
		}

	}

	for iter := 0; iter < 1000; iter++ {
		v := uint64((1 + iter) << 60)

		truncated := uint64(int64(v) >> 16)
		s0, s1, s2 := ShareRSS128(v, bPRG)

		// Test that Additive shares are generated correctly
		if recoverRSS128(s0, s1, s2) != v {
			fmt.Printf("TestRSSTruncate128 failed (test 3, before truncate): got %d but should be %d\n",
				recoverRSS128(s0, s1, s2), v)
			test.Fail()
			panic("FAIL")
		}

		// Test that truncation works correctly
		a0, a1, a2 := truncateRSSToAdditive128(s0, s1, s2, decimals, bPRG)
		t0, t1, t2 := AdditiveToRSS128(a0, a1, a2, bPRG)
		recovered := recoverRSS128(t0, t1, t2)

		if !(recovered == truncated) {
			fmt.Printf("Truncating %d by %d digits: should get %d\n", v, decimals, truncated)
			fmt.Printf("TestRSSTruncate128 failed (test 3, after truncate): got %d but should be %d\n",
				recovered, truncated)
			test.Fail()
			panic("FAIL")
		}

	}

	for iter := 0; iter < 1000; iter++ {
		v := uint64((1 + iter) << 60)
		v = -v

		truncated := uint64(int64(v) >> 16)
		s0, s1, s2 := ShareRSS128(v, bPRG)

		// Test that Additive shares are generated correctly
		if recoverRSS128(s0, s1, s2) != v {
			fmt.Printf("TestRSSTruncate128 failed (test 4, before truncate): got %d but should be %d\n",
				recoverRSS128(s0, s1, s2), v)
			test.Fail()
			panic("FAIL")
		}

		// Test that truncation works correctly
		a0, a1, a2 := truncateRSSToAdditive128(s0, s1, s2, decimals, bPRG)
		t0, t1, t2 := AdditiveToRSS128(a0, a1, a2, bPRG)
		recovered := recoverRSS128(t0, t1, t2)

		if !(recovered == truncated) {
			fmt.Printf("Truncating %d by %d digits: should get %d\n", v, decimals, truncated)
			fmt.Printf("TestRSSTruncate128 failed (test 4, after truncate): got %d but should be %d\n",
				recovered, truncated)
			test.Fail()
			panic("FAIL")
		}

	}

	// In this test: generate deliberately bad shares (i.e., that overflow) by sharing x into (-1, x+1)
	for iter := 0; iter < 1000; iter++ {
		v := uint64((1 + iter) * 23487)
		truncated := uint64(int64(v) >> 16)

		zero := *MakeUint128(0, 0)
		minusOne := *MakeUint128(math.MaxUint64, math.MaxUint64)
		v_big := *ToUint128(v)
		v_big.AddOneInPlace()

		s0 := &Share128{First: minusOne, Second: zero}
		s1 := &Share128{First: v_big, Second: minusOne}
		s2 := &Share128{First: zero, Second: v_big}

		// Test that Additive shares are generated correctly
		if recoverRSS128(s0, s1, s2) != v {
			fmt.Printf("TestRSSTruncate128 failed (test 5, before truncate): got %d but should be %d\n",
				recoverRSS128(s0, s1, s2), v)
			test.Fail()
			panic("FAIL")
		}

		// Test that truncation works correctly
		a0, a1, a2 := truncateRSSToAdditive128(s0, s1, s2, decimals, bPRG)
		t0, t1, t2 := AdditiveToRSS128(a0, a1, a2, bPRG)
		recovered := recoverRSS128(t0, t1, t2)

		if !(recovered == truncated) {
			fmt.Printf("Truncating %d by %d digits: should get %d\n", v, decimals, truncated)
			fmt.Printf("TestRSSTruncate128 failed (test 5, after truncate): got %d but should be %d\n",
				recovered, truncated)
			test.Fail()
			panic("FAIL")
		}

	}
}

func TestRSSMulNeg(test *testing.T) {
	fmt.Println("TestRSSMulNeg")

	seed := RandomPRGKey()
	bPRG := NewBufPRG(NewPRG(seed))

	nRows := 100
	nCols := 100
	matrix := make([]uint64, nRows*nCols)
	vector := make([]uint64, nRows)
	shares0 := make([]Share128, nRows*nCols)
	shares1 := make([]Share128, nRows*nCols)
	shares2 := make([]Share128, nRows*nCols)

	for i := 0; i < nRows; i++ {
		vector[i] = uint64(-i) // To mul by negative value, need to represent as Uint128!
		for j := 0; j < nCols; j++ {
			matrix[i*nCols+j] = uint64(i*nCols + j)
			s0, s1, s2 := ShareRSS128(matrix[i*nCols+j], bPRG)
			shares0[i*nCols+j] = *s0
			shares1[i*nCols+j] = *s1
			shares2[i*nCols+j] = *s2
		}
	}

	// Correctness check
	for i := 0; i < nRows; i++ {
		for j := 0; j < nCols; j++ {
			if recoverRSS128(&shares0[i*nCols+j], &shares1[i*nCols+j], &shares2[i*nCols+j]) != matrix[i*nCols+j] {
				fmt.Printf("Correctness check 1 failed at %d, %d\n", i, j)
				test.Fail()
			}
		}
	}

	// Matrix-vector product between secret-shared matrix and plaintext vector
	vector2_share0 := make([]Share128, nRows)
	vector2_share1 := make([]Share128, nRows)
	vector2_share2 := make([]Share128, nRows)
	vector2_ptxt := make([]uint64, nRows)
	for i := 0; i < nRows; i++ {
		for j := 0; j < nCols; j++ {
			vector2_ptxt[i] += (matrix[i*nCols+j] * vector[j])

			val := ToUint128(vector[j])
			s0 := largePtxtMulRSS128(&shares0[i*nCols+j], val)
			s1 := largePtxtMulRSS128(&shares1[i*nCols+j], val)
			s2 := largePtxtMulRSS128(&shares2[i*nCols+j], val)
			AddRSSInPlace128(&vector2_share0[i], s0)
			AddRSSInPlace128(&vector2_share1[i], s1)
			AddRSSInPlace128(&vector2_share2[i], s2)
		}
	}

	// Correctness check
	for i := 0; i < nRows; i++ {
		if recoverRSS128(&vector2_share0[i], &vector2_share1[i], &vector2_share2[i]) != vector2_ptxt[i] {
			fmt.Printf("Correctness check 2 failed at %d\n", i)
			test.Fail()
		}
	}
}
