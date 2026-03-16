// Adapted from: https://github.com/dimakogan/dpf-go/blob/master/dpf/dpf_test.go

package multdpf

import (
	"fmt"
	"testing"

	aes "github.com/NudgeArtifact/private-recs/aes"
	. "github.com/NudgeArtifact/private-recs/uint128"
)

// checkRSS64 verifies that (aa1,aa2), (bb1,bb2), (cc1,cc2) form valid RSS
// shares of f(i) = [i == alpha] for 64-bit outputs.
func checkRSS64(test *testing.T, i, alpha uint64, aa1, aa2, bb1, bb2, cc1, cc2 uint64) {
	// Overlapping shares must match across neighbouring servers.
	if aa2 != cc1 {
		test.Errorf("index %d: aa2 (%d) != cc1 (%d)", i, aa2, cc1)
	}
	if aa1 != bb2 {
		test.Errorf("index %d: aa1 (%d) != bb2 (%d)", i, aa1, bb2)
	}
	if bb1 != cc2 {
		test.Errorf("index %d: bb1 (%d) != cc2 (%d)", i, bb1, cc2)
	}

	// The three "second" shares must sum to f(i).
	sum := aa2 + bb2 + cc2
	if i == alpha && sum != 1 {
		test.Errorf("index %d (alpha): shares sum to %d, want 1", i, sum)
	}
	if i != alpha && sum != 0 {
		test.Errorf("index %d: shares sum to %d, want 0", i, sum)
	}
}

// checkRSS128 is like checkRSS64 but for 128-bit outputs.
func checkRSS128(test *testing.T, i, alpha uint64, aa1, aa2, bb1, bb2, cc1, cc2 Uint128) {
	if aa2 != cc1 {
		test.Errorf("index %d: aa2 != cc1", i)
	}
	if aa1 != bb2 {
		test.Errorf("index %d: aa1 != bb2", i)
	}
	if bb1 != cc2 {
		test.Errorf("index %d: bb1 != cc2", i)
	}

	sum := Add(&aa2, &bb2)
	sum.AddInPlace(&cc2)
	if i == alpha && !IsOne(sum) {
		test.Errorf("index %d (alpha): shares do not sum to 1", i)
	}
	if i != alpha && !IsZero(sum) {
		test.Errorf("index %d: shares do not sum to 0", i)
	}
}

func BenchmarkEvalFull64(bench *testing.B) {
	logN := uint64(28)
	a, _, _ := Gen(0, logN, 64)
	bench.ResetTimer()
	for i := 0; i < bench.N; i++ {
		EvalFull64(a, logN, 0)
	}
}

func BenchmarkEvalFull128(bench *testing.B) {
	logN := uint64(28)
	a, _, _ := Gen(0, logN, 128)
	bench.ResetTimer()
	for i := 0; i < bench.N; i++ {
		EvalFull128(a, logN, 0)
	}
}

func BenchmarkXor16(bench *testing.B) {
	a := new(Block)
	b := new(Block)
	c := new(Block)
	for i := 0; i < bench.N; i++ {
		aes.Xor16(&c[0], &b[0], &a[0])
	}
}

func BenchmarkGen64(bench *testing.B) {
	logN := uint64(18)
	a, b, c := Gen(0, logN, 64)
	fmt.Printf("Size of DPF key (N=2^%d, 64-bit outputs): %f KB, %f KB, %f KB\n",
		logN, DPFSizeKB(a), DPFSizeKB(b), DPFSizeKB(c))

	a, b, c = Gen(0, logN, 128)
	fmt.Printf("Size of DPF key (N=2^%d, 128-bit outputs): %f KB, %f KB, %f KB\n",
		logN, DPFSizeKB(a), DPFSizeKB(b), DPFSizeKB(c))

	bench.ResetTimer()
	for i := 0; i < bench.N; i++ {
		Gen(0, logN, 64)
	}
}

func BenchmarkGen128(bench *testing.B) {
	logN := uint64(28)
	a, b, c := Gen(0, logN, 128)
	fmt.Printf("Size of DPF key (N=2^%d, 128-bit outputs): %f KB, %f KB, %f KB\n",
		logN, DPFSizeKB(a), DPFSizeKB(b), DPFSizeKB(c))

	bench.ResetTimer()
	for i := 0; i < bench.N; i++ {
		Gen(0, logN, 128)
	}
}

func TestEval64(test *testing.T) {
	fmt.Println("TestEval64")
	logN := uint64(8)
	alpha := uint64(123)
	a, b, c := Gen(alpha, logN, 64)
	for i := uint64(0); i < (uint64(1) << logN); i++ {
		aa1, aa2 := Eval64(a, i, logN, 0)
		bb1, bb2 := Eval64(b, i, logN, 1)
		cc1, cc2 := Eval64(c, i, logN, 2)
		checkRSS64(test, i, alpha, aa1, aa2, bb1, bb2, cc1, cc2)
	}
}

func TestEval128(test *testing.T) {
	fmt.Println("TestEval128")
	logN := uint64(8)
	alpha := uint64(123)
	a, b, c := Gen(alpha, logN, 128)
	for i := uint64(0); i < (uint64(1) << logN); i++ {
		aa1, aa2 := Eval128(a, i, logN, 0)
		bb1, bb2 := Eval128(b, i, logN, 1)
		cc1, cc2 := Eval128(c, i, logN, 2)
		checkRSS128(test, i, alpha, aa1, aa2, bb1, bb2, cc1, cc2)
	}
}

func TestEvalShort64(test *testing.T) {
	fmt.Println("TestEvalShort64")
	logN := uint64(3)
	alpha := uint64(1)
	a, b, c := Gen(alpha, logN, 64)
	for i := uint64(0); i < (uint64(1) << logN); i++ {
		aa1, aa2 := Eval64(a, i, logN, 0)
		bb1, bb2 := Eval64(b, i, logN, 1)
		cc1, cc2 := Eval64(c, i, logN, 2)
		checkRSS64(test, i, alpha, aa1, aa2, bb1, bb2, cc1, cc2)
	}
}

func TestEvalShort128(test *testing.T) {
	fmt.Println("TestEvalShort128")
	logN := uint64(3)
	alpha := uint64(1)
	a, b, c := Gen(alpha, logN, 128)
	for i := uint64(0); i < (uint64(1) << logN); i++ {
		aa1, aa2 := Eval128(a, i, logN, 0)
		bb1, bb2 := Eval128(b, i, logN, 1)
		cc1, cc2 := Eval128(c, i, logN, 2)
		checkRSS128(test, i, alpha, aa1, aa2, bb1, bb2, cc1, cc2)
	}
}

func TestEvalFull64(test *testing.T) {
	fmt.Println("TestEvalFull64")
	logN := uint64(9)
	alpha := uint64(128)
	a, b, c := Gen(alpha, logN, 64)
	aa := EvalFull64(a, logN, 0)
	bb := EvalFull64(b, logN, 1)
	cc := EvalFull64(c, logN, 2)

	for i := uint64(0); i < (uint64(1) << logN); i++ {
		checkRSS64(test, i, alpha,
			aa[2*i], aa[2*i+1],
			bb[2*i], bb[2*i+1],
			cc[2*i], cc[2*i+1])
	}
}

func TestEvalFull128(test *testing.T) {
	fmt.Println("TestEvalFull128")
	logN := uint64(9)
	alpha := uint64(128)
	a, b, c := Gen(alpha, logN, 128)
	aa := EvalFull128(a, logN, 0)
	bb := EvalFull128(b, logN, 1)
	cc := EvalFull128(c, logN, 2)

	for i := uint64(0); i < (uint64(1) << logN); i++ {
		checkRSS128(test, i, alpha,
			aa[2*i], aa[2*i+1],
			bb[2*i], bb[2*i+1],
			cc[2*i], cc[2*i+1])
	}
}

func TestEvalFullShort64(test *testing.T) {
	fmt.Println("TestEvalFullShort64")
	logN := uint64(3)
	alpha := uint64(1)
	a, b, c := Gen(alpha, logN, 64)
	aa := EvalFull64(a, logN, 0)
	bb := EvalFull64(b, logN, 1)
	cc := EvalFull64(c, logN, 2)

	for i := uint64(0); i < (uint64(1) << logN); i++ {
		checkRSS64(test, i, alpha,
			aa[2*i], aa[2*i+1],
			bb[2*i], bb[2*i+1],
			cc[2*i], cc[2*i+1])
	}
}

func TestEvalFullShort128(test *testing.T) {
	fmt.Println("TestEvalFullShort128")
	logN := uint64(3)
	alpha := uint64(1)
	a, b, c := Gen(alpha, logN, 128)
	aa := EvalFull128(a, logN, 0)
	bb := EvalFull128(b, logN, 1)
	cc := EvalFull128(c, logN, 2)

	for i := uint64(0); i < (uint64(1) << logN); i++ {
		checkRSS128(test, i, alpha,
			aa[2*i], aa[2*i+1],
			bb[2*i], bb[2*i+1],
			cc[2*i], cc[2*i+1])
	}
}
