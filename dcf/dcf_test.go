// Adapted from: https://github.com/dimakogan/dpf-go/blob/master/dpf/dpf_test.go

package dcf

import (
	"fmt"
	aes "github.com/NudgeArtifact/private-recs/aes"
	. "github.com/NudgeArtifact/private-recs/rand"
	. "github.com/NudgeArtifact/private-recs/uint128"
	"testing"
)

func BenchmarkEvalFull64(bench *testing.B) {
	logN := uint64(28)
	a, _ := Gen64(0, logN, true)
	bench.ResetTimer()
	for i := 0; i < bench.N; i++ {
		EvalFull64(a, logN, 0)
	}
}

func BenchmarkEvalFull128(bench *testing.B) {
	logN := uint64(28)
	a, _ := Gen128(0, logN, true)
	bench.ResetTimer()
	for i := 0; i < bench.N; i++ {
		EvalFull128(a, logN, 0)
	}
}

func BenchmarkXor16(bench *testing.B) {
	a := new(block)
	b := new(block)
	c := new(block)
	for i := 0; i < bench.N; i++ {
		aes.Xor16(&c[0], &b[0], &a[0])
	}
}

func BenchmarkGen64(bench *testing.B) {
	logN := uint64(18)
	a, b := Gen64(0, logN, true)
	szA := float64(len(a))
	szB := float64(len(b))
	fmt.Printf("Size of DCF key (N=2^%d, 64-bit outputs): %f KB, %f KB, %f KB\n",
		logN, szA/1024.0, szB/1024.0, float64(ByteLen(64, logN, false))/1024.0)

	bench.ResetTimer()
	for i := 0; i < bench.N; i++ {
		Gen64(0, logN, true)
	}
}

func BenchmarkGen128(bench *testing.B) {
	logN := uint64(28)
	a, b := Gen128(0, logN, true)
	szA := float64(len(a))
	szB := float64(len(b))
	fmt.Printf("Size of DCF key (N=2^%d, 128-bit outputs): %f KB, %f KB -- if were small: %f KB\n",
		logN, szA/1024.0, szB/1024.0, float64(ByteLen(128, logN, true))/1024.0)

	bench.ResetTimer()
	for i := 0; i < bench.N; i++ {
		Gen128(0, logN, true)
	}
}

func TestEval64(test *testing.T) {
	fmt.Println("TestEval64")
	logN := uint64(8)
	alpha := uint64(123)

	// First: Test DCF for >=
	a, b := Gen64(alpha, logN, true)
	for i := uint64(0); i < (uint64(1) << logN); i++ {
		aa := Eval64(a, i, logN, 0)
		bb := Eval64(b, i, logN, 1)

		// Make sure that secret shares sum to right value
		sum := aa + bb
		if (i < alpha) && (sum != 0) {
			fmt.Printf("Did not sum to 0 at index %d: %d + %d = %d\n", i, aa, bb, sum)
			test.Fail()
		}
		if (i >= alpha) && (sum != 1) {
			fmt.Printf("Did not sum to 1 at index %d: %d + %d = %d\n", i, aa, bb, sum)
			test.Fail()
		}
	}

	// Second: Test DCF for >
	a, b = Gen64(alpha, logN, false)
	for i := uint64(0); i < (uint64(1) << logN); i++ {
		aa := Eval64(a, i, logN, 0)
		bb := Eval64(b, i, logN, 1)

		// Make sure that secret shares sum to right value
		sum := aa + bb
		if (i <= alpha) && (sum != 0) {
			fmt.Printf("Did not sum to 0 at index %d: %d + %d = %d\n", i, aa, bb, sum)
			test.Fail()
		}
		if (i > alpha) && (sum != 1) {
			fmt.Printf("Did not sum to 1 at index %d: %d + %d = %d\n", i, aa, bb, sum)
			test.Fail()
		}
	}
}

func TestEval128(test *testing.T) {
	fmt.Println("TestEval128")
	logN := uint64(12)
	alpha := uint64(123)
	a, b := Gen128(alpha, logN, true)
	for i := uint64(0); i < (uint64(1) << logN); i++ {
		aa := Eval128(a, i, logN, 0)
		bb := Eval128(b, i, logN, 1)

		// Make sure that secret shares sum to right value
		sum := Add(&aa, &bb)
		if (i < alpha) && (!IsZero(sum)) {
			fmt.Printf("Did not sum to 0 at index %d: %d\n", i, sum)
			test.Fail()
		}
		if (i >= alpha) && (!IsOne(sum)) {
			fmt.Printf("Did not sum to 1 at index %d: %d\n", i, sum)
			test.Fail()
		}
	}

	a, b = Gen128(alpha, logN, false)
	for i := uint64(0); i < (uint64(1) << logN); i++ {
		aa := Eval128(a, i, logN, 0)
		bb := Eval128(b, i, logN, 1)

		// Make sure that secret shares sum to right value
		sum := Add(&aa, &bb)
		if (i <= alpha) && (!IsZero(sum)) {
			fmt.Printf("Did not sum to 0 at index %d: %d\n", i, sum)
			test.Fail()
		}
		if (i > alpha) && (!IsOne(sum)) {
			fmt.Printf("Did not sum to 1 at index %d: %d\n", i, sum)
			test.Fail()
		}
	}
}

func TestEvalLargeInput128(test *testing.T) {
	fmt.Println("TestEvalLargeInput128")
	logN := uint64(128)
	alpha := MakeUint128(123, 0)
	a, b := GenLargeInput128(alpha, logN, true)

	seed := RandomPRGKey()
	bPRG := NewBufPRG(NewPRG(seed))

	for iter := 0; iter < 100; iter++ {
		var evalPoint *Uint128
		if iter > 0 {
			hi, lo := bPRG.TwoUint64()
			evalPoint = MakeUint128(hi, lo)
		} else {
			evalPoint = MakeUint128(123, 0)
		}

		aa := EvalLargeInput128(a, evalPoint, logN, 0)
		bb := EvalLargeInput128(b, evalPoint, logN, 1)

		// Make sure that secret shares sum to right value
		sum := Add(&aa, &bb)

		if alpha.GreaterThan(evalPoint) && (!IsZero(sum)) {
			fmt.Printf("Did not sum to 0 at index %d: %d\n", evalPoint, sum)
			test.Fail()
		}
		if (!alpha.GreaterThan(evalPoint)) && (!IsOne(sum)) {
			fmt.Printf("Did not sum to 1 at index %d: %d\n", evalPoint, sum)
			test.Fail()
		}
	}

	for iter := 0; iter < 100; iter++ {
		var evalPoint *Uint128
		hi, lo := bPRG.TwoUint64()
		hi = hi % 123 // force to always be smaller!
		evalPoint = MakeUint128(hi, lo)

		aa := EvalLargeInput128(a, evalPoint, logN, 0)
		bb := EvalLargeInput128(b, evalPoint, logN, 1)

		// Make sure that secret shares sum to right value
		sum := Add(&aa, &bb)

		if alpha.GreaterThan(evalPoint) && (!IsZero(sum)) {
			fmt.Printf("Did not sum to 0 at index %d: %d\n", evalPoint, sum)
			fmt.Printf(" index: ")
			evalPoint.Print()
			fmt.Printf(" sum: ")
			sum.Print()
			test.Fail()
			panic("FAIL")
		}
		if (!alpha.GreaterThan(evalPoint)) && (!IsOne(sum)) {
			fmt.Printf("Did not sum to 1 at index %d: %d\n", evalPoint, sum)
			fmt.Printf(" index: ")
			evalPoint.Print()
			fmt.Printf(" sum: ")
			sum.Print()
			test.Fail()
			panic("FAIL")
		}
	}
}

func TestEvalShort64(test *testing.T) {
	fmt.Println("TestEvalShort64")
	logN := uint64(3)
	alpha := uint64(1)
	a, b := Gen64(alpha, logN, true)
	for i := uint64(0); i < (uint64(1) << logN); i++ {
		aa := Eval64(a, i, logN, 0)
		bb := Eval64(b, i, logN, 1)

		sum := aa + bb
		if (i < alpha) && (sum != 0) {
			fmt.Printf("Did not sum to 0 at index %d: %d\n", i, sum)
			test.Fail()
		}
		if (i >= alpha) && (sum != 1) {
			fmt.Printf("Did not sum to 1 at index %d: %d\n", i, sum)
			test.Fail()
		}
	}

	a, b = Gen64(alpha, logN, false)
	for i := uint64(0); i < (uint64(1) << logN); i++ {
		aa := Eval64(a, i, logN, 0)
		bb := Eval64(b, i, logN, 1)

		sum := aa + bb
		if (i <= alpha) && (sum != 0) {
			fmt.Printf("Did not sum to 0 at index %d: %d\n", i, sum)
			test.Fail()
		}
		if (i > alpha) && (sum != 1) {
			fmt.Printf("Did not sum to 1 at index %d: %d\n", i, sum)
			test.Fail()
		}
	}
}

func TestEvalShort128(test *testing.T) {
	fmt.Println("TestEvalShort128")
	logN := uint64(3)
	alpha := uint64(1)
	a, b := Gen128(alpha, logN, true)
	for i := uint64(0); i < (uint64(1) << logN); i++ {
		aa := Eval128(a, i, logN, 0)
		bb := Eval128(b, i, logN, 1)

		sum := Add(&aa, &bb)
		if (i < alpha) && (!IsZero(sum)) {
			fmt.Printf("Did not sum to 0 at index %d: %d\n", i, sum)
			test.Fail()
		}
		if (i >= alpha) && (!IsOne(sum)) {
			fmt.Printf("Did not sum to 1 at index %d: %d\n", i, sum)
			test.Fail()
		}
	}

	a, b = Gen128(alpha, logN, false)
	for i := uint64(0); i < (uint64(1) << logN); i++ {
		aa := Eval128(a, i, logN, 0)
		bb := Eval128(b, i, logN, 1)

		sum := Add(&aa, &bb)
		if (i <= alpha) && (!IsZero(sum)) {
			fmt.Printf("Did not sum to 0 at index %d: %d\n", i, sum)
			test.Fail()
		}
		if (i > alpha) && (!IsOne(sum)) {
			fmt.Printf("Did not sum to 1 at index %d: %d\n", i, sum)
			test.Fail()
		}
	}
}

func TestEvalFull64(test *testing.T) {
	fmt.Println("TestEvalFull64")
	logN := uint64(9)
	alpha := uint64(128)
	a, b := Gen64(alpha, logN, true)
	aa := EvalFull64(a, logN, 0)
	bb := EvalFull64(b, logN, 1)

	for i := uint64(0); i < (uint64(1) << logN); i++ {
		aaa := aa[i]
		bbb := bb[i]

		sum := aaa + bbb
		if (i < alpha) && (sum != 0) {
			fmt.Printf("Did not sum to 0 at index %d: %d\n", i, sum)
			test.Fail()
		}
		if (i >= alpha) && (sum != 1) {
			fmt.Printf("Did not sum to 1 at index %d: %d\n", i, sum)
			test.Fail()
		}
	}

	a, b = Gen64(alpha, logN, false)
	aa = EvalFull64(a, logN, 0)
	bb = EvalFull64(b, logN, 1)

	for i := uint64(0); i < (uint64(1) << logN); i++ {
		aaa := aa[i]
		bbb := bb[i]

		sum := aaa + bbb
		if (i <= alpha) && (sum != 0) {
			fmt.Printf("Did not sum to 0 at index %d: %d\n", i, sum)
			test.Fail()
		}
		if (i > alpha) && (sum != 1) {
			fmt.Printf("Did not sum to 1 at index %d: %d\n", i, sum)
			test.Fail()
		}
	}
}

func TestEvalFull128(test *testing.T) {
	fmt.Println("TestEvalFull128")
	logN := uint64(9)
	alpha := uint64(128)
	a, b := Gen128(alpha, logN, true)
	aa := EvalFull128(a, logN, 0)
	bb := EvalFull128(b, logN, 1)

	for i := uint64(0); i < (uint64(1) << logN); i++ {
		aaa := aa[i]
		bbb := bb[i]

		sum := Add(&aaa, &bbb)
		if (i < alpha) && (!IsZero(sum)) {
			fmt.Printf("Did not sum to 0 at index %d: %d\n", i, sum)
			test.Fail()
		}
		if (i >= alpha) && (!IsOne(sum)) {
			fmt.Printf("Did not sum to 1 at index %d: %d\n", i, sum)
			test.Fail()
		}
	}

	a, b = Gen128(alpha, logN, false)
	aa = EvalFull128(a, logN, 0)
	bb = EvalFull128(b, logN, 1)

	for i := uint64(0); i < (uint64(1) << logN); i++ {
		aaa := aa[i]
		bbb := bb[i]

		sum := Add(&aaa, &bbb)
		if (i <= alpha) && (!IsZero(sum)) {
			fmt.Printf("Did not sum to 0 at index %d: %d\n", i, sum)
			test.Fail()
		}
		if (i > alpha) && (!IsOne(sum)) {
			fmt.Printf("Did not sum to 1 at index %d: %d\n", i, sum)
			test.Fail()
		}
	}
}

func TestEvalFullShort64(test *testing.T) {
	fmt.Println("TestEvalFullShort64")
	logN := uint64(3)
	alpha := uint64(1)
	a, b := Gen64(alpha, logN, true)
	aa := EvalFull64(a, logN, 0)
	bb := EvalFull64(b, logN, 1)

	for i := uint64(0); i < (uint64(1) << logN); i++ {
		aaa := aa[i]
		bbb := bb[i]

		sum := aaa + bbb
		if (i < alpha) && (sum != 0) {
			fmt.Printf("Did not sum to 0 at index %d: %d\n", i, sum)
			test.Fail()
		}
		if (i >= alpha) && (sum != 1) {
			fmt.Printf("Did not sum to 1 at index %d: %d\n", i, sum)
			test.Fail()
		}
	}

	a, b = Gen64(alpha, logN, false)
	aa = EvalFull64(a, logN, 0)
	bb = EvalFull64(b, logN, 1)

	for i := uint64(0); i < (uint64(1) << logN); i++ {
		aaa := aa[i]
		bbb := bb[i]

		sum := aaa + bbb
		if (i <= alpha) && (sum != 0) {
			fmt.Printf("Did not sum to 0 at index %d: %d\n", i, sum)
			test.Fail()
		}
		if (i > alpha) && (sum != 1) {
			fmt.Printf("Did not sum to 1 at index %d: %d\n", i, sum)
			test.Fail()
		}
	}
}

func TestEvalFullShort128(test *testing.T) {
	fmt.Println("TestEvalFullShort128")
	logN := uint64(3)
	alpha := uint64(1)
	a, b := Gen128(alpha, logN, true)
	aa := EvalFull128(a, logN, 0)
	bb := EvalFull128(b, logN, 1)

	for i := uint64(0); i < (uint64(1) << logN); i++ {
		aaa := aa[i]
		bbb := bb[i]

		sum := Add(&aaa, &bbb)
		if (i < alpha) && (!IsZero(sum)) {
			fmt.Printf("Did not sum to 0 at index %d: %d\n", i, sum)
			test.Fail()
		}
		if (i >= alpha) && (!IsOne(sum)) {
			fmt.Printf("Did not sum to 1 at index %d: %d\n", i, sum)
			test.Fail()
		}
	}

	a, b = Gen128(alpha, logN, false)
	aa = EvalFull128(a, logN, 0)
	bb = EvalFull128(b, logN, 1)

	for i := uint64(0); i < (uint64(1) << logN); i++ {
		aaa := aa[i]
		bbb := bb[i]

		sum := Add(&aaa, &bbb)
		if (i <= alpha) && (!IsZero(sum)) {
			fmt.Printf("Did not sum to 0 at index %d: %d\n", i, sum)
			test.Fail()
		}
		if (i > alpha) && (!IsOne(sum)) {
			fmt.Printf("Did not sum to 1 at index %d: %d\n", i, sum)
			test.Fail()
		}
	}
}

func TestEvalSmallOutput128(test *testing.T) {
	fmt.Println("TestEvalSmallOutput128")
	logN := uint64(50)
	alpha := uint64(123)
	a, b := GenSmallOutput128(alpha, logN, true)

	seed := RandomPRGKey()
	bPRG := NewBufPRG(NewPRG(seed))

	for iter := 0; iter < 100; iter++ {
		evalPoint := bPRG.Uint64()
		if iter == 0 {
			evalPoint = 123
		}

		aa := EvalSmallOutput128(a, evalPoint, logN, 0)
		bb := EvalSmallOutput128(b, evalPoint, logN, 1)

		// Make sure that secret shares sum to right value
		sum := Add(&aa, &bb)

		if (alpha > evalPoint) && (!IsZero(sum)) {
			fmt.Printf("Did not sum to 0 at index %d: %d\n", evalPoint, sum)
			test.Fail()
			panic("FAIL")
		}
		if (alpha <= evalPoint) && (!IsOne(sum)) && (!IsNegativeOne(sum)) {
			fmt.Printf("Did not sum to +/- 1 at index %d: %d\n", evalPoint, sum)
			test.Fail()
			panic("FAIL")
		}
	}

	for iter := 0; iter < 100; iter++ {
		evalPoint := bPRG.Uint64() % 123 // force to always be smaller

		aa := EvalSmallOutput128(a, evalPoint, logN, 0)
		bb := EvalSmallOutput128(b, evalPoint, logN, 1)

		// Make sure that secret shares sum to right value
		sum := Add(&aa, &bb)

		if (alpha > evalPoint) && (!IsZero(sum)) {
			fmt.Printf("Did not sum to 0 at index %d: %d\n", evalPoint, sum)
			fmt.Printf(" index: %d\n", evalPoint)
			fmt.Printf(" sum: %d\n", ToUint64(sum))
			test.Fail()
			panic("FAIL")
		}
		if (alpha <= evalPoint) && (!IsOne(sum)) && (!IsNegativeOne(sum)) {
			fmt.Printf("Did not sum to +/-1 at index %d: %d\n", evalPoint, sum)
			fmt.Printf(" index: %d\n", evalPoint)
			fmt.Printf(" sum: %d\n", sum)
			test.Fail()
			panic("FAIL")
		}
	}

	// Change leq, repeat
	a, b = GenSmallOutput128(alpha, logN, false)

	for iter := 0; iter < 100; iter++ {
		evalPoint := bPRG.Uint64()
		if iter == 0 {
			evalPoint = 123
		}

		aa := EvalSmallOutput128(a, evalPoint, logN, 0)
		bb := EvalSmallOutput128(b, evalPoint, logN, 1)

		// Make sure that secret shares sum to right value
		sum := Add(&aa, &bb)

		if (alpha >= evalPoint) && (!IsZero(sum)) {
			fmt.Printf("Did not sum to 0 at index %d: %d\n", evalPoint, sum)
			test.Fail()
			panic("FAIL")
		}
		if (alpha < evalPoint) && (!IsOne(sum)) && (!IsNegativeOne(sum)) {
			fmt.Printf("Did not sum to +/- 1 at index %d: %d\n", evalPoint, sum)
			test.Fail()
			panic("FAIL")
		}
	}

	for iter := 0; iter < 100; iter++ {
		evalPoint := bPRG.Uint64() % 123 // force to always be smaller

		aa := EvalSmallOutput128(a, evalPoint, logN, 0)
		bb := EvalSmallOutput128(b, evalPoint, logN, 1)

		// Make sure that secret shares sum to right value
		sum := Add(&aa, &bb)

		if (alpha >= evalPoint) && (!IsZero(sum)) {
			fmt.Printf("Did not sum to 0 at index %d: %d\n", evalPoint, sum)
			fmt.Printf(" index: %d\n", evalPoint)
			fmt.Printf(" sum: %d\n", sum)
			test.Fail()
			panic("FAIL")
		}
		if (alpha < evalPoint) && (!IsOne(sum)) && (!IsNegativeOne(sum)) {
			fmt.Printf("Did not sum to +/-1 at index %d: %d\n", evalPoint, sum)
			fmt.Printf(" index: %d\n", evalPoint)
			fmt.Printf(" sum: %d\n", sum)
			test.Fail()
			panic("FAIL")
		}
	}
}
