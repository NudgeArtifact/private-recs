// Adapted from: https://github.com/dimakogan/dpf-go/blob/master/dpf/dpf_test.go

package multdpf

import (
	"fmt"
	"testing"
	. "private-recs/uint128"
	aes "private-recs/aes"
)

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

		// Make sure that got value replicated secret shares
		if aa2 != cc1 {
			fmt.Println("Not valid share -- 1")
			test.Fail()
		}
		if aa1 != bb2 {
			fmt.Println("Not valid share -- 2")
			test.Fail()
		}
		if bb1 != cc2 {
			fmt.Println("Not valid share -- 3")
			test.Fail()
		}

		// Make sure that resplicated secret shares sum to right value
		sum := aa2 + bb2 + cc2
		if (i != alpha) && (sum != 0) {
			fmt.Printf("Did not sum to 0 at index %d: %d\n", i, sum)
			test.Fail()
		}
		if (i == alpha) && (sum != 1) {
			fmt.Printf("Did not sum to 1 at index %d: %d\n", i, sum)
			test.Fail()
		}
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

                // Make sure that got value replicated secret shares
                if aa2 != cc1 {
                        fmt.Println("Not valid share -- 1")
                        test.Fail()
                }
                if aa1 != bb2 {
                        fmt.Println("Not valid share -- 2")
                        test.Fail()
                }
                if bb1 != cc2 {
                        fmt.Println("Not valid share -- 3")
                        test.Fail()
                }

                // Make sure that resplicated secret shares sum to right value
                sum := Add(&aa2, &bb2)
		sum.AddInPlace(&cc2)
                if (i != alpha) && (!IsZero(sum)) {
                        fmt.Printf("Did not sum to 0 at index %d: %d\n", i, sum)
                        test.Fail()
                }
                if (i == alpha) && (!IsOne(sum)) {
                        fmt.Printf("Did not sum to 1 at index %d: %d\n", i, sum)
                        test.Fail()
                }
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

                // Make sure that got value replicated secret shares
                if aa2 != cc1 {
                        fmt.Println("Not valid share -- 1")
                        test.Fail()
                }
                if aa1 != bb2 {
                        fmt.Println("Not valid share -- 2")
                        test.Fail()
                }
                if bb1 != cc2 {
                        fmt.Println("Not valid share -- 3")
                        test.Fail()
                }

                // Make sure that resplicated secret shares sum to right value
                sum := aa2 + bb2 + cc2
                if (i != alpha) && (sum != 0) {
                        fmt.Printf("Did not sum to 0 at index %d: %d\n", i, sum)
                        test.Fail()
                }
                if (i == alpha) && (sum != 1) {
		        fmt.Printf("~~ Index %d: shares a = (%d, %d), b = (%d, %d), -a-b+1 = (%d, %d)\n", i, aa2, cc1, aa1, bb2, cc2, bb1)
                        fmt.Printf("Did not sum to 1 at index %d: %d\n", i, sum)
                        test.Fail()
                }
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

                // Make sure that got value replicated secret shares
                if aa2 != cc1 {
                        fmt.Println("Not valid share -- 1")
                        test.Fail()
                }
                if aa1 != bb2 {
                        fmt.Println("Not valid share -- 2")
                        test.Fail()
                }
                if bb1 != cc2 {
                        fmt.Println("Not valid share -- 3")
                        test.Fail()
                }

                // Make sure that resplicated secret shares sum to right value
                sum := Add(&aa2, &bb2)
		sum.AddInPlace(&cc2)
                if (i != alpha) && (!IsZero(sum)) {
                        fmt.Printf("Did not sum to 0 at index %d: %d\n", i, sum)
                        test.Fail()
                }
                if (i == alpha) && (!IsOne(sum)) {
                        fmt.Printf("~~ Index %d: shares a = (%d, %d), b = (%d, %d), -a-b+1 = (%d, %d)\n", i, aa2, cc1, aa1, bb2, cc2, bb1)
                        fmt.Printf("Did not sum to 1 at index %d: %d\n", i, sum)
                        test.Fail()
                }
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
		aaa1 := aa[2*i]
		aaa2 := aa[2*i+1]
		bbb1 := bb[2*i]
		bbb2 := bb[2*i+1]
		ccc1 := cc[2*i]
		ccc2 := cc[2*i+1]

	        // Make sure that got value replicated secret shares
                if aaa2 != ccc1 {
                        fmt.Println("Not valid share -- 1")
                        test.Fail()
                }
                if aaa1 != bbb2 {
                        fmt.Println("Not valid share -- 2")
                        test.Fail()
                }
                if bbb1 != ccc2 {
                        fmt.Println("Not valid share -- 3")
                        test.Fail()
                }

                // Make sure that resplicated secret shares sum to right value
                sum := aaa2 + bbb2 + ccc2
                if (i != alpha) && (sum != 0) {
                        fmt.Printf("Did not sum to 0 at index %d: %d\n", i, sum)
                        test.Fail()
                }
                if (i == alpha) && (sum != 1) {
                        fmt.Printf("Did not sum to 1 at index %d: %d\n", i, sum)
                        test.Fail()
                }
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
                aaa1 := aa[2*i]
                aaa2 := aa[2*i+1]
                bbb1 := bb[2*i]
                bbb2 := bb[2*i+1]
                ccc1 := cc[2*i]
                ccc2 := cc[2*i+1]

                // Make sure that got value replicated secret shares
                if aaa2 != ccc1 {
                        fmt.Println("Not valid share -- 1")
                        test.Fail()
                }
                if aaa1 != bbb2 {
                        fmt.Println("Not valid share -- 2")
                        test.Fail()
                }
                if bbb1 != ccc2 {
                        fmt.Println("Not valid share -- 3")
                        test.Fail()
                }

                // Make sure that resplicated secret shares sum to right value
                sum := Add(&aaa2, &bbb2)
		sum.AddInPlace(&ccc2)
                if (i != alpha) && (!IsZero(sum)) {
                        fmt.Printf("Did not sum to 0 at index %d: %d\n", i, sum)
                        test.Fail()
                }
                if (i == alpha) && (!IsOne(sum)) {
                        fmt.Printf("Did not sum to 1 at index %d: %d\n", i, sum)
                        test.Fail()
                }
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
                aaa1 := aa[2*i]
                aaa2 := aa[2*i+1]
                bbb1 := bb[2*i]
                bbb2 := bb[2*i+1]
                ccc1 := cc[2*i]
                ccc2 := cc[2*i+1]

                // Make sure that got value replicated secret shares
                if aaa2 != ccc1 {
                        fmt.Println("Not valid share -- 1")
                        test.Fail()
                }
                if aaa1 != bbb2 {
                        fmt.Println("Not valid share -- 2")
                        test.Fail()
                }
                if bbb1 != ccc2 {
                        fmt.Println("Not valid share -- 3")
                        test.Fail()
                }

                // Make sure that resplicated secret shares sum to right value
                sum := aaa2 + bbb2 + ccc2
                if (i != alpha) && (sum != 0) {
		        fmt.Printf("~~ Index %d: shares a = (%d, %d), b = (%d, %d), -a-b+1 = (%d, %d)\n", i, aaa2, ccc1, aaa1, bbb2, ccc2, bbb1)
                        fmt.Printf("Did not sum to 0 at index %d: %d\n", i, sum)
                        test.Fail()
                }
                if (i == alpha) && (sum != 1) {
		        fmt.Printf("~~ Index %d: shares a = (%d, %d), b = (%d, %d), -a-b+1 = (%d, %d)\n", i, aaa2, ccc1, aaa1, bbb2, ccc2, bbb1)
                        fmt.Printf("Did not sum to 1 at index %d: %d\n", i, sum)
                        test.Fail()
                }
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
                aaa1 := aa[2*i]
                aaa2 := aa[2*i+1]
                bbb1 := bb[2*i]
                bbb2 := bb[2*i+1]
                ccc1 := cc[2*i]
                ccc2 := cc[2*i+1]

                // Make sure that got value replicated secret shares
                if aaa2 != ccc1 {
                        fmt.Println("Not valid share -- 1")
                        test.Fail()
                }
                if aaa1 != bbb2 {
                        fmt.Println("Not valid share -- 2")
                        test.Fail()
                }
                if bbb1 != ccc2 {
                        fmt.Println("Not valid share -- 3")
                        test.Fail()
                }

                // Make sure that resplicated secret shares sum to right value
                sum := Add(&aaa2, &bbb2)
		sum.AddInPlace(&ccc2)
                if (i != alpha) && (!IsZero(sum)) {
                        fmt.Printf("~~ Index %d: shares a = (%d, %d), b = (%d, %d), -a-b+1 = (%d, %d)\n", i, aaa2, ccc1, aaa1, bbb2, ccc2, bbb1)
                        fmt.Printf("Did not sum to 0 at index %d: %d\n", i, sum)
                        test.Fail()
                }
                if (i == alpha) && (!IsOne(sum)) {
                        fmt.Printf("~~ Index %d: shares a = (%d, %d), b = (%d, %d), -a-b+1 = (%d, %d)\n", i, aaa2, ccc1, aaa1, bbb2, ccc2, bbb1)
                        fmt.Printf("Did not sum to 1 at index %d: %d\n", i, sum)
                        test.Fail()
                }
        }
}
