package protocol

import (
	"fmt"
	"runtime"
	"runtime/pprof"
	"strconv"
	"sync"
	"testing"

	"github.com/NudgeArtifact/private-recs/net"
	. "github.com/NudgeArtifact/private-recs/params"
	. "github.com/NudgeArtifact/private-recs/share"
)

func BenchmarkNetflix(b *testing.B) {
	fmt.Println("BenchNetflix")
	params := FromJSON("../params/full_params.json")
	U := ReadMatrixFromFile("../share/test_matrix/netflix_test_matrix.csv")
	fmt.Printf("Got matrix: %d by %d\n", U.NRows(), U.NCols())

	pool := InitPRGPoolFromMatrix(U)
	U0, U1, U2 := ShareMatrixRSS(U, pool)
	fmt.Println("Shared matrix")
	runtime.GC()

	var wg0, wg1, wg2 sync.WaitGroup
	wg0.Add(1)
	wg1.Add(1)
	wg2.Add(1)

	config := &net.NetworkConfig{
		Ports: [][][]string{
			[][]string{[]string{"", ""}, []string{":8881", ":8882"}, []string{":8883", ":8884"}},
			[][]string{[]string{":8885", ":8886"}, []string{"", ""}, []string{":8887", ":8888"}},
			[][]string{[]string{":8889", ":8890"}, []string{":8891", ":8892"}, []string{"", ""}},
		},
		IPAddrs: []string{"127.0.0.1", "127.0.0.1", "127.0.0.1"},
	}
	networks := make([]*net.Network, 3)
	done := make(chan bool)

	for i := 0; i < 3; i++ {
		go func(idx int) {
			networks[idx] = net.NewTCPNetwork(idx, config)
			done <- true
		}(i)
	}

	for i := 0; i < 3; i++ {
		<-done
	}

	go func() {
		defer wg0.Done()
		s0 := LaunchServerFromMatrixAndNetwork(0, networks[0], U0)
		runtime.GC()

		s0.PowerIteration(params, true, true)
		WriteMatrixToS3(s0.Item_emb, "netflix_local_items.csv")
	}()

	go func() {
		defer wg1.Done()
		s1 := LaunchServerFromMatrixAndNetwork(1, networks[1], U1)
		runtime.GC()

		s1.PowerIteration(params, true, true)
	}()

	go func() {
		defer wg2.Done()
		s2 := LaunchServerFromMatrixAndNetwork(2, networks[2], U2)
		runtime.GC()

		s2.PowerIteration(params, true, true)
	}()

	wg0.Wait()
	wg1.Wait()
	wg2.Wait()
}

func runPowerIt(U *Matrix[uint64], params *PowerItParams, shareName string, verifyZeroOne bool) bool {
	pool := InitPRGPoolFromMatrix(U)
	U0, U1, U2 := ShareMatrixRSS(U, pool)
	fmt.Println("Shared matrix")

	WriteMatrixShareToFile(U0, shareName+"mat0.csv")
	WriteMatrixShareToFile(U1, shareName+"mat1.csv")
	WriteMatrixShareToFile(U2, shareName+"mat2.csv")

	var wg sync.WaitGroup
	wg.Add(3)

	for i := 0; i <= 2; i++ {
		go func(id int) {
			file := shareName + "mat" + strconv.Itoa(id) + ".csv"
			s := LaunchServerFromFile(id, "127.0.0.1", "127.0.0.1", "127.0.0.1", file)

			if verifyZeroOne {
				if result := s.VerifyZeroOneEntries(); !result {
					panic("VerifyZeroOneEntries check failed.")
				}
			}

			s.PowerIteration(params, true, true)

			if id == 0 {
				WriteMatrixToS3(s.Item_emb, shareName+"items.csv")
			}

			wg.Done()
			s.Teardown()
		}(i)
	}

	wg.Wait()

	B := ReadMatrixFromS3(shareName + "items.csv")
	A := MatrixMul(U, B.Transpose())
	C := MatrixMul(A, B)
	MatrixSignedRoundInPlace(C, (1 << (params.N_decimals * 2)))

	success := C.Equals(U)

	if (U.NRows() <= 10) && (!success) {
		fmt.Printf("SVD on matrix U: \n")
		Print(U)

		fmt.Printf("Rank-%d approximation: \n", params.K)
		PrintSigned(C)

		fmt.Printf("Left singular vectors: \n")
		PrintSigned(A)

		fmt.Printf("Right singular vectors: \n")
		PrintSigned(B)
	}

	if !success {
		fmt.Println(params.ToString())
		fmt.Println("Matrices not equal")
	}

	fmt.Printf("\n-----\n\n")

	return success
}

func testPowerIt(test *testing.T, saveTrunc bool) {
	params := FromJSON("../params/tiny_params.json")
	params.Save_truncate = saveTrunc
	params.Start_random = true
	one := uint64(1)

	// Test that accurately factors a rank-1 matrix
	U := MatrixZeros[uint64](3, 3) // 3-by-3 matrix of zeros
	U.SetRowFromSlice(0, []uint64{1, 2, 3})
	U.SetRowFromSlice(1, []uint64{1, 2, 3})
	U.SetRowFromSlice(2, []uint64{2, 4, 6})

	if b := runPowerIt(U, params, "scratch/", false); !b {
		test.Fail()
		panic("Bad event!")
	}

	// ... and its transpose
	if b := runPowerIt(U.Transpose(), params, "scratch/", false); !b {
		test.Fail()
		panic("Bad event!")
	}

	// Test that accurately factors a rank-2 matrix
	V := MatrixZeros[uint64](3, 3) // 3-by-3 matrix of zeros
	V.SetRowFromSlice(0, []uint64{1, 1, 1})
	V.SetRowFromSlice(1, []uint64{4, 4, 4})
	V.SetRowFromSlice(2, []uint64{7, 7, 7})
	MatrixAddInPlace64(U, V)

	if b := runPowerIt(U, params, "scratch/", false); !b {
		test.Fail()
		panic("Bad event!")
	}

	// ... and its transpose
	if b := runPowerIt(U.Transpose(), params, "scratch/", false); !b {
		test.Fail()
		panic("Bad event!")
	}

	// Test that accurately factors a medium rank-2 matrix
	U = MatrixZeros[uint64](5, 10)
	U.Set(1, 2, &one)
	U.Set(4, 9, &one)

	if b := runPowerIt(U, params, "scratch/", true); !b {
		test.Fail()
		panic("Bad event!")
	}

	// ... and its transpose
	if b := runPowerIt(U.Transpose(), params, "scratch/", true); !b {
		test.Fail()
		panic("Bad event!")
	}

	// Test that accurately factors a large rank-2 matrix
	U = MatrixZeros[uint64](100, 200)
	U.Set(37, 2, &one)
	U.Set(45, 96, &one)

	if b := runPowerIt(U, params, "scratch/", true); !b {
		test.Fail()
		panic("Bad event!")
	}

	// ... and its transpose
	if b := runPowerIt(U.Transpose(), params, "scratch/", true); !b {
		test.Fail()
		panic("Bad event!")
	}
}

func TestPowerIt(test *testing.T) {
	fmt.Println("TestPowerIt")

	f := ProfileCPU("cpu_test.prof")
	defer f.Close()
	defer pprof.StopCPUProfile()

	testPowerIt(test, true)
	testPowerIt(test, false)
}
