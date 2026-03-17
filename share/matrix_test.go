package share

import (
	"fmt"
	. "github.com/NudgeArtifact/private-recs/params"
	. "github.com/NudgeArtifact/private-recs/rand"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"testing"
)

// Tests that make use of the matrix functionalities

func TestS3(test *testing.T) {
	fmt.Println("TestS3")

	U := MatrixZeros[uint64](3, 3) // 3-by-3 matrix of zeros
	U.SetRowFromSlice(0, []uint64{1, 2, 3})
	U.SetRowFromSlice(1, []uint64{1, 2, 3})
	U.SetRowFromSlice(2, []uint64{2, 4, 6})

	WriteMatrixToS3(U, "testS3.csv")

	V := ReadMatrixFromS3("testS3.csv")

	if !U.Equals(V) {
		panic("Not equal")
		test.Fail()
	}
}

func TestLogging(test *testing.T) {
	fmt.Println("TestLogging")

	file := "scratch.log"
	u := MatrixZeros[uint64](100, 200)
	pool := InitPRGPoolFromMatrix(u)

	U0, _, _ := ShareMatrixRSS(u, pool)
	WriteMatrixShareToFile(U0, file)

	V := ReadMatrixShareFromFile(file)

	if !U0.Equals(V) {
		test.Fail()
		panic("Matrices not equal!")
	}
}

func TestMatPtxtMul(test *testing.T) {
	fmt.Println("TestMatPtxtMul")

	nRows := uint64(100)
	nCols := uint64(100)
	pool := InitPRGPool(uint64(100))
	perf := new(PerfLog)

	M := RandMatrix[uint64](nRows, nCols, 0, 500, pool) // Get random values mod 500
	N := RandMatrix[uint64](nCols, nRows, 0, 500, pool) // Get random values mod 500
	shares0, shares1, shares2 := ShareMatrixRSS(N, pool)

	res := MatrixMul(M, N)
	res0 := MatrixPtxtMul(M, shares0)
	res1 := MatrixPtxtMul(M, shares1)
	res2 := MatrixPtxtMul(M, shares2)

	recon := MatrixRecoverFromRSS(res0, res1, res2, perf)
	if !res.Equals(recon) {
		test.Fail()
		panic("Matrices not equal!")
	}
}

func TestMatrixVec(test *testing.T) {
	fmt.Println("TestMatrixVec")

	nRows := uint64(100)
	nCols := uint64(100)
	pool := InitPRGPool(uint64(100))
	perf := new(PerfLog)

	matrix := RandMatrix[uint64](nRows, nCols, 0, 500, pool) // Get random values mod 500
	vector := RandMatrix[uint64](nCols, 1, 0, 500, pool)
	shares0, shares1, shares2 := ShareMatrixRSS(matrix, pool)

	// Correctness check
	matrix_additive0 := MatrixRSSToAdditive(shares0, 0)
	matrix_additive1 := MatrixRSSToAdditive(shares1, 1)
	matrix_additive2 := MatrixRSSToAdditive(shares2, 2)
	matrix_recovered := MatrixAddInPlaceShrink(matrix_additive0, matrix_additive1, matrix_additive2)

	for i := uint64(0); i < nRows; i++ {
		for j := uint64(0); j < nCols; j++ {
			if (*matrix_recovered.Get(i, j)) != (*matrix.Get(i, j)) {
				fmt.Printf("Correctness check 1 failed at (%d, %d)\n", i, j)
				test.Fail()
			}
		}
	}

	// Matrix-vector product between secret-shared matrix and plaintext vector
	vector2_share0 := MatrixMulRSSPtxt(shares0, vector)
	vector2_share1 := MatrixMulRSSPtxt(shares1, vector)
	vector2_share2 := MatrixMulRSSPtxt(shares2, vector)

	vector2_ptxt := make([]uint64, nRows)
	for i := uint64(0); i < nRows; i++ {
		for j := uint64(0); j < nCols; j++ {
			vector2_ptxt[i] += (*matrix.Get(i, j)) * (*vector.Get(j, 0))
		}
	}

	// Correctness check
	vector2_additive0 := MatrixRSSToAdditive(vector2_share0, 0)
	vector2_additive1 := MatrixRSSToAdditive(vector2_share1, 1)
	vector2_additive2 := MatrixRSSToAdditive(vector2_share2, 2)
	vector2_recovered := MatrixAddInPlaceShrink(vector2_additive0, vector2_additive1, vector2_additive2)

	for i := uint64(0); i < nRows; i++ {
		if (*vector2_recovered.Get(i, 0)) != vector2_ptxt[i] {
			fmt.Printf("Correctness check 2 failed at %d\n", i)
			test.Fail()
		}
	}

	// Matrix-vector product between secret-shared matrix and secret-shared vector
	vector3_additive0 := MatrixMulRSS(shares0, vector2_share0)
	vector3_additive1 := MatrixMulRSS(shares1, vector2_share1)
	vector3_additive2 := MatrixMulRSS(shares2, vector2_share2)

	vector3_ptxt := make([]uint64, nRows)
	for i := uint64(0); i < nRows; i++ {
		for j := uint64(0); j < nCols; j++ {
			vector3_ptxt[i] += ((*matrix.Get(i, j)) * vector2_ptxt[j])
		}
	}

	// Re-sharing: turn additive shares into RSS shares
	vector3_share0, vector3_share1, vector3_share2 := MatrixAdditiveToRSS(vector3_additive0,
		vector3_additive1,
		vector3_additive2,
		pool,
		perf)
	// Correctness check
	// WARNING: modifies vector3_additive0, so previous line needs to be before
	vector3_recovered := MatrixAddInPlaceShrink(vector3_additive0, vector3_additive1, vector3_additive2)

	for i := uint64(0); i < nRows; i++ {
		if (*vector3_recovered.Get(i, 0)) != vector3_ptxt[i] {
			fmt.Printf("Correctness check 3 failed at %d\n", i)
			test.Fail()
		}
	}

	// Truncation: divide everything by 4 (else, entire computation overflows past 2^64)
	vector3_share0, vector3_share1, vector3_share2 = MatrixTruncateRSS(vector3_share0,
		vector3_share1,
		vector3_share2,
		2,
		pool,
		perf)

	for i := uint64(0); i < nRows; i++ {
		vector3_ptxt[i] = (vector3_ptxt[i] >> 2)
	}

	// Correctness check
	vector3_additive0 = MatrixRSSToAdditive(vector3_share0, 0)
	vector3_additive1 = MatrixRSSToAdditive(vector3_share1, 1)
	vector3_additive2 = MatrixRSSToAdditive(vector3_share2, 2)
	vector3_recovered = MatrixAddInPlaceShrink(vector3_additive0, vector3_additive1, vector3_additive2)

	for i := uint64(0); i < nRows; i++ {
		if !((*vector3_recovered.Get(i, 0)) == vector3_ptxt[i]) {
			fmt.Printf("Correctness check 4 failed at %d: got %d instead of %d\n", i, (*vector3_recovered.Get(i, 0)), vector3_ptxt[i])
			test.Fail()
		}
	}

	// Correctness check
	vector3_additive0 = MatrixRSSToAdditive(vector3_share0, 0)
	vector3_additive1 = MatrixRSSToAdditive(vector3_share1, 1)
	vector3_additive2 = MatrixRSSToAdditive(vector3_share2, 2)
	vector3_recovered = MatrixAddInPlaceShrink(vector3_additive0, vector3_additive1, vector3_additive2)

	for i := uint64(0); i < nRows; i++ {
		if !((*vector3_recovered.Get(i, 0)) == vector3_ptxt[i] || (*vector3_recovered.Get(i, 0)) == vector3_ptxt[i]+1) {
			fmt.Printf("Correctness check 5 failed at %d: got %d instead of %d\n", i, (*vector3_recovered.Get(i, 0)), vector3_ptxt[i])
			test.Fail()
		}

		if (*vector3_recovered.Get(i, 0)) == vector3_ptxt[i]+1 {
			vector3_ptxt[i] += 1
		}
	}

	// Matrix-vector product between secret-shared matrix and secret-shared vector
	vector4_additive0 := MatrixMulRSS(shares0, vector3_share0)
	vector4_additive1 := MatrixMulRSS(shares1, vector3_share1)
	vector4_additive2 := MatrixMulRSS(shares2, vector3_share2)

	vector4_ptxt := make([]uint64, nRows)
	for i := uint64(0); i < nRows; i++ {
		for j := uint64(0); j < nCols; j++ {
			vector4_ptxt[i] += ((*matrix.Get(i, j)) * vector3_ptxt[j])
		}
	}

	// Correctness check
	vector4_recovered := MatrixAddInPlaceShrink(vector4_additive0, vector4_additive1, vector4_additive2)
	for i := uint64(0); i < nRows; i++ {
		if (*vector4_recovered.Get(i, 0)) != vector4_ptxt[i] {
			fmt.Printf("Correctness check 6 failed at %d\n", i)
			test.Fail()
		}
	}
}

func runPowerIt(U, S *Matrix[uint64], params *PowerItParams, save_mem, print_shares bool, shareName string) (bool, *Matrix[uint64], *Matrix[uint64]) {
	if save_mem {
		runtime.GC()
		debug.SetMemoryLimit((1 << 30) * 900)
		PrintMemUsage()
	}

	pool := InitPRGPoolFromMatrix(U)
	U0, U1, U2 := ShareMatrixRSS(U, pool)
	fmt.Println("Shared matrix")

	if save_mem {
		runtime.GC()
		PrintMemUsage()
	}

	if print_shares {
		fmt.Println("Writing to S3...")
		WriteMatrixShareToS3(U0, shareName+"0.csv")
		WriteMatrixShareToS3(U1, shareName+"1.csv")
		WriteMatrixShareToS3(U2, shareName+"2.csv")
		fmt.Println("  done")
	}

	var B *Matrix[uint64]
	var transposed bool
	var perf *PerfLog

	if Sketch {
		S0, S1, S2 := ShareMatrixRSS(S, pool)
		fmt.Println("Shared sketched matrix")
		WriteMatrixShareToS3(S0, "sketched_"+shareName+"0.csv")
		WriteMatrixShareToS3(S1, "sketched_"+shareName+"1.csv")
		WriteMatrixShareToS3(S2, "sketched_"+shareName+"2.csv")

		B, transposed, perf = PowerIteration(S0, S1, S2, params, pool, false) // don't shift up if sketching (already done)

		if transposed {
			panic("Not yet supported")
		}
	} else {
		B, transposed, perf = PowerIteration(U0, U1, U2, params, pool, true) // don't shift up if sketching (already done)
	}

	var A *Matrix[uint64]
	var tmp *Matrix[uint64]
	if !transposed {
		A = MatrixMul(U, B.Transpose())
	} else {
		B.TransposeInPlace()
		A = MatrixTransposeMul(U, B)
		A.TransposeInPlace()

		// swap pointers to A and B
		tmp = B
		B = A
		A = tmp
	}

	perf.Print()

	PrintMemUsage()
	if save_mem {
		U = nil // try to trigger garbage collection...
		return false, A, B
	}

	C := MatrixMul(A, B)
	MatrixSignedRoundInPlace(C, (1 << (params.N_decimals * 2)))

	if U.NRows() <= 10 {
		fmt.Printf("SVD on matrix U: \n")
		Print(U)

		fmt.Printf("Rank-%d approximation: \n", params.K)
		PrintSigned(C)

		fmt.Printf("Left singular vectors: \n")
		PrintSigned(A)

		fmt.Printf("Right singular vectors: \n")
		PrintSigned(B)
	}

	success := C.Equals(U)
	if !success {
		fmt.Println(params.ToString())
		fmt.Println("Matrices not equal")
	}

	fmt.Printf("\n-----\n\n")

	return success, A, B
}

func BenchmarkPowerIt(b *testing.B) {
	fmt.Println("BenchmarkPowerIt")

	var experiment string
	var params *PowerItParams
	var U *Matrix[uint64]
	var S *Matrix[uint64]

	full := !DebugMode
	shareName := ""

	if MovielensMode {
		// runs an experiment with the *dimensions* (but not the actual data) of the Movielens dataset
		experiment = "movielens"
		shareName = "movielens_share"
		params = FromJSON("../params/movielens_params.json")
		U = Rand01Matrix(6040, 3883)
	} else if full {
		experiment = "full_test"
		shareName = "netflix_test_share"
		params = FromJSON("../params/full_params.json")
		U = ReadMatrixFromFile("test_matrix/netflix_test_matrix.csv")

		if Sketch {
			experiment += "_sketch"
			S = ReadMatrixFromFile("test_matrix/sketched_netflix_test.csv")
			WriteMatrixToS3(S, "sketched_netflix_test.csv")
		}

	} else {
		experiment = "small"
		shareName = "netflix_small_share"
		params = FromJSON("../params/small_params.json")
		U = ReadMatrixFromFile("test_matrix/check_perf_matrix.csv")
	}

	fmt.Printf("Got matrix: %d by %d\n", U.NRows(), U.NCols())

	f := ProfileCPU("cpu" + experiment + ".prof")
	defer f.Close()
	defer pprof.StopCPUProfile()

	_, A, B := runPowerIt(U, S, params, true, false /* whether to print shares to S3 */, shareName)

	WriteMatrixToFile(A, "A_"+experiment+"_"+params.ToString()+".csv")
	WriteMatrixToFile(B, "B_"+experiment+"_"+params.ToString()+".csv")

	ProfileMemory("mem" + experiment + ".prof")
}

func testPowerIt(test *testing.T, saveTrunc bool) {
	params := FromJSON("../params/tiny_params.json")
	params.Save_truncate = saveTrunc
	one := uint64(1)

	// Test that accurately factors a rank-1 matrix
	U := MatrixZeros[uint64](3, 3) // 3-by-3 matrix of zeros
	U.SetRowFromSlice(0, []uint64{1, 2, 3})
	U.SetRowFromSlice(1, []uint64{1, 2, 3})
	U.SetRowFromSlice(2, []uint64{2, 4, 6})

	if b, _, _ := runPowerIt(U, nil, params, false, true, "test_matrix/small_share"); !b {
		test.Fail()
		panic("Bad event!")
	}

	// ... and its transpose
	if b, _, _ := runPowerIt(U.Transpose(), nil, params, false, false, ""); !b {
		test.Fail()
		panic("Bad event!")
	}

	// Test that accurately factors a rank-2 matrix
	V := MatrixZeros[uint64](3, 3) // 3-by-3 matrix of zeros
	V.SetRowFromSlice(0, []uint64{1, 1, 1})
	V.SetRowFromSlice(1, []uint64{4, 4, 4})
	V.SetRowFromSlice(2, []uint64{7, 7, 7})
	MatrixAddInPlace64(U, V)

	if b, _, _ := runPowerIt(U, nil, params, false, false, ""); !b {
		test.Fail()
		panic("Bad event!")
	}

	// ... and its transpose
	if b, _, _ := runPowerIt(U.Transpose(), nil, params, false, false, ""); !b {
		test.Fail()
		panic("Bad event!")
	}

	// Test that accurately factors a medium rank-2 matrix
	U = MatrixZeros[uint64](5, 10)
	U.Set(1, 2, &one)
	U.Set(4, 9, &one)

	if b, _, _ := runPowerIt(U, nil, params, false, false, ""); !b {
		test.Fail()
		panic("Bad event!")
	}

	// ... and its transpose
	if b, _, _ := runPowerIt(U.Transpose(), nil, params, false, false, ""); !b {
		test.Fail()
		panic("Bad event!")
	}

	// Test that accurately factors a large rank-2 matrix
	U = MatrixZeros[uint64](100, 200)
	U.Set(37, 2, &one)
	U.Set(45, 96, &one)

	if b, _, _ := runPowerIt(U, nil, params, false, false, ""); !b {
		test.Fail()
		panic("Bad event!")
	}

	// ... and its transpose
	if b, _, _ := runPowerIt(U.Transpose(), nil, params, false, false, ""); !b {
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
