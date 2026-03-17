package protocol

import (
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	. "github.com/NudgeArtifact/private-recs/share"
)

func testDataCollection(t *testing.T, ratings *Matrix[uint64], shareName string) {
	var perf PerfLog
	wg := make([]sync.WaitGroup, 4)
	wg[3].Add(3)

	nusers := ratings.Rows
	nitems := ratings.Cols

	// Launch 3 servers
	for i := 0; i <= 2; i++ {
		wg[i].Add(1)

		go func(id int) {
			file := shareName + "mat" + strconv.Itoa(id) + ".csv"
			s := LaunchDataCollectionServer(id, nusers, nitems, false /* hang */)

			wg[i].Wait() // client rings this when all ratings written

			WriteMatrixShareToFile(s.M, file)

			wg[3].Done() // server rings this when shares written

			s.StopListening()
		}(i)
	}

	time.Sleep(1 * time.Second) // hack to make sure all the servers are up and listening

	// Write as client
	ip0 := LocalAddr(ServerPort0)
	ip1 := LocalAddr(ServerPort1)
	ip2 := LocalAddr(ServerPort2)
	for userId := uint64(0); userId < nusers; userId++ {
		c := LaunchDataCollectionClient(uint64(nusers), uint64(nitems), userId, ip0, ip1, ip2)

		for itemId := uint64(0); itemId < nitems; itemId++ {
			rating := *ratings.Get(userId, itemId)
			if !(rating == uint64(0) || rating == uint64(1)) {
				panic("Not yet supported")
			}
			if rating > uint64(0) {
				c.LogRating(itemId)
			}
		}
	}

	// Notify servers that all ratings written
	for i := 0; i < 3; i++ {
		wg[i].Done()
	}
	wg[3].Wait()

	// Reconstruct the shared matrix, check that correct
	share0 := ReadMatrixShareFromFile(shareName + "mat0.csv")
	share1 := ReadMatrixShareFromFile(shareName + "mat1.csv")
	share2 := ReadMatrixShareFromFile(shareName + "mat2.csv")
	U := MatrixRecoverFromRSS(share0, share1, share2, &perf)

	if !U.Equals(ratings) {
		fmt.Println("Recovered:")
		Print(U)
		fmt.Println("Should be:")
		Print(ratings)
		t.Fail()
		panic("Data collection failed")
	}
}

func TestDataCollectionSmall(t *testing.T) {
	fmt.Println("TestDataCollectionSmall")

	U := MatrixZeros[uint64](5, 10)
	one := uint64(1)
	U.Set(1, 2, &one)
	U.Set(4, 9, &one)

	testDataCollection(t, U, "scratch/")
}

func TestDataCollectionMed(t *testing.T) {
	fmt.Println("TestDataCollectionMed")

	U := MatrixZeros[uint64](100, 100)
	one := uint64(1)
	U.Set(1, 2, &one)
	U.Set(1, 3, &one)
	U.Set(1, 4, &one)
	U.Set(1, 49, &one)
	U.Set(4, 9, &one)
	U.Set(4, 91, &one)
	U.Set(4, 98, &one)

	testDataCollection(t, U, "scratch/")
}
