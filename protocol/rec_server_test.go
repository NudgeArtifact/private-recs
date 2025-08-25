package protocol

import (
        "fmt"
        "sync"
        "testing"

        . "private-recs/share"
	"private-recs/rand"
)

func testRecs(t *testing.T, clientEmbs []Matrix[uint64], itemEmbs []Matrix[uint64]) {
	wg := make([]sync.WaitGroup, 4)

	nusers := len(clientEmbs)
	nclusters := len(itemEmbs)
	nitems := 0
	for _, cluster := range itemEmbs {
		nitems += int(cluster.NRows())
	}

	pool := InitPRGPoolFromMatrix(&clientEmbs[0])
	clientShares := make([][]Matrix[Share128], 3)
	clientShares[0] = make([]Matrix[Share128], 0)
	clientShares[1] = make([]Matrix[Share128], 0)
	clientShares[2] = make([]Matrix[Share128], 0)

	for _, mat := range clientEmbs {
		M0, M1, M2 := ShareMatrixRSS(&mat, pool)
		clientShares[0] = append(clientShares[0], *M0)
		clientShares[1] = append(clientShares[1], *M1)
		clientShares[2] = append(clientShares[2], *M2)
	}

	fmt.Println("   built secret shares")

	// Launch 3 servers
	wg[3].Add(3)
        for i := 0; i <= 2; i++ {
		wg[i].Add(1)

                go func(id int) {
                        s := LaunchRecServer(id, uint64(nusers), uint64(nitems), false /* hang */, clientShares[i], itemEmbs)

			wg[3].Done() // server rings this when starts listening

			fmt.Println("    setup server ", id)

			wg[i].Wait() // client rings this when all tests complete

			s.StopListening()
                }(i)
        }

	// Start building queries
	clusterIds := make([]int, nclusters)
        for i := 0; i < nclusters; i++ {
		clusterIds[i] = i
	}

	fmt.Println("    built all queries")
	wg[3].Wait() // make sure all the servers are up and listening
	fmt.Println("    passed synchronization point")

	// Make queries as client
	ip0 := LocalAddr(ServerPort0)
	ip1 := LocalAddr(ServerPort1)
	ip2 := LocalAddr(ServerPort2)

	for userId := uint64(0); userId < uint64(nusers); userId++ {
		fmt.Println("     making queries on user ", userId)

		c := LaunchRecClient(uint64(nusers), uint64(nclusters), uint64(nitems), userId, ip0, ip1, ip2)

		var res []*Matrix[uint64]
		if nclusters == 1 {
			res, _, _, _, _, _, _ = c.FetchRecsWithoutClustering()
		} else {
			panic("Not yet supported")
		}

		// Verify that results are as expected

		for j := 0; j < nclusters; j++ {
			expected := MatrixMul(&itemEmbs[j], &clientEmbs[userId])

			if !res[j].Equals(expected) {
				fmt.Printf("MISMATCH at user %d, cluster %d...\n", userId, j)
				fmt.Println("Expected:")
				PrintSigned(expected)
				fmt.Println("Got: ")
				PrintSigned(res[j])
				t.Fail()
		                panic("Matrices not equal!")
			}
		}
	}

	// Notify servers that all ratings written
	for i := 0; i < 3; i++ {
		wg[i].Done()
	}
}

func TestRecsSmall(t *testing.T) {
	fmt.Println("TestRecsSmall")

	d := uint64(10)
	nclients := 1
	nclusters := 1
	itemsPerCluster := uint64(10)
	pool := rand.InitPRGPool(10)

	clientEmbs := make([]Matrix[uint64], 0)
	for i := 0; i < nclients; i++ {
		mat := RandMatrix[uint64](d, 1, 0, 10, pool)
		clientEmbs = append(clientEmbs, *mat)
	}

	itemEmbs := make([]Matrix[uint64], 0)
	for i := 0; i < nclusters; i++ {
		mat := RandMatrix[uint64](itemsPerCluster, d, 0, 1000, pool)
		itemEmbs = append(itemEmbs, *mat)
	}

	fmt.Println("   finished setup")
	testRecs(t, clientEmbs, itemEmbs)
}

func TestRecsMed(t *testing.T) {
        fmt.Println("TestRecsMed")

        d := uint64(20)
        nclients := 1
        nclusters := 1
        itemsPerCluster := uint64(20)
        pool := rand.InitPRGPool(10)

        clientEmbs := make([]Matrix[uint64], 0)
        for i := 0; i < nclients; i++ {
                mat := RandMatrix[uint64](d, 1, 0, 10, pool)
                clientEmbs = append(clientEmbs, *mat)
        }

        itemEmbs := make([]Matrix[uint64], 0)
        for i := 0; i < nclusters; i++ {
                mat := RandMatrix[uint64](itemsPerCluster, d, 0, 1000, pool)
                itemEmbs = append(itemEmbs, *mat)
        }

        fmt.Println("   finished setup")
        testRecs(t, clientEmbs, itemEmbs)
}

func TestRecsBig(t *testing.T) {
        fmt.Println("TestRecsBig")

        d := uint64(50)
        nclients := 100
        nclusters := 1
        itemsPerCluster := uint64(10)
        pool := rand.InitPRGPool(100)

        clientEmbs := make([]Matrix[uint64], 0)
        for i := 0; i < nclients; i++ {
                mat := RandMatrix[uint64](d, 1, 0, 10, pool)
                clientEmbs = append(clientEmbs, *mat)
        }

        itemEmbs := make([]Matrix[uint64], 0)
        for i := 0; i < nclusters; i++ {
                mat := RandMatrix[uint64](itemsPerCluster, d, 0, 1000, pool)
                itemEmbs = append(itemEmbs, *mat)
        }

        fmt.Println("   finished setup")
        testRecs(t, clientEmbs, itemEmbs)
}
