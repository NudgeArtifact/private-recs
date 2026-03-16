package main

import (
	"flag"
	"fmt"
	"runtime/metrics"
	"strconv"
	"sync"
	"time"

	"github.com/NudgeArtifact/private-recs/params"
	"github.com/NudgeArtifact/private-recs/protocol"
	"github.com/NudgeArtifact/private-recs/rand"
	"github.com/NudgeArtifact/private-recs/share"
)

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("For matrix factorization: go run . server {0,1,2} serverIP0 serverIP1 serverIP2 matrixFile")
	fmt.Println(" ")
	fmt.Println("For data collection:      go run . data-server {0,1,2} nusers nitems")
	fmt.Println("                          go run . data-client nusers nitems serverIP0 serverIP1 serverIP2")
	fmt.Println("                          go run . data-bench nusers nitems serverIP0 serverIP1 serverIP2")
	fmt.Println("For recommendations:      go run . recs-server {0,1,2} nusers nclusters nitemsPerCluster")
	fmt.Println("                          go run . recs-client nusers nitems serverIP0 serverIP1 serverIP2")
	fmt.Println("                          go run . recs-bench nusers nclusters nitemsPerCluster serverIP0 serverIP1 serverIP2")
}

func main() {
	paramsJson := flag.String("params", "params/tiny_params.json", "Power iteration parameters")
	movielens := flag.Bool("movielens", false, "Whether to run movielens benchmarks")
	movielens100K := flag.Bool("movielens100K", false, "Whether to run movielens100K benchmarks")
	movielensTiny := flag.Bool("movielensTiny", false, "Whether to run movielensTiny benchmarks")
	netflix := flag.Bool("netflix", false, "Whether to run netflix benchmarks")
	random := flag.Bool("random", false, "Whether to run benchmarks on random matrix of given dims")

	users := flag.Int("users", 100000, "Num users, if random")
	items := flag.Int("items", 10000, "Num items, if random")
	ratings := flag.Int("ratings", 1000000, "Num ratings, if random")

	flag.Parse()
	args := flag.Args() // remaining, not-parsed as flags
	fmt.Println("Movielens1M:", *movielens)
	fmt.Println("Movielens100K:", *movielens100K)
	fmt.Println("MovielensTiny:", *movielensTiny)
	fmt.Println("Netflix: ", *netflix)
	fmt.Println("Rand: ", *random, *users, *items, *ratings)
	fmt.Println("Remaining args: ", args)

	if len(args) < 1 {
		printUsage()
		return
	}

	parameters := params.FromJSON(*paramsJson)

	if args[0] == "data-server" {
		if len(args) != 4 {
			printUsage()
			return
		}

		id, err := strconv.Atoi(args[1])
		if err != nil {
			panic(err)
		}

		nusers, err := strconv.Atoi(args[2])
		if err != nil {
			panic(err)
		}

		nitems, err := strconv.Atoi(args[3])
		if err != nil {
			panic(err)
		}

		protocol.LaunchDataCollectionServer(id, uint64(nusers), uint64(nitems), true)
	}

	if args[0] == "recs-server" {
		if len(args) != 5 {
			printUsage()
			return
		}

		id, err := strconv.Atoi(args[1])
		if err != nil {
			panic(err)
		}

		nusers, err := strconv.Atoi(args[2])
		if err != nil {
			panic(err)
		}

		nclusters, err := strconv.Atoi(args[3])
		if err != nil {
			panic(err)
		}

		nitemsPerCluster, err := strconv.Atoi(args[4])
		if err != nil {
			panic(err)
		}

		d := uint64(50)
		clientEmbs := make([]share.Matrix[share.Share128], nusers)

		var wg sync.WaitGroup
		for i := 0; i < nusers; i += 1000 {
			wg.Add(1)
			go func(at int) {
				defer wg.Done()
				pool := rand.InitPRGPool(d)
				for j := at; j < nusers && j < (at+1000); j++ {
					mat := share.RandMatrix[uint64](d, 1, 0, 10, pool)
					M, _, _ := share.ShareMatrixRSS(mat, pool)
					clientEmbs[j] = *M
				}
				fmt.Println("  users: finished ", at)
			}(i)
		}
		wg.Wait()
		fmt.Println(" built user embeddings")

		var wg2 sync.WaitGroup
		itemEmbs := make([]share.Matrix[uint64], nclusters)
		for i := 0; i < nclusters; i += 1000 {
			wg2.Add(1)
			go func(at int) {
				defer wg2.Done()
				pool := rand.InitPRGPool(d)
				for j := at; j < nclusters && j < (at+1000); j++ {
					mat := share.RandMatrix[uint64](uint64(nitemsPerCluster), d, 0, 1000, pool)
					itemEmbs[j] = *mat
				}
				fmt.Println("  items: finished ", at)
			}(i)
		}
		wg2.Wait()
		fmt.Println(" built item embeddings")

		protocol.LaunchRecServer(id, uint64(nusers),
			uint64(nclusters)*uint64(nitemsPerCluster),
			true, /* hang */
			clientEmbs, itemEmbs)
	}

	if args[0] == "data-client" {
		if len(args) != 6 {
			printUsage()
			return
		}

		nusers, err := strconv.Atoi(args[1])
		if err != nil {
			panic(err)
		}

		nitems, err := strconv.Atoi(args[2])
		if err != nil {
			panic(err)
		}

		ip0 := args[3]
		ip1 := args[4]
		ip2 := args[5]

		c := protocol.LaunchDataCollectionClientRandId(uint64(nusers), uint64(nitems), ip0, ip1, ip2)
		c.LogRating(1)
		c.LogRating(2)
	}

	if args[0] == "data-bench" {
		if len(args) != 6 {
			printUsage()
			return
		}

		nusers, err := strconv.Atoi(args[1])
		if err != nil {
			panic(err)
		}

		nitems, err := strconv.Atoi(args[2])
		if err != nil {
			panic(err)
		}

		ip0 := args[3]
		ip1 := args[4]
		ip2 := args[5]

		protocol.BenchLatency(nusers, nitems, ip0, ip1, ip2)
		protocol.BenchTput(nusers, nitems, ip0, ip1, ip2)
	}

	if args[0] == "recs-bench" {
		if len(args) != 7 {
			printUsage()
			return
		}

		nusers, err := strconv.Atoi(args[1])
		if err != nil {
			panic(err)
		}

		nclusters, err := strconv.Atoi(args[2])
		if err != nil {
			panic(err)
		}

		nitemsPerCluster, err := strconv.Atoi(args[3])
		if err != nil {
			panic(err)
		}

		ip0 := args[4]
		ip1 := args[5]
		ip2 := args[6]

		protocol.BenchRecsLatency(nusers, nclusters, nitemsPerCluster, ip0, ip1, ip2)
		protocol.BenchRecsTput(nusers, nclusters, nitemsPerCluster, ip0, ip1, ip2)
	}

	if args[0] == "server" {
		if len(args) != 5 && len(args) != 6 {
			printUsage()
			return
		}

		id, err := strconv.Atoi(args[1])
		if err != nil {
			panic(err)
		}

		ip0 := args[2]
		ip1 := args[3]
		ip2 := args[4]

		var file string
		var s *protocol.Server

		if *movielens {
			parameters = params.FromJSON("params/movielens_params.json")
			file = "movielens_share" + args[1] + ".csv"
			fmt.Println("Running on random matrix, with the dimensions of the Movielens dataset")
			s = protocol.LaunchServerFromS3WithSize(id, ip0, ip1, ip2, file, 6040*3883)

		} else if *movielens100K {
			parameters = params.FromJSON("params/movielens_tiny_params.json")
			fmt.Println("Running on random matrix, with the dimensions of the Movielens100K dataset")
			pool := rand.InitPRGPool(100)
			U := share.RandMatrix[share.Share128](uint64(943), uint64(1682), 0, 0, pool)
			s = protocol.LaunchServerFromMatrix(id, ip0, ip1, ip2, U)

		} else if *movielensTiny {
			parameters = params.FromJSON("params/movielens_tiny_params.json")
			fmt.Println("Running on random matrix, with the dimensions of the MovielensTiny dataset")
			pool := rand.InitPRGPool(100)
			U := share.RandMatrix[share.Share128](uint64(940), uint64(40), 0, 0, pool)
			s = protocol.LaunchServerFromMatrix(id, ip0, ip1, ip2, U)

		} else if *random {
			parameters = params.FromJSON("params/full_params.json")
			fmt.Println("Running on random matrix, with dimensions: ", *users, *items)
			pool := rand.InitPRGPool(192)
			U := share.RandMatrix[share.Share128](uint64(*users), uint64(*items), 0, 0, pool)
			s = protocol.LaunchServerFromMatrix(id, ip0, ip1, ip2, U)

		} else if *netflix {
			parameters = params.FromJSON("params/full_params.json")
			file = "netflix_test_share" + args[1] + ".csv"
			s = protocol.LaunchServerFromS3WithSize(id, ip0, ip1, ip2, file, 463435*17769)
			fmt.Println("  read matrix")

			s.ResetComm()
			s.VerifyZeroOneEntries()
			s.LogComm()

		} else if len(args) == 6 {
			file = args[5]
			s = protocol.LaunchServerFromS3(id, ip0, ip1, ip2, file)
		} else {
			panic("Don't know where to load matrix!")
		}

		//s.VerifyZeroOneEntries()
		s.ResetComm()

		// Hacky to measure core-seconds...
		sample := make([]metrics.Sample, 1)
		sample[0].Name = "/cpu/classes/user:cpu-seconds"
		metrics.Read(sample)
		startCS := sample[0].Value.Float64() // seconds*cores

		start := time.Now()
		s.PowerIteration(parameters, false, false)
		duration := time.Since(start)
		fmt.Printf("    took %v\n", duration)

		// Again measure core seconds
		metrics.Read(sample)
		endCS := sample[0].Value.Float64()
		fmt.Printf("    approximate core-seconds spent: %f\n", endCS-startCS)

		share.WriteMatrixToS3(s.Item_emb, file[:len(file)-4]+"_"+parameters.ToString()+"_items.csv")
		share.WriteMatrixShareToS3(s.User_emb, file[:len(file)-4]+"_"+parameters.ToString()+"_users.csv")
	}
}
