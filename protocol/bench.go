package protocol

import (
	"fmt"
	"time"
	"sync"
	"math"
)

func avg(data []float64) float64 {
        sum := 0.0
        num := 0.0
        for _, elem := range data {
                sum += elem
                num += 1.0
        }
        return sum / num
}

func stddev(data []float64) float64 {
        avg := avg(data)
        sum := 0.0
        num := 0.0
        for _, elem := range data {
                sum += math.Pow(elem-avg, 2)
                num += 1.0
        }
        variance := sum / num 
        return math.Sqrt(variance)
}

func getMax(data []int) int {
	res := data[0]
	for _, elem := range data {
		if elem > res {
			res = elem
		}
	}
	return res
}

func BenchLatency(nusers, nitems int, ip0, ip1, ip2 string) {
	c := LaunchDataCollectionClientRandId(uint64(nusers), uint64(nitems), ip0, ip1, ip2)
        c.LogRating(1)
        c.LogRating(2)
  
	numQueries := 100
	latency := make([]float64, 0)
	commUp := make([]int, 0)
	commDown := make([]int, 0)

	for iter := 0; iter < numQueries; iter++ {
		start := time.Now()
		up0, up1, up2, down0, down1, down2 := c.LogRating(0)
		elapsed := time.Since(start)

		fmt.Printf("%d. %fs\n", iter, elapsed.Seconds())

		latency = append(latency, elapsed.Seconds())
		commUp = append(commUp, up0, up1, up2)
		commDown = append(commDown, down0, down1, down2)
	}

	fmt.Printf("  Avg latency per LogRating: %f s\n", avg(latency))
	fmt.Printf("  Std dev of latency: %f s\n", stddev(latency))
	fmt.Printf("  Max comm up: %d bytes\n", getMax(commUp))
	fmt.Printf("  Max comm down: %d bytes\n", getMax(commDown))
}

func BenchTput(nusers, nitems int, ip0, ip1, ip2 string) {
	nclients := 1000
	clients := make([]*Client, nclients)

	for i := 0; i < nclients; i++ {
		clients[i] = LaunchDataCollectionClient(uint64(nusers), uint64(nitems), uint64(i % nusers), ip0, ip1, ip2)
	}

	fmt.Println("Set up clients")

	nc := make([]int, 0)
	tputs := make([]float64, 0)

	for cur := 400; cur < nclients; cur += 10 {
		fmt.Printf("  on %d clients\n", cur)
		timeUp := false
		var timeMu sync.Mutex

		queriesAnswered := 0
		var answeredMu sync.Mutex

		start := time.Now()
		for i := 0; i < cur; i++ {
			go func(i int) {
				for {
					clients[i].LogRating(0)
          
					answeredMu.Lock()
          				queriesAnswered += 1
          				answeredMu.Unlock()

          				timeMu.Lock()
          				if timeUp {
            					timeMu.Unlock()
            					return
          				}
          				timeMu.Unlock()
        			}
			}(i)
		}
		time.Sleep(60 * time.Second)

    		answeredMu.Lock()
    		elapsed := time.Since(start)
    		tput := float64(queriesAnswered) / elapsed.Seconds()
    		answeredMu.Unlock()

    		timeMu.Lock()
    		timeUp = true
    		timeMu.Unlock()

    		nc = append(nc, cur)
		tputs = append(tputs, tput)
    		fmt.Printf("  %d clients: %d queries answered in %f seconds\n",
        		    cur, queriesAnswered, elapsed.Seconds())
    		fmt.Printf("  Measured tput: %f queries/second\n", tput)

		time.Sleep(60 * time.Second)
	}
}

func BenchRecsLatency(nusers, nclusters, nitemsPerCluster int, ip0, ip1, ip2 string) {
	nitems := nclusters * nitemsPerCluster
	c := LaunchRecClient(uint64(nusers), uint64(nclusters), uint64(nitems), 0 /* userId */, ip0, ip1, ip2)
	c.FetchRecsWithoutClustering()

        numQueries := 10
        latency := make([]float64, 0)
        commUp := make([]int, 0)
        commDown := make([]int, 0)

        for iter := 0; iter < numQueries; iter++ {
                start := time.Now()
                _, up0, up1, up2, down0, down1, down2 := c.FetchRecsWithoutClustering()
                elapsed := time.Since(start)

                fmt.Printf("%d. %fs\n", iter, elapsed.Seconds())

                latency = append(latency, elapsed.Seconds())
                commUp = append(commUp, up0, up1, up2)
                commDown = append(commDown, down0, down1, down2)
        }

        fmt.Printf("  Avg latency per recs: %f s\n", avg(latency))
        fmt.Printf("  Std dev of latency: %f s\n", stddev(latency))
        fmt.Printf("  Max comm up: %d bytes\n", getMax(commUp))
        fmt.Printf("  Max comm down: %d bytes\n", getMax(commDown))
}

func BenchRecsTput(nusers, nclusters, nitemsPerCluster int, ip0, ip1, ip2 string) {
        nclients := 100
        clients := make([]*Client, nclients)
	nitems := nclusters * nitemsPerCluster

        for i := 0; i < nclients; i++ {
		clients[i] = LaunchRecClient(uint64(nusers), uint64(nclusters), uint64(nitems), 
					     uint64(i % nusers) /* userId */, ip0, ip1, ip2)
        }

        fmt.Println("Set up clients")

        nc := make([]int, 0)
        tputs := make([]float64, 0)

        for cur := 2; cur < nclients; cur += 2 {
                fmt.Printf("  on %d clients\n", cur)
                timeUp := false
                var timeMu sync.Mutex

                queriesAnswered := 0
                var answeredMu sync.Mutex

                start := time.Now()
                for i := 0; i < cur; i++ {
                        go func(i int) {
                                for {
                                        clients[i].FetchRecsWithoutClustering()

                                        answeredMu.Lock()
                                        queriesAnswered += 1
                                        answeredMu.Unlock()

                                        timeMu.Lock()
                                        if timeUp {
                                                timeMu.Unlock()
                                                return
                                        }
                                        timeMu.Unlock()
                                }
                        }(i)
                }
                time.Sleep(60 * 2 * time.Second)

                answeredMu.Lock()
                elapsed := time.Since(start)
                tput := float64(queriesAnswered) / elapsed.Seconds()
                answeredMu.Unlock()

                timeMu.Lock()
                timeUp = true
                timeMu.Unlock()

                nc = append(nc, cur)
                tputs = append(tputs, tput)
                fmt.Printf("  %d clients: %d queries answered in %f seconds\n",
                            cur, queriesAnswered, elapsed.Seconds())
                fmt.Printf("  Measured tput: %f queries/second\n", tput)

                time.Sleep(60 * time.Second)
        }
}
