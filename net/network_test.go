package net

import (
	"fmt"
	"testing"
	"time"
)

func BenchmarkThroughput(b *testing.B) {
	config := &NetworkConfig{
		Ports: [][][]string{
			[][]string{[]string{"", ""}, []string{":8881", ":8882"}},
			[][]string{[]string{":8883", ":8884"}, []string{"", ""}},
		},
		IPAddrs: []string{"127.0.0.1", "127.0.0.1"},
	}
	networks := make([]*Network, 2)
	done := make(chan bool)

	for i := 0; i < 2; i++ {
		go func(idx int) {
			networks[idx] = NewTCPNetwork(idx, config)
			done <- true
		}(i)
	}

	for i := 0; i < 2; i++ {
		<-done
	}

	// Same test as above

	datasize := 10 << 30
	sendBuf := make([]byte, datasize)
	recvBuf := make([]byte, datasize)
	start := time.Now()

	for i := 0; i < 10; i++ {
		// Party 0
		go func() {
			blockSize := 1 << 30
			for j := 0; j < len(sendBuf); j += blockSize {
				networks[0].SendBytes(1, sendBuf[j:j+blockSize])
			}
			done <- true
		}()

		// Party 1
		go func() {
			blockSize := 1 << 30
			for j := 0; j < len(recvBuf); j += blockSize {
				networks[1].RecvBytes(0, recvBuf[j:j+blockSize])
			}
			done <- true
		}()

		// Wait for all parties to finish
		for i := 0; i < 2; i++ {
			<-done
		}
	}

	elapsed := time.Since(start)
	fmt.Printf("Time taken: %s\n", elapsed)
	fmt.Printf("Throughput: %f GB/s\n", float64(datasize*10)/elapsed.Seconds()/1e9)
}
