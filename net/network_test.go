package net

import (
	"fmt"
	"testing"
	"time"
)

func TestNetwork(t *testing.T) {
	networks := NewTestNetwork(3, 2)
	done := make(chan bool)

	var s string
	var s2 int

	// Party 0
	go func() {
		networks[0].Send(1, "test")
		networks[0].Recv(2, &s2)
		done <- true
	}()

	// Party 1
	go func() {
		networks[1].Recv(0, &s)
		done <- true
	}()

	// Party 2
	go func() {
		networks[2].Send(0, 7)
		done <- true
	}()

	// Wait for all parties to finish
	for i := 0; i < 3; i++ {
		<-done
	}

	if s != "test" {
		t.Errorf("Expected 'test', got %s", s)
	}

	if s2 != 7 {
		t.Errorf("Expected 'test2', got %v", s2)
	}
}

func TestTCPNetwork(t *testing.T) {
	config := &NetworkConfig{
		Ports: [][][]string{
			[][]string{[]string{"", ""}, []string{":8881", ":8882"}, []string{":8883", ":8884"}},
			[][]string{[]string{":8885", ":8886"}, []string{"", ""}, []string{":8887", ":8888"}},
			[][]string{[]string{":8889", ":8890"}, []string{":8891", ":8892"}, []string{"", ""}},
		},
		IPAddrs: []string{"127.0.0.1", "127.0.0.1", "127.0.0.1"},
	}
	networks := make([]*Network, 3)
	done := make(chan bool)

	for i := 0; i < 3; i++ {
		go func(idx int) {
			networks[idx] = NewTCPNetwork(idx, config)
			done <- true
		}(i)
	}

	for i := 0; i < 3; i++ {
		<-done
	}

	// Same test as above

	var s string
	var s2 int

	// Party 0
	go func() {
		networks[0].SendParallel(1, 1, "test")
		networks[0].RecvParallel(2, 0, &s2)
		done <- true
	}()

	// Party 1
	go func() {
		networks[1].RecvParallel(0, 1, &s)
		done <- true
	}()

	// Party 2
	go func() {
		networks[2].SendParallel(0, 0, 7)
		done <- true
	}()

	// Wait for all parties to finish
	for i := 0; i < 3; i++ {
		<-done
	}

	if s != "test" {
		t.Errorf("Expected 'test', got %s", s)
	}

	if s2 != 7 {
		t.Errorf("Expected 'test2', got %v", s2)
	}
}

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

