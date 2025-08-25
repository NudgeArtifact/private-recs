package net

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"net"
	"time"
	"sync"

	"private-recs/share"
	"private-recs/dmsb"
	"private-recs/dcf"
	. "private-recs/uint128"
)


type Network struct {
	myIdx     int
	senders   [][]io.Writer
	receivers [][]io.Reader

	senderConns [][]net.Conn
	receiverConns [][]net.Listener

	numRounds int
	bytesSent [][]int
	bytesRecv [][]int

	sendMu [][]sync.Mutex
	recvMu [][]sync.Mutex

	outgoing [][]byte
}

type NetworkConfig struct {
	Ports   [][][]string // sender i contacts receiver j worker k at ports[i][j][k]
	IPAddrs []string
}

func (n *Network) ResetComm() {
	for i, v := range n.bytesSent {
		for j, _ := range v {
			n.bytesSent[i][j] = 0
		}
	}

	for i, v := range n.bytesRecv {
		for j, _ := range v {
			n.bytesRecv[i][j] = 0
		}
	}

	n.numRounds = 0
}

func (n *Network) Close() {
	for i, _ := range n.senders {
		for j, _ := range n.senders[i] {
			n.senderConns[i][j].Close()
		}
	}

	for i, _ := range n.receivers {
		for j, _ := range n.senders[i] {
                	n.receiverConns[i][j].Close()
		}
        }
}

func localIP() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		fmt.Println(err)
		panic("Error looking up own IP")
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP
			}
		}
	}

	panic("Own IP not found")
	return nil
}

func NewTestNetwork(n int, numWorkers int) []*Network {
	readers := make([]io.Reader, n*n*numWorkers)
	writers := make([]io.Writer, n*n*numWorkers)

	for i := 0; i < n*n*numWorkers; i++ {
		start, end := io.Pipe()
		readers[i] = start
		writers[i] = end
	}

	out := make([]*Network, n)
	for i := 0; i < n; i++ {
		out[i] = &Network{
			myIdx:     i,
			senders:   make([][]io.Writer, n),
			receivers: make([][]io.Reader, n),
			bytesSent: make([][]int, n),
                        bytesRecv: make([][]int, n),
			sendMu:    make([][]sync.Mutex, n),
			recvMu:    make([][]sync.Mutex, n),
			outgoing:  make([][]byte, 3),
		}

		for j := 0; j < n; j++ {
			out[i].senders[j] = make([]io.Writer, numWorkers)
			out[i].receivers[j] = make([]io.Reader, numWorkers)
			out[i].bytesSent[j] = make([]int, numWorkers)
			out[i].bytesRecv[j] = make([]int, numWorkers)
			out[i].sendMu[j] = make([]sync.Mutex, numWorkers)
			out[i].recvMu[j] = make([]sync.Mutex, numWorkers)

			for k := 0; k < numWorkers; k++ {
				out[i].senders[j][k] = writers[i*n+j*numWorkers+k]
				out[i].receivers[j][k] = readers[j*n+i*numWorkers+k]
			}
		}
	}

	return out
}

// Input: port numbers to listen on and ip_addr:port pairs to
// establish connections with
func NewTCPNetwork(idx int, config *NetworkConfig) *Network {
	n := &Network{
		myIdx:         idx,
		senders:       make([][]io.Writer, len(config.IPAddrs)),
		receivers:     make([][]io.Reader, len(config.IPAddrs)),
                senderConns:   make([][]net.Conn, len(config.IPAddrs)),
                receiverConns: make([][]net.Listener, len(config.IPAddrs)),
		bytesSent:     make([][]int, len(config.IPAddrs)),
		bytesRecv:     make([][]int, len(config.IPAddrs)),
                sendMu:        make([][]sync.Mutex, len(config.IPAddrs)),
                recvMu:        make([][]sync.Mutex, len(config.IPAddrs)),
		outgoing:      make([][]byte, 3),
	}

	// Set up receivers
	done := make(chan bool)
	for i := 0; i < len(config.IPAddrs); i++ {
		if i == idx {
			continue
		}
		fmt.Printf("Listening on server %d\n", i)

		n.senders[i] = make([]io.Writer, len(config.Ports[i][idx]))
		n.receivers[i] = make([]io.Reader, len(config.Ports[i][idx]))
                n.senderConns[i] = make([]net.Conn, len(config.Ports[i][idx]))
                n.receiverConns[i] = make([]net.Listener, len(config.Ports[i][idx]))
		n.bytesSent[i] = make([]int, len(config.Ports[i][idx]))
		n.bytesRecv[i] = make([]int, len(config.Ports[i][idx]))
		n.sendMu[i] = make([]sync.Mutex, len(config.Ports[i][idx]))
                n.recvMu[i] = make([]sync.Mutex, len(config.Ports[i][idx]))

		for j := 0; j < len(config.Ports[i][idx]); j++ {
			go func(connIdx int, workerIdx int) {
				listener, err := net.Listen("tcp", config.Ports[connIdx][idx][workerIdx])
				if err != nil {
					panic(fmt.Sprintf("Error listening on port: %s", err.Error()))
				}
				//log.Printf("Listening on %s\n", config.Ports[connIdx][idx][workerIdx])
				for {
					time.Sleep(5 * time.Second)
					conn, err := listener.Accept()
					if err != nil {
						continue
					}
					//log.Printf("Accepted connection on port %s\n", config.Ports[connIdx][idx][workerIdx])
					conn.(*net.TCPConn).SetNoDelay(true)
					conn.(*net.TCPConn).SetReadBuffer(4 * 65536) // make configurable based on block size
					n.receiverConns[connIdx][workerIdx] = listener
					n.receivers[connIdx][workerIdx] = conn
					done <- true
					fmt.Println("  success: receiving from ", connIdx)
					share.PrintMemUsage()

					break
				}
			}(i, j)
		}
	}

	// Kind of hacky, should probably do something better to make sure all listeners
	// set up before establishing connections
	time.Sleep(5 * time.Second)

	// Set up senders
	for i := 0; i < len(config.IPAddrs); i++ {
		if i == idx {
			continue
		}
		for j := 0; j < len(config.Ports[idx][i]); j++ {
			fmt.Printf("Receiving for server %d\n", i)
			go func(connIdx int, workerIdx int) {
				for {
					conn, err := net.Dial("tcp", fmt.Sprintf("%s%s", config.IPAddrs[connIdx], config.Ports[idx][connIdx][workerIdx]))
					if err != nil {
						continue
					}
					//log.Printf("Made connection at %s%s\n", config.IPAddrs[i], config.Ports[idx][connIdx][workerIdx])
					conn.(*net.TCPConn).SetNoDelay(true)
					conn.(*net.TCPConn).SetWriteBuffer(4 * 65536) // make configurable based on block size
					n.senderConns[connIdx][workerIdx] = conn
					n.senders[connIdx][workerIdx] = conn
					done <- true
					fmt.Println("  success: sending to ", connIdx)

					break
				}
			}(i, j)
		}
	}

	// Make sure all senders + receivers set up
	for i := 0; i < 2*(len(config.IPAddrs)-1)*len(config.Ports[0][0]); i++ {
		<-done
	}

	fmt.Printf("Network setup complete\n")
	return n
}

func (n *Network) MyIdx() int {
	return n.myIdx
}

func ByteLen(msg interface{}) int {
	var buf bytes.Buffer
        enc := gob.NewEncoder(&buf)
        err := enc.Encode(msg)
        if err != nil {
                panic(fmt.Sprintf("Failed to encode message: %v", err))
        }                       
        return len(buf.Bytes())
}

func (n *Network) SendBytesParallel(idx int, workerIdx int, msg []byte) {
	if _, err := n.senders[idx][workerIdx].Write(msg); err != nil {
		panic(err)
	}

        n.bytesSent[idx][workerIdx] += len(msg)
}

func (n *Network) RecvBytesParallel(idx int, workerIdx int, msg []byte) {
	io.ReadFull(n.receivers[idx][workerIdx], msg)
	n.bytesRecv[idx][workerIdx] += len(msg)
}

func (n *Network) SendBytes(idx int, msg []byte) {
	n.SendBytesParallel(idx, 0, msg)
}

func (n *Network) RecvBytes(idx int, msg []byte) {
	n.RecvBytesParallel(idx, 0, msg)
}

func (n *Network) SendUint64(idx int, val uint64) {
	n.sendMu[idx][0].Lock()
	defer n.sendMu[idx][0].Unlock()

        var intBuf [8]byte
        binary.LittleEndian.PutUint64(intBuf[:], val)
        n.SendBytes(idx, intBuf[:])
}

func (n *Network) RecvUint64(idx int) uint64 {
	n.recvMu[idx][0].Lock()
        defer n.recvMu[idx][0].Unlock()

        var intBuf [8]byte
	n.RecvBytes(idx, intBuf[:])
        return uint64(binary.LittleEndian.Uint64(intBuf[:]))
}

// TODO: Make faster using unsafe.slice
func (n *Network) appendUint128(idx int, u *Uint128) {
        bytes := Uint128ToBytes(u)
        n.outgoing[idx] = append(n.outgoing[idx], bytes...)
}

func (n *Network) AppendUint128(idx int, u *Uint128) {
	n.sendMu[idx][0].Lock()
        defer n.sendMu[idx][0].Unlock()
	n.appendUint128(idx, u)
}

func (n *Network) SendUint128(idx int, u *Uint128) {
        n.sendMu[idx][0].Lock()
        n.appendUint128(idx, u)
        n.sendMu[idx][0].Unlock()
	n.SendOutgoingMsgs()
}

func (n *Network) recvUint128(idx int, u *Uint128) {
        bytes := make([]byte, 16)
        n.RecvBytes(idx, bytes)
        BytesToUint128Dst(bytes, u)
}

func (n *Network) RecvUint128(idx int, u *Uint128) {
	n.recvMu[idx][0].Lock()
        defer n.recvMu[idx][0].Unlock()
	n.recvUint128(idx, u)
}

func (n *Network) appendByteArr(idx int, arr []byte) {
        var intBuf [8]byte
        binary.LittleEndian.PutUint64(intBuf[:], uint64(len(arr)))

        n.outgoing[idx] = append(n.outgoing[idx], intBuf[:]...)
        n.outgoing[idx] = append(n.outgoing[idx], arr...)
}

func (n *Network) AppendByteArr(idx int, arr []byte) {
	n.sendMu[idx][0].Lock()
        defer n.sendMu[idx][0].Unlock()
	n.appendByteArr(idx, arr)
}

func (n *Network) recvByteArr(idx int) []byte {
        var intBuf [8]byte
        n.RecvBytes(idx, intBuf[:])
        msgLen := binary.LittleEndian.Uint64(intBuf[:])

        msgBytes := make([]byte, msgLen)
        n.RecvBytes(idx, msgBytes)
        return msgBytes
}

func (n *Network) RecvByteArr(idx int) []byte {
	n.recvMu[idx][0].Lock()
        defer n.recvMu[idx][0].Unlock()
	return n.recvByteArr(idx)
}

func (n *Network) AppendTruncKey(idx int, key *share.TruncKey) {
	n.sendMu[idx][0].Lock()
        defer n.sendMu[idx][0].Unlock()

	n.appendByteArr(idx, []byte(key.Dcf))
        n.appendUint128(idx, &key.Share)
        n.appendUint128(idx, &key.Share2)
}

func (n *Network) RecvTruncKey(idx int, key *share.TruncKey) {
	n.recvMu[idx][0].Lock()
        defer n.recvMu[idx][0].Unlock()

	key.Dcf = n.recvByteArr(idx)
	n.recvUint128(idx, &key.Share)
	n.recvUint128(idx, &key.Share2)
}

func (n *Network) AppendDmsbKey(idx int, key *dmsb.DMSBkey128) {
	n.sendMu[idx][0].Lock()
        defer n.sendMu[idx][0].Unlock()

        if len(key.Cws) != 128 {
              panic("Not yet supported")
        }

	if len(key.Keys) != 129 {
              panic("Not yet supported")
        }

	for i := 0; i < 129; i++ {
		n.appendByteArr(idx, key.Keys[i])
	}

	for i := 0; i < 128; i++ {
		n.appendUint128(idx, &key.Cws[i])
	}
}

func (n *Network) RecvDmsbKey(idx int, key *dmsb.DMSBkey128) {
	n.recvMu[idx][0].Lock()
        defer n.recvMu[idx][0].Unlock()

	key.Keys = make([]dcf.DCFkey, 129)
	key.Cws = make([]Uint128, 128)

	for i := 0; i < 129; i++ {
		key.Keys[i] = n.recvByteArr(idx)
        }

        for i := 0; i < 128; i++ {
		n.recvUint128(idx, &key.Cws[i])
        }
}

func (n *Network) PrintComm() {
	fmt.Println("Bytes sent")
	totalSent := 0
	for i := 0; i < len(n.bytesSent); i++ {
		fmt.Printf("  To %d: ", i)
		for j := 0; j < len(n.bytesSent[i]); j++ {
			fmt.Printf(" %f MB ", float64(n.bytesSent[i][j]) / 1024.0 / 1024.0)
			totalSent += n.bytesSent[i][j]
		}
		fmt.Printf("\n")
	}
	fmt.Printf(" Total sent: %f MB\n", float64(totalSent) / 1024.0 / 1024.0)

        fmt.Println("Bytes received")
	totalReceived := 0
        for i := 0; i < len(n.bytesSent); i++ {
                fmt.Printf("  From %d: ", i)
                for j := 0; j < len(n.bytesSent[i]); j++ {
                        fmt.Printf(" %f MB ", float64(n.bytesRecv[i][j]) / 1024.0 / 1024.0)
			totalReceived += n.bytesRecv[i][j]
                }
                fmt.Printf("\n")
        }
	fmt.Printf(" Total received: %f MB\n", float64(totalReceived) / 1024.0 / 1024.0)
	fmt.Printf("Num Rounds: %d\n", n.numRounds)
}

func (n * Network) SendOutgoingMsgs() {
        for i := 0; i < 3; i++ {
                if len(n.outgoing[i]) > 0 {
                        n.SendBytesParallel(i, 0, n.outgoing[i])
                        n.outgoing[i] = n.outgoing[i][:0]
                }
        }

        n.AddRound()
}

func (n *Network) AddRound() {
	n.numRounds += 1
}
