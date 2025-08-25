package protocol

import (
	"fmt"
	"net"
	"bytes"
	"net/rpc"
	"math/bits"
	"sync"

	crand "crypto/rand"

        "private-recs/rand"
        "private-recs/multdpf"

        . "private-recs/share"
)

type Submission struct {
	ClientId        uint64
	Key  	        multdpf.DPFkey
}

type ClientData struct {
	NumSubmissions  int
	NextSeed        multdpf.Block
}

type DataCollectionServer struct {
        Id              int 

	Nusers          uint64
	Nitems          uint64
	logNitems       uint64

	matMu           sync.Mutex
	M               *Matrix[Share128]   // share of matrix
        prg             *rand.PrgPool       // shared secrets with other servers (own prgs are at position s.Id) 

	listening       bool
	Listener        net.Listener

	mu              sync.Mutex
	Clients         map[uint64]ClientData
}

func LaunchDataCollectionServer(id int, num_users, num_items uint64, hang bool) *DataCollectionServer {
	s := new(DataCollectionServer)
	s.Id = id
	s.Nusers = num_users
	s.Nitems = num_items
	s.logNitems = uint64(bits.Len64(num_items-1))

	s.M = MatrixZeros[Share128](num_users, num_items)
	s.prg = InitPRGPoolFromMatrix(s.M)
	s.Clients = make(map[uint64]ClientData)

	s.Serve(hang)

	return s
}

// Start listening for RPCs
func (s *DataCollectionServer) Serve(hang bool) {
	rs := rpc.NewServer()
	rs.Register(s)

	port := ServerPort
	if s.Id == 0 {
		port = ServerPort0
	} else if s.Id == 1 {
		port = ServerPort1
	} else if s.Id == 2 {
		port = ServerPort2
	}

	s.Listener = ListenAndServeTLS(rs, port, hang)
	s.listening = true
}

// RPCs in protocol
func (s *DataCollectionServer) RegisterClient(clientId *uint64, ans *multdpf.Block) error {
	if *clientId >= s.Nusers {
		panic("RegisterClient: Client ID out of range")
	}

	v := ClientData{NumSubmissions: 0}
	crand.Read(v.NextSeed[:])

	s.mu.Lock()
	//if _, ok := s.Clients[*clientId]; ok {
	//	panic("RegisterClient: Client already registered")
	//}
	s.Clients[*clientId] = v
	s.mu.Unlock()

	*ans = v.NextSeed

	//fmt.Printf("RPC: registered client %d\n", *clientId)

	return nil
}

// Logs rating, returns next seed to be used
func (s *DataCollectionServer) LogRating(query *Submission, ans *multdpf.Block) error {
	s.mu.Lock()
	v, ok := s.Clients[query.ClientId]
	s.mu.Unlock()

        if  !ok {
		panic("LogRating: Client did not previously register with RegisterClient()") 
        }

	v.NextSeed[0] &^= 0x3
	if !bytes.Equal(v.NextSeed[:16], query.Key[:16]) {
		fmt.Printf("%x\n", query.Key[:16])
		fmt.Printf("%x\n", v.NextSeed[:16])
		panic("LogRating: Client's seed does not match registered one")
	}

	vals := multdpf.EvalFull128(query.Key, s.logNitems, s.Id)

	s.matMu.Lock()
	AddToRowFromSlice(s.M, query.ClientId, vals)
	s.matMu.Unlock()

        v.NumSubmissions += 1
	crand.Read(v.NextSeed[:])

	s.mu.Lock()
	s.Clients[query.ClientId] = v
	s.mu.Unlock()

        *ans = v.NextSeed

	//fmt.Printf("RPC: logged rating from client %d\n", query.ClientId)

	return nil
}

func (s *DataCollectionServer) StopListening() {
	if s.listening == false {
		return
	}

	s.Listener.Close()
	s.listening = false
}
