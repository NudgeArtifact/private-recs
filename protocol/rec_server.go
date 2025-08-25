package protocol

import (
	"net"
	"net/rpc"
	"math/bits"
	"unsafe"
	"sync"
        "private-recs/multdpf"
        . "private-recs/share"
        . "private-recs/uint128"
)

type RecQuery struct {
	ClientId        uint64
	Keys  	        []multdpf.DPFkey
}

type RecAnswer []Matrix[Uint128]

type RecServer struct {
        Id              int 

	ClientEmbs      []Matrix[Share128] // array of secret-shared client embeddings (each a vector)
	ClientEmbsAdd   []Matrix[Uint128] // array of secret-shared client embeddings (each a vector)
	ItemEmbs        []Matrix[uint64]  // array of item embeddings, grouped by cluster, each a matrix of same dimensions

	Nusers          uint64
	Nitems          uint64
	logNClusters    uint64

	listening       bool
	Listener        net.Listener
}

func LaunchRecServer(id int, num_users, num_items uint64, hang bool, clients []Matrix[Share128], items []Matrix[uint64]) *RecServer {
	s := new(RecServer)
	s.Id = id
	s.ItemEmbs = items
	s.Nusers = num_users
	s.Nitems = num_items
	s.logNClusters = uint64(bits.Len64(uint64(len(items))-1))
	s.listening = false

	if len(items) == 1 { // num clusters is 1 -- cast to additive shares instead
		s.ClientEmbsAdd = make([]Matrix[Uint128], len(clients))
		for i := 0; i <  len(clients); i++ {
			s.ClientEmbsAdd[i] = *MatrixRSSToAdditive(&clients[i], id) 
		}

	} else {
		s.ClientEmbs = clients
	}

	s.Serve(hang)

	return s
}

// Start listening for RPCs
func (s *RecServer) Serve(hang bool) {
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
func (s *RecServer) ServeRecsWithoutClustering(clientId *uint64, ans *RecAnswer) error {
        if *clientId >= s.Nusers {
                panic("RegisterClient: Client ID out of range")
        }

        clientEmb := s.ClientEmbsAdd[*clientId]

	mat := MatrixZeros[Uint128](s.ItemEmbs[0].Rows, clientEmb.Cols) 
	MatrixMulMixedDst(&s.ItemEmbs[0], &clientEmb, mat) // all data is just stored in cluster 0
	res := []Matrix[Uint128]{ *mat }
	*ans = res

        return nil
}

func (s *RecServer) StopListening() {
	if s.listening == false {
		return
	}

	s.Listener.Close()
	s.listening = false
}
