package protocol

import (
        "net/rpc"
        "math/bits"

        "private-recs/rand"
        "private-recs/multdpf"
        "private-recs/net"
        . "private-recs/share"
)


type QueryType interface {
	uint64 | Submission | RecQuery
}

type AnsType interface {
	multdpf.Block | RecAnswer
}


type Client struct {
	ClientId  uint64

	Addrs        []string
	Conns        []*rpc.Client       // open connections with servers
	NextSeed     []multdpf.Block

	Nusers       uint64
	Nitems       uint64
	Nclusters    uint64
	logNitems    uint64
	logNclusters uint64

	prg          *rand.PrgPool
}

func LaunchDataCollectionClientRandId(num_users, num_items uint64, ip0, ip1, ip2 string) *Client {
	prg := rand.InitPRGPool(1)
	id := prg.At(0).Uint64() % num_users
	return LaunchDataCollectionClient(num_users, num_items, id, ip0, ip1, ip2)
}

func LaunchDataCollectionClient(num_users, num_items, id uint64, ip0, ip1, ip2 string) *Client {
        c := new(Client)
        c.Addrs = []string{ip0, ip1, ip2}
        c.Conns = make([]*rpc.Client, 3)
        c.NextSeed = make([]multdpf.Block, 3)

        c.Nusers = num_users
        c.Nitems = num_items
        c.logNitems = uint64(bits.Len64(num_items-1))

        c.prg = rand.InitPRGPool(1)
	c.ClientId = id
	//fmt.Printf("Launched client with ID %d (of %d)\n", c.ClientId, num_users)

        for i := 0; i < 3; i++ {
                var ans multdpf.Block
                makeRPC(c, i, &c.ClientId, &ans, true /* keep conn */, "DataCollectionServer.RegisterClient")
                c.NextSeed[i] = ans
        }

        return c
}

func LaunchRecClient(num_users, num_clusters, num_items, id uint64, ip0, ip1, ip2 string) *Client {
        c := new(Client)
        c.Addrs = []string{ip0, ip1, ip2}
        c.Conns = make([]*rpc.Client, 3)

        c.Nusers = num_users
        c.Nitems = num_items
	c.Nclusters = num_clusters
        c.logNitems = uint64(bits.Len64(num_items-1))
        c.logNclusters = uint64(bits.Len64(num_clusters-1))

        c.prg = rand.InitPRGPool(1)
        c.ClientId = id
        //fmt.Printf("Launched client with ID %d (of %d)\n", c.ClientId, num_users)

        return c
}

// RPCS:

func (c *Client) LogRating(item uint64) (int, int, int, int, int, int) {
	if item >= c.Nitems {
		panic("logRating: item out of bounds")
	}

	key0, key1, key2 := multdpf.GenFromBlock(item, c.logNitems, 128, &c.NextSeed[0], &c.NextSeed[1], &c.NextSeed[2])

	sub0 := Submission{ClientId: c.ClientId, Key: key0}
	sub1 := Submission{ClientId: c.ClientId, Key: key1}
	sub2 := Submission{ClientId: c.ClientId, Key: key2}

	var ans0, ans1, ans2 multdpf.Block
	up0, down0 := makeRPC(c, 0, &sub0, &ans0, true /* keep conn */, "DataCollectionServer.LogRating")
	up1, down1 := makeRPC(c, 1, &sub1, &ans1, true /* keep conn */, "DataCollectionServer.LogRating")
	up2, down2 := makeRPC(c, 2, &sub2, &ans2, true /* keep conn */, "DataCollectionServer.LogRating")
                
	c.NextSeed[0] = ans0
	c.NextSeed[1] = ans1
	c.NextSeed[2] = ans2

	return up0, up1, up2, down0, down1, down2
}

func (c *Client) FetchRecsWithoutClustering() ([]*Matrix[uint64], int, int, int, int, int, int) {
        q := make([]uint64, 3)
        for i := 0; i < 3; i++ {
                q[i] = c.ClientId
        }

        var ans0, ans1, ans2 RecAnswer
        up0, down0 := makeRPC(c, 0, &q[0], &ans0, true /* keep conn */, "RecServer.ServeRecsWithoutClustering")
        up1, down1 := makeRPC(c, 1, &q[1], &ans1, true /* keep conn */, "RecServer.ServeRecsWithoutClustering")
        up2, down2 := makeRPC(c, 2, &q[2], &ans2, true /* keep conn */, "RecServer.ServeRecsWithoutClustering")

        res := make([]*Matrix[uint64], 0)
        for j := 0; j < len(ans0); j++ {
                res = append(res, MatrixAddInPlaceShrink(&ans0[j], &ans1[j], &ans2[j]))
        }

        return res, up0, up1, up2, down0, down1, down2
}

func makeRPC[Q QueryType, A AnsType](c *Client, 
				     dest_id int,
	  		  	     query *Q, answer *A,
			             keepConn bool,
			     	     rpc string) (int, int) {
	//fmt.Printf("Client %d: dialing server %d for RPC call %s\n", c.ClientId, dest_id, rpc)

	if c.Conns[dest_id] == nil {
		c.Conns[dest_id] = DialTLS(c.Addrs[dest_id])
	}

	CallTLS(c.Conns[dest_id], rpc, query, answer)

	if !keepConn {
		c.Conns[dest_id].Close()
		c.Conns[dest_id] = nil
	}

	return net.ByteLen(query), net.ByteLen(answer)
}
