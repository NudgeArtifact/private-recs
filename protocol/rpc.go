package protocol

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/rpc"
)

var publicKey = `-----BEGIN CERTIFICATE-----
MIIBVTCB/KADAgECAgEAMAoGCCqGSM49BAMCMBIxEDAOBgNVBAoTB0FjbWUgQ28w
HhcNMTQwNTAyMDQ0NDM4WhcNMTUwNTAyMDQ0NDM4WjASMRAwDgYDVQQKEwdBY21l
IENvMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEU7EtIv3GVZKMduiOwmQBzrqI
XnF84tNhcPSNtnw8cTgF8CPfJ0wcCbIvgQXEeZpTgn+A5N7YpdooUiwtICadeKND
MEEwDgYDVR0PAQH/BAQDAgCgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB
/wQCMAAwDAYDVR0RBAUwA4IBKjAKBggqhkjOPQQDAgNIADBFAiBU0cZRnenXWw0Y
OgQekAT+sx64ptjzm+ruABzBcIggbQIhAL2XbTx1l8IgmxtQZnK5S9wUmiIYMSxz
F2OaCRUekyth
-----END CERTIFICATE-----
`

var privateKey = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKbLcggTNozKjPjKdF2ZL/cT1i0UnT2gkcSi+sqxBebioAoGCCqGSM49
AwEHoUQDQgAEU7EtIv3GVZKMduiOwmQBzrqIXnF84tNhcPSNtnw8cTgF8CPfJ0wc
CbIvgQXEeZpTgn+A5N7YpdooUiwtICadeA==
-----END EC PRIVATE KEY-----
`

const (
	ServerPort  = "1234"
	ServerPort0 = "1235"
	ServerPort1 = "1236"
	ServerPort2 = "1237"
	Port0To1    = "1235"
	Port0To2    = "1236"
	Port1To0    = "1237"
	Port1To2    = "1238"
	Port2To0    = "1239"
	Port2To1    = "1230"
)

func LocalAddr(port string) string {
	return localIP().String() + ":" + port
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

// DialTLS connects to an RPC server over TLS.
func DialTLS(address string) *rpc.Client {
	var config tls.Config
	config.InsecureSkipVerify = true

	conn, err := tls.Dial("tcp", address, &config)
	if err != nil {
		panic(err)
		panic("Should not happen")
	}

	return rpc.NewClient(conn)
}

func CallTLS(c *rpc.Client, rpcname string, args interface{}, reply interface{}) {
	err := c.Call(rpcname, args, reply)
	if err == nil {
		return
	}

	fmt.Printf("Err: %s\n", err)
	panic("Call failed")
}

// ListenAndServeTLS starts a TLS RPC server on the given port.
func ListenAndServeTLS(server *rpc.Server, port string, hang bool) net.Listener {
	address := LocalAddr(port)
	cert, err := tls.X509KeyPair([]byte(publicKey), []byte(privateKey))
	if err != nil {
		fmt.Printf("Could not load certficate: %v\n", err)
		panic("Could not load certificate")
	}

	var config tls.Config
	config.InsecureSkipVerify = true
	config.Certificates = []tls.Certificate{cert}

	l, err := tls.Listen("tcp", address, &config)
	if err != nil {
		fmt.Printf("Listener error: %v\n", err)
		panic("Listener error")
	}

	//defer l.Close()

	fmt.Printf("TLS server listening on %s\n", address)

	if hang {
		for {
			conn, err := l.Accept()
			if err != nil {
				// Accept returns error when listener is closed
				fmt.Printf("accept error: %v", err)
				//return l
			}

			go handleOneClientTLS(conn, server)
		}

		return l // unreachable
	}

	go func(l net.Listener) {
		for {
			conn, err := l.Accept()
			if err != nil {
				// Accept returns error when listener is closed
				fmt.Printf("accept error: %v", err)
				return
			}

			go handleOneClientTLS(conn, server)
		}
	}(l)

	return l
}

func handleOneClientTLS(conn net.Conn, server *rpc.Server) {
	defer conn.Close()

	tlscon, ok := conn.(*tls.Conn)
	if !ok {
		fmt.Println("Could not cast conn")
		return
	}

	err := tlscon.Handshake()
	if err != nil {
		fmt.Printf("Handshake failed: %v\n", err)
		return
	}
	fmt.Println("Handshake OK")

	server.ServeConn(conn)
}
