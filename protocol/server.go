package protocol

import (
	"io"
	"os"
	"fmt"
	"math"
	"time"
	"sync"
	"strconv"
	"os/exec"

	"private-recs/rand"
	"private-recs/net"
	"private-recs/dmsb"
        "private-recs/multdpf"

	. "private-recs/share"
	. "private-recs/uint128"
	. "private-recs/params"
)


type Server struct {
	Id	     int

	M	     *Matrix[Share128]   // share of matrix
        Items        uint64

	Item_emb     *Matrix[uint64]
	User_emb     *Matrix[Share128]

	network      *net.Network
	prgs         []*rand.PrgPool     // shared secrets with other servers (own prgs are at position 'Id', shared prgs are at position '4')
}


// For now: server initiating connection picks shared seeds

func NewServer (id int) *Server {
        if id >= 3 {
                panic("NewServer: Invalid server id")
        }

        s := new(Server)
        s.Id = id
	return s
}

// Initialize server. (What matrix it holds is stored in file.)
func LaunchServerFromFile(id int, ip0, ip1, ip2, file string) *Server {
	s := NewServer(id)

	fmt.Println("Reading matrix from file...", file)
        s.M = ReadMatrixShareFromFile(file)
        fmt.Println("  done")

	s.launchServer(ip0, ip1, ip2)
	return s
}

func LaunchServerFromS3(id int, ip0, ip1, ip2, file string) *Server {
        s := NewServer(id)

        fmt.Println("Reading matrix from S3...", file)
        s.M = ReadMatrixShareFromS3(file)
        fmt.Println("  done")

        s.launchServer(ip0, ip1, ip2)
        return s
}

func LaunchServerFromS3WithSize(id int, ip0, ip1, ip2, file string, numEntries int) *Server {
        s := NewServer(id)

        fmt.Println("Reading matrix from S3...", file)
        s.M = ReadMatrixShareFromS3WithSize(file, numEntries)
        fmt.Println("  done")

        s.launchServer(ip0, ip1, ip2)
        return s
}

func LaunchServerFromMatrix(id int, ip0, ip1, ip2 string, U *Matrix[Share128]) *Server {
        s := NewServer(id)
	s.M = U
        s.launchServer(ip0, ip1, ip2)
        return s
}

func LaunchServerFromMatrixAndNetwork(id int, n *net.Network, U *Matrix[Share128]) *Server {
        s := NewServer(id)
        s.M = U
	s.network = n

	s.prgs = make([]*rand.PrgPool, 4)
        for i := 0; i < 4; i++ {
                s.prgs[i] = InitPRGPoolFromMatrix(s.M)
                fmt.Printf("Server %d: prg pool %d has len %d\n", s.Id, i, s.prgs[i].Len())
        }

	s.VerifyMatrixDims()
        s.ExchangeSharedSecret()

        return s
}

func (s *Server) InitPRGs() {
	s.prgs = make([]*rand.PrgPool, 4)
        for i := 0; i < 4; i++ {
		if s.M != nil {
                	s.prgs[i] = InitPRGPoolFromMatrix(s.M)
		} else {
                	s.prgs[i] = rand.InitPRGPool(NUM_VCPUS)
		}
                fmt.Printf("Server %d: prg pool %d has len %d\n", s.Id, i, s.prgs[i].Len())
        }
}

func (s *Server) launchServer(ip0, ip1, ip2 string) {
	s.InitPRGs()

        fmt.Println("Setting up network")
        config := &net.NetworkConfig{
                Ports: [][][]string{
                        [][]string{[]string{""}, []string{":"+Port0To1}, []string{":"+Port0To2}},
                        [][]string{[]string{":"+Port1To0}, []string{""}, []string{":"+Port1To2}},
                        [][]string{[]string{":"+Port2To0}, []string{":"+Port2To1}, []string{""}},
                },
                IPAddrs: []string{ip0, ip1, ip2},
        }

        s.network = net.NewTCPNetwork(s.Id, config)

        fmt.Println("  done")

	if s.M != nil {
        	s.VerifyMatrixDims()
	}
        s.ExchangeSharedSecret()
}

func (s *Server) ResetComm() {
	s.network.ResetComm()
}

func (s *Server) ExchangeSharedSecret() {
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
	        for idx := 0; idx < s.Id; idx++ {
			for j := uint64(0); j < s.prgs[idx].Len(); j++ {
				s.network.SendBytes(idx, s.prgs[idx].At(j).Key[:])
			}
        	}
	
		if s.Id  == 0 {
			for j := uint64(0); j < s.prgs[3].Len(); j++ {
				s.network.SendBytes(1, s.prgs[3].At(j).Key[:])
				s.network.SendBytes(2, s.prgs[3].At(j).Key[:])
			}
		}
	}()

	var key rand.PRGKey
	for idx := s.Id + 1; idx <= 2; idx++ {
		for j := uint64(0); j < s.prgs[idx].Len(); j++ {
			s.network.RecvBytes(idx, []byte(key[:]))
			s.prgs[idx].Set(uint64(j), &key)
		}
		fmt.Printf("Server %d: got %d shared secrets from server %d\n", s.Id, s.prgs[idx].Len(), idx)
        }

	if s.Id != 0 {
		for j := uint64(0); j < s.prgs[3].Len(); j++ {
			s.network.RecvBytes(0, []byte(key[:]))
                	s.prgs[3].Set(uint64(j), &key)
		}
                fmt.Printf("Server %d: got %d 3-way shared secret from server 0\n", s.Id, s.prgs[3].Len())
	}

	wg.Wait()

	// Freeze PRG pools once have set up shared secrets
	for i := 0; i < len(s.prgs); i++ {
		if i == s.Id {
			continue
		}
		s.prgs[i].Freeze()
	}
}

func (s *Server) VerifyMatrixDims() {
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		for idx := 0; idx <= 2; idx++ {
			if idx == s.Id {
				continue
			}

			s.network.SendUint64(idx, s.M.NRows())
			s.network.SendUint64(idx, s.M.NCols())
		}
	}()

        for idx := int(0); idx <= 2; idx++ {
                if idx == s.Id {
                        continue
                }

		nRows := s.network.RecvUint64(idx)
		nCols := s.network.RecvUint64(idx)

		if nRows != s.M.NRows() {
			fmt.Printf("Server %d: nrows mismatch with server %d\n", s.Id, idx)
			panic("Fail")
		}

                if nCols != s.M.NCols() {
                        fmt.Printf("Server %d: ncols mismatch with server %d\n", s.Id, idx)
                        panic("Fail")
                }
        }

	wg.Wait()
	fmt.Println("Matrix Dimension verification passed")
}

// Verify that the entries of M are 0 or 1 
func (s *Server) VerifyZeroOneEntries() bool {
	fmt.Println("Verifying that M has zero/one entries")
	start := time.Now()

	U := s.M
	res_add := MatrixCheckZeroOneRSS(U, s.Id, s.prgs[3])

	if s.Id != 0 {
                s.network.SendUint128(0, res_add)
		s.network.RecvUint128(0, res_add)
        } else {
		var tmp Uint128
                s.network.RecvUint128(1, &tmp)
		res_add.AddInPlace(&tmp)
                s.network.RecvUint128(2, &tmp)
		res_add.AddInPlace(&tmp)

		s.network.SendUint128(1, res_add)
		s.network.SendUint128(2, res_add)
        }

	fmt.Printf("    recovered: %d ?= 0\n", res_add)
	duration := time.Since(start)
        fmt.Printf("    took %v\n", duration)

	return IsZero(res_add)
}

// Initial implementation:
// - Server 0 is always the dealer
// - Server 1 is always the left server
// - Server 2 is always the right server
func (s *Server) PowerIteration(params *PowerItParams, check_proximity, shift_up bool) {
        fmt.Printf("Start power iteration: %d components, %d iters, %d bits of precision -- %s\n",
                   params.K, params.N_iters, params.N_decimals, params.ToString())
                 
	start := time.Now()

	U := s.M
	if U == nil {
		panic("Should not happen")
	}

        pad := uint64(1 << params.N_decimals)
	if shift_up {
        	MulByConstantInPlaceRSS128(U, pad)
	}

        // Initialize right singular vectors
        B := MatrixZeros[uint64](uint64(params.K), U.NCols())

        // Trigger memory allocations once upfront, then not anymore throughout
        v_rss := MatrixZeros[Share128](U.NCols(), 1)
        v_add := MatrixZeros[Uint128](U.NCols(), 1)
        v := MatrixZeros[uint64](U.NCols(), 1)
        v_init := MatrixZeros[Uint128](U.NCols(), 1)
        v_init_sm := MatrixZeros[uint64](U.NCols(), 1)
        sub := MatrixZeros[uint64](U.NCols(), 1)
        sub_rss := MatrixZeros[Share128](U.NCols(), 1)

        u_rss := MatrixZeros[Share128](U.NRows(), 1)
        u_add := MatrixZeros[Uint128](U.NRows(), 1)

        inner_prod := MatrixZeros[uint64](1, 1)
        inner_prod_rss := MatrixZeros[Share128](1, 1)
        inner_prod_add := MatrixZeros[Uint128](1, 1)
        norm_sq := MatrixZeros[Uint128](1, 1)

	for component := 0; component < params.K; component++ {
                fmt.Printf("  building factor %d of %d\n", component, params.K)

                if params.Start_random {
                        // Init with random values in {-1, 0, 1} 
			SetRand[uint64](v_init_sm, U.NCols(), 1, 0, 3, s.prgs[3]) // 3-rd location: 3-way shared randomness
                        MatrixSubScalarInPlace(v_init_sm, 1)
                } else {
                        SetOnes[uint64](v_init_sm, U.NCols(), 1)
                }

                MulByConstantInPlace64(v_init_sm, pad)

                // Force orthogonality to already-computed factors
                for factor := 0; factor < component; factor++ {
                        factor_vector := B.GetRowsPointer(uint64(factor), uint64(factor+1))
                        MatrixMulDst(factor_vector, v_init_sm, inner_prod)
                        MatrixRshSignedInPlace(inner_prod, params.N_decimals)

                        MatrixTransposeMulDst(factor_vector, inner_prod, sub)
                        MatrixRshSignedInPlace(sub, params.N_decimals)
                        MatrixSubInPlace(v_init_sm, sub)
                }

                // Normalize v_init (still all plaintext)
                ToMatrix128Dst(v_init_sm, v_init) // Map to huge array to prevent overflow
                MatrixTransposeMul128Dst(v_init, v_init, norm_sq)
                shifted_by := 0
                norm_sq_int := norm_sq.Get(0, 0)
                for ; !CheckPositiveUint64(norm_sq_int); {
                        if shifted_by > 128 {
                                panic("Should not happen")
                        }
                        norm_sq_int.RshInPlace(uint(params.N_decimals)) 
                        shifted_by += params.N_decimals
                }

                norm_sq_shifted_int := ToUint64(norm_sq_int)
                norm := uint64(math.Sqrt(float64(norm_sq_shifted_int)))

                shifted_by_after_sqrt := shifted_by / 2 

                if norm > 0 {
                        if shifted_by_after_sqrt <= params.N_decimals {
                                MulByConstantInPlace128(v_init, (pad >> shifted_by_after_sqrt))
                                DivByConstantInPlace128(v_init, norm)
                        } else {
                                DivByConstantInPlace128(v_init, norm << (shifted_by_after_sqrt-params.N_decimals))
                        }
                }

                ToMatrix64Dst(v_init, v_init_sm)
		
                if params.Start_random {
                        // Noise the lowest-order bits
                        SetRand[uint64](sub, U.NCols(), 1, 1, 10001, s.prgs[3])
                        MatrixAddInPlace64(v_init_sm, sub) 
                }

                // First step in Mul
                MatrixMulRSSPtxtDst(U, v_init_sm, u_rss)

		var trunc_saved uint
                if !params.Save_truncate {
                        s.MatrixTruncateRSSToAdditive(u_rss, u_add, uint(params.N_decimals))
			s.MatrixAdditiveToRSSDst(u_add, u_rss)
			trunc_saved = 0
		} else {
			trunc_saved = 1
		}

                for iter := 0; iter < params.N_iters; iter++ {
                        fmt.Printf("Iter %d\n", iter)
                        start := time.Now()

                        // Pulled out the very first operation (performed right above), because v starts out as plaintext
                        // Also: avoid truncation by just not scaling up v_init by pad in the first place
                        if iter > 0 {
                                // Matrix-vector product on shared Data: [u] = [U] * [v]
                                MatrixMulRSSDst(U, v_rss, u_add)

                                if !params.Save_truncate {
					s.MatrixAdditiveToRSSDst(u_add, u_rss)
					s.MatrixTruncateRSSToAdditive(u_rss, u_add, uint(params.N_decimals))
					trunc_saved = 0
                                } else {
					trunc_saved += 1
				}

                                // Re-sharing: turn additive shares of [u] into RSS ones
                                s.MatrixAdditiveToRSSDst(u_add, u_rss)
                        }

                        // Matrix-vector product on shared Data: [v] = [U.transpose] * [u]
			MatrixTransposeMulRSSDst(U, u_rss, v_add) 

			s.MatrixAdditiveToRSSDst(v_add, v_rss)

                        if !params.Save_truncate {
				s.MatrixTruncateRSSToAdditive(v_rss, v_add, uint(params.N_decimals))
                        } else {
				s.MatrixTruncateRSSToAdditive(v_rss, v_add, uint(params.N_decimals) * (trunc_saved + 1))
                        }
			trunc_saved = 0

                        s.MatrixAdditiveToRSSDst(v_add, v_rss)

                        // Force orthogonality to already-computed factors
			MulByConstantInPlaceRSS128(v_rss, pad)
			
                        for factor := 0; factor < component; factor++ {
                                factor_vector := B.GetRowsPointer(uint64(factor), uint64(factor+1))
                                MatrixPtxtMulDst(factor_vector, v_rss, inner_prod_rss)

                        	s.MatrixTruncateRSSToAdditive(inner_prod_rss, inner_prod_add, uint(params.N_decimals * 2))
                        	s.MatrixAdditiveToRSSDst(inner_prod_add, inner_prod_rss)

                                MatrixTransposePtxtMulDst(factor_vector, inner_prod_rss, sub_rss)
                                MatrixSubRSSInPlace(v_rss, sub_rss)
                        }

			s.MatrixTruncateRSSToAdditive(v_rss, v_add, uint(params.N_decimals))
			s.MatrixAdditiveToRSSDst(v_add, v_rss)
			trunc_saved = 0

			// Normalize the vector
                        s.VectorNormalizeRSSInPlace(v_rss, uint(params.N_decimals), uint(params.Norm_decimals), uint(params.Newton_iters))

                        duration := time.Since(start)
                        fmt.Printf("    took %v\n", duration)
                }

                // At this point: share and reveal the vector v (which leaks as part of the output anyways)
                // TODO: Save one round of communication, reveal with additive sharing instead
                s.MatrixRecoverFromRSSDst(v_rss, v)
                B.SetRow(uint64(component), v)
                fmt.Printf("Recovered component %d\n", component)
        }

        fmt.Println("Returing from power iteration...")
        
	// Optimization: skip last truncation (no extra leakage...)
	s.Item_emb = B
	if s.M != nil {
		U = s.M // use original matrix, not shifted one
		A := MatrixMulRSSPtxt(U, B.Transpose())
		s.User_emb = A
	} else {
		panic("Not yet supported")
	}

	duration := time.Since(start)
        fmt.Printf("    took %v (to compute user + item embeddings)\n", duration)

	// Just for testing purposes
	if check_proximity {
		User_emb_ptxt := MatrixZeros[uint64](U.NRows(), uint64(params.K)) 
		s.MatrixRecoverFromRSSDst(s.User_emb, User_emb_ptxt)

        	C := MatrixMul(User_emb_ptxt, s.Item_emb)
        	MatrixSignedRoundInPlace(C, (1 << (params.N_decimals * 2)))

        	if U.NRows() <= 10 {
        		fmt.Printf("Rank-%d approximation (%s): \n", params.K, params.ToString())
        		PrintSigned(C)

        		fmt.Printf("Left singular vectors: \n")
        		PrintSigned(User_emb_ptxt)

        		fmt.Printf("Right singular vectors: \n")
        		PrintSigned(B)
		}
	}

	s.network.PrintComm()
}

func (s *Server) LogComm() {
	s.network.PrintComm()
}

func (s *Server) truncateRSSToAdditive128(src *Share128, decimals uint) *Uint128 {
	dst := MakeUint128(0, 0)
	s.truncateRSSToAdditive128Dst(src, dst, decimals, 0 /* prgIndex */)
	return dst
}

func (s *Server) truncateRSSToAdditive128Dst(src *Share128, dst *Uint128, decimals uint, prgIndex uint64) {
	dstToSquare := MakeUint128(0, 0)
	s.truncateRSSToAdditivePart1Write(src, dst, decimals, prgIndex)
	s.SendMsgs()

	s.truncateRSSToAdditivePart1Read(src, dst, dstToSquare, decimals)
	s.truncateRSSToAdditivePart2Write(src, dstToSquare, prgIndex)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.SendMsgs()
	}()

	s.truncateRSSToAdditivePart2Read(src, dst)
	wg.Wait()
}	

func (s *Server) truncateRSSToAdditivePart1Write(src *Share128, dst *Uint128, decimals uint, prgIndex uint64) {
        if s.Id == 0 {
                truncKeyL, truncKeyR := DealerTruncateRSSToAdditive128(src, decimals, s.prgs[s.Id].At(prgIndex))
                s.network.AppendTruncKey(1, truncKeyL)
                s.network.AppendTruncKey(2, truncKeyR)
        	Clear(dst)
        }
}

func (s *Server) truncateRSSToAdditivePart1Read(src *Share128, dst *Uint128, dstToSquare *Uint128, decimals uint) {
        if s.Id == 1 {
                var truncKey TruncKey
                s.network.RecvTruncKey(0, &truncKey)
                ServerLTruncateRSSToAdditive128Dst(&truncKey, src, dst, dstToSquare, decimals)

        } else if s.Id == 2 {
                var truncKey TruncKey
                s.network.RecvTruncKey(0, &truncKey)
                ServerRTruncateRSSToAdditive128Dst(&truncKey, src, dst, dstToSquare, decimals)
	}
}

func (s *Server) truncateRSSToAdditivePart2Write(src *Share128, dstToSquare *Uint128, prgIndex uint64) {
	s.additiveToRSSWrite(dstToSquare, src, prgIndex)
}

func (s *Server) truncateRSSToAdditivePart2Read(src *Share128, dst *Uint128) {
        s.additiveToRSSRead(src)
	res := MakeUint128(0, 0)
        MulRSS128Dst(src, src, res) // Locally square
	dst.AddInPlace(res)
}

func (s *Server) MatrixTruncateRSSToAdditive(m *Matrix[Share128], out *Matrix[Uint128], decimals uint) {
        rows := m.NRows()
        cols := m.NCols()
       
	clear(out.Data)

        for i := uint64(0); i < rows; i++ {
                for j := uint64(0); j < cols; j++ {
			s.truncateRSSToAdditivePart1Write(&m.Data[i*cols+j], &out.Data[i*cols+j], decimals, i % s.prgs[0].Len())
                }
        }

	s.SendMsgs()

	dstToSquare := MatrixZeros[Uint128](out.Rows, out.Cols)
        for i := uint64(0); i < rows; i++ {
                for j := uint64(0); j < cols; j++ {
                        s.truncateRSSToAdditivePart1Read(&m.Data[i*cols+j], &out.Data[i*cols+j], &dstToSquare.Data[i*cols+j], decimals)
                }
        }

        for i := uint64(0); i < rows; i++ {
                for j := uint64(0); j < cols; j++ {
                        s.truncateRSSToAdditivePart2Write(&m.Data[i*cols+j], &dstToSquare.Data[i*cols+j], i % s.prgs[0].Len())
                }
        }

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.SendMsgs()
	}()

        for i := uint64(0); i < rows; i++ {
                for j := uint64(0); j < cols; j++ {
                        s.truncateRSSToAdditivePart2Read(&m.Data[i*cols+j], &out.Data[i*cols+j])
                }
        }

	wg.Wait()
}

func (s *Server) MatrixRecoverFromAdditiveDst(m *Matrix[Uint128], out *Matrix[uint64]) {
        rows := m.Rows
        cols := m.Cols
	clear(out.Data)

        var u, v Uint128
        for i := uint64(0); i < rows; i++{
                for j := uint64(0); j < cols; j++ {
                        if s.Id == 1  || s.Id == 2{
                                s.network.AppendUint128(0, &m.Data[i*cols+j])

                        } else if s.Id == 0 {
                                s.network.RecvUint128(1, &u)
                                s.network.RecvUint128(2, &v)
				u.AddInPlace(&v)
                                u.AddInPlace(&m.Data[i*cols+j])
                                if !CheckUint64(&u) {
                                         u.Print()
                                         panic("ToMatrix64: value does not fit in Uint64!")
                                }
                                out.Data[i*cols+j] = ToUint64(&u)
                        }
                }
        }

        s.SendMsgs()

	if s.Id == 0 {
		fmt.Printf("Recovered after additive reconstruct (%d by %d): norm %d\n", out.Rows, out.Cols, GetNorm(out, 0))
	}
}

func (s *Server) additiveToRSS128(src *Uint128) *Share128 {
	dst := new(Share128)
	s.additiveToRSS128Dst(src, dst, 0 /* prg index */)
	return dst
}

func (s *Server) additiveToRSS128Dst(src *Uint128, dst *Share128, prgIndex uint64) {
	s.additiveToRSSWrite(src, dst, prgIndex)

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		s.SendMsgs()
	}()

	s.additiveToRSSRead(dst)
	wg.Wait()
}

func (s *Server) additiveToRSSWrite(src *Uint128, dst *Share128, prgIndex uint64) {
        if s.Id == 0 {
                r01_hi, r01_lo := s.prgs[1].At(prgIndex).TwoUint64()
                r02_hi, r02_lo := s.prgs[2].At(prgIndex).TwoUint64()

                AddTwoHalvesDst(src, r01_hi, r01_lo, r02_hi, r02_lo, &dst.Second) // known
                s.network.AppendUint128(2, &dst.Second)

        } else if s.Id == 1 {
                r01_hi, r01_lo := s.prgs[0].At(prgIndex).TwoUint64()
                r12_hi, r12_lo := s.prgs[2].At(prgIndex).TwoUint64()

                SubTwoHalvesDst(src, r01_hi, r01_lo, r12_hi, r12_lo, &dst.Second)
                s.network.AppendUint128(0, &dst.Second)

        } else if s.Id == 2 {
                r02_hi, r02_lo := s.prgs[0].At(prgIndex).TwoUint64()
                r12_hi, r12_lo := s.prgs[1].At(prgIndex).TwoUint64()

                AddSubTwoHalvesDst(src, r12_hi, r12_lo, r02_hi, r02_lo, &dst.Second)
                s.network.AppendUint128(1, &dst.Second)
        }
}

func (s *Server) additiveToRSSRead(dst *Share128) {
        if s.Id == 0 {
                s.network.RecvUint128(1, &dst.First)
        } else if s.Id == 1 {
                s.network.RecvUint128(2, &dst.First)
        } else if s.Id == 2 {
                s.network.RecvUint128(0, &dst.First)
        }
}

// Requires 1 round of communication
func (s *Server) MatrixAdditiveToRSSDst(m *Matrix[Uint128], out *Matrix[Share128]) {
        rows := m.Rows
        cols := m.Cols

        clear(out.Data)

	// Servers write to channels: A->B, B->C, C->A
        for i := uint64(0); i < rows; i++ {
                for j := uint64(0); j < cols; j++ {
			s.additiveToRSSWrite(&m.Data[i*cols+j], &out.Data[i*cols+j], i % s.prgs[0].Len())
                }
        }

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.SendMsgs()
	}()

	for i := uint64(0); i < rows; i++ {
	        for j := uint64(0); j < cols; j++ {
                         s.additiveToRSSRead(&out.Data[i*cols+j])
                }
        }

	wg.Wait()
}

// Non-interactively: Get shares of 2^{-MSB(||v||^2)/2}
func (s *Server) estimateInvSqrt(eval []Uint128, decimals, norm_decimals uint, dst *Uint128) {
	for i := 0; i < 128; i++ {
 		index := 127 - i - int(decimals)
 		index /= 2 // NOTE: This is a floor instead of a ceil
                if int(norm_decimals) >= index {
			coeff := MakeUint128(0, 1)
                        coeff.LshInPlace(uint(int(norm_decimals) - index))
                	eval[i].MulInPlace(coeff)
                	dst.AddInPlace(&eval[i])
		}
       }
}

func (s *Server) VectorNormalizeRSSInPlace(v *Matrix[Share128], decimals, norm_decimals, newton_iters uint) {
        // Build additive shares of ||v||^2
        vsq_add := MatrixSum(MatrixTransposeMulRSS(v, v)) // same as v.T * v

        // Build RSS shares of ||v||^2
	vsq_rss := s.additiveToRSS128(vsq_add)

        // Truncate RSS shares of ||v||^2
	vsq_add = s.truncateRSSToAdditive128(vsq_rss, decimals)

        // ... and back to RSS shares
	vsq_rss = s.additiveToRSS128(vsq_add)

        // Get secret shares of bitlen of ||v||^2
	if s.Id == 0 {
        	r := vsq_rss.ShareSum()
        	r.NegateInPlace()

        	keyL, keyR := dmsb.Gen128(r, 128)
		s.network.AppendDmsbKey(1, &keyL)
		s.network.AppendDmsbKey(2, &keyR)
	}

	s.SendMsgs()
	y_cur_add := MakeUint128(0, 0)

	if s.Id == 1 {
        	y := &vsq_rss.First

		var key dmsb.DMSBkey128
		s.network.RecvDmsbKey(0, &key)
        	evalL := dmsb.Eval128(key, y, 128, 0)
		s.estimateInvSqrt(evalL, decimals, norm_decimals, y_cur_add)

	} else if s.Id == 2 {
		y := &vsq_rss.Second

		var key dmsb.DMSBkey128
		s.network.RecvDmsbKey(0, &key)
        	evalR := dmsb.Eval128(key, y, 128, 1)
		s.estimateInvSqrt(evalR, decimals, norm_decimals, y_cur_add)
	}

        // Make RSS shares of starting point to Newton iteration
	y_cur_rss := s.additiveToRSS128(y_cur_add)
        three := MakeUint128(0, 3)
        three.LshInPlace(norm_decimals)

        // Perform Newton iteration to refine approximation
        for i := uint(0); i < newton_iters; i++ {
                // (1) perform x * y
                x_times_y_add := MulRSS128(y_cur_rss, vsq_rss)

                // to RSS
                x_times_y_rss := s.additiveToRSS128(x_times_y_add)

                // truncate (after mul...)
                x_times_y_add = s.truncateRSSToAdditive128(x_times_y_rss, decimals)

                // to RSS
                x_times_y_rss = s.additiveToRSS128(x_times_y_add)

                // (2) perform x * y * y
                x_times_ysq_add := MulRSS128(y_cur_rss, x_times_y_rss)

                // to RSS
                x_times_ysq_rss := s.additiveToRSS128(x_times_ysq_add)

                // truncate (after mul...)
                x_times_ysq_add = s.truncateRSSToAdditive128(x_times_ysq_rss, norm_decimals)

                // to RSS
                x_times_ysq_rss = s.additiveToRSS128(x_times_ysq_add)

                // (3) perform y * (3 - x * y * y) / 2
                PtxtSubRSSInPlace128(x_times_ysq_rss, three, s.Id) // compute shares of 3 - x * y * y 
                outer_add := MulRSS128(y_cur_rss, x_times_ysq_rss)

                // to RSS
                outer_rss := s.additiveToRSS128(outer_add)

                // truncate (after mul...)
		outer_add = s.truncateRSSToAdditive128(outer_rss, norm_decimals+1)

                // to RSS
                y_cur_rss = s.additiveToRSS128(outer_add)
        }

        // multiply by vector
        v_add := MatrixScalarMulRSS(y_cur_rss, v)

        // to RSS
        s.MatrixAdditiveToRSSDst(v_add, v)

        // truncate again
	s.MatrixTruncateRSSToAdditive(v, v_add, norm_decimals)
        s.MatrixAdditiveToRSSDst(v_add, v)
}

func (s *Server) recoverFromAdditive(v *Uint128) uint64 {
        var interm, interm2 Uint128

        if s.Id == 1 || s.Id == 2 {
                s.network.AppendUint128(0, v)
        }

	s.SendMsgs()

        if s.Id == 0 {
                s.network.RecvUint128(1, &interm)
                interm.AddInPlace(v)
                s.network.RecvUint128(2, &interm2)
                interm.AddInPlace(&interm2)

                s.network.AppendUint128(1, &interm)
                s.network.AppendUint128(2, &interm)

        }

	s.SendMsgs()

        if s.Id == 1 || s.Id == 2 {
                s.network.RecvUint128(0, &interm)
        }

        if DebugMode && !CheckUint64(&interm) {
                interm.Print()
                panic("Secret shared value does not fit in 64 bits")
        }

        return ToUint64(&interm)
}

func (s *Server) recoverFromRSS(rss *Share128) uint64 {
	var interm, interm2 Uint128

	if s.Id == 0 {
        	AddDst(&rss.First, &rss.Second, &interm)
                s.network.AppendUint128(1, &interm)
                s.network.AppendUint128(2, &interm)
	} else if s.Id == 1 {
                s.network.AppendUint128(0, &rss.First)
	}

	s.SendMsgs()

	if s.Id == 0 {
                s.network.RecvUint128(1, &interm2)
                interm.AddInPlace(&interm2)

        } else if s.Id == 1 {
                s.network.RecvUint128(0, &interm2)
                AddDst(&rss.First, &interm2, &interm)

       } else if s.Id == 2 {
                s.network.RecvUint128(0, &interm2)
                AddDst(&rss.Second, &interm2, &interm)
       }

       if DebugMode && !CheckUint64(&interm) {
                interm.Print()
                panic("Secret shared value does not fit in 64 bits")
       }

       return ToUint64(&interm)
}

func (s *Server) MatrixRecoverFromRSSDst(m *Matrix[Share128], out *Matrix[uint64]) {
	rows := m.Rows
        cols := m.Cols

	var intermMat *Matrix[Uint128]
	if s.Id == 0 {
		intermMat = MatrixZeros[Uint128](rows, cols)
	}

	clear(out.Data)

	var interm, interm2 Uint128
        for i := uint64(0); i < rows; i++ {
                for j := uint64(0); j < cols; j++ {
			if s.Id == 0 {
				AddDst(&m.Data[i*cols+j].First, &m.Data[i*cols+j].Second, &interm)
				s.network.AppendUint128(1, &interm)
				s.network.AppendUint128(2, &interm)
				
				// Copy interm over to memory
				Copy(&interm, &intermMat.Data[i*cols+j])

			} else if s.Id == 1 {
				s.network.AppendUint128(0, &m.Data[i*cols+j].First)
			}
		}
        }

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.SendMsgs()
	}()

        for i := uint64(0); i < rows; i++ {
                for j := uint64(0); j < cols; j++ {
                        if s.Id == 0 {
                                s.network.RecvUint128(1, &interm)
                                interm.AddInPlace(&intermMat.Data[i*cols+j])
                        } else if s.Id == 1 {
                                s.network.RecvUint128(0, &interm2)
                                AddDst(&m.Data[i*cols+j].First, &interm2, &interm)
                        } else if s.Id == 2 {
                                s.network.RecvUint128(0, &interm2)
                                AddDst(&m.Data[i*cols+j].Second, &interm2, &interm)
                        }

                        if DebugMode && !CheckUint64(&interm) {
                                interm.Print()
                                panic("Secret shared value does not fit in 64 bits")
                        }

                        out.Data[i*cols+j] = ToUint64(&interm)
                }
        }

	wg.Wait()
}

func (s *Server) SendMsgs() {
	s.network.SendOutgoingMsgs()
}

func (s *Server) Teardown() {
	s.network.Close()
}
