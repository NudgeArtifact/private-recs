// Adapted from: https://github.com/dkales/dpf-go/blob/master/dpf/aes.go
//               https://github.com/dimakogan/dpf-go/blob/master/dpf/aes.go

// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package multdpf

// defined in asm_amd64.s
// extern Xor16
func Xor16(dst, a, b *byte)
func EncryptAes128(xk *uint32, dst, src *byte)
func Aes128MMO(xk *uint32, dst, src *byte)
func ExpandKeyAsm(key *byte, enc *uint32)

type AesPrf struct {
	enc []uint32
}

func NewCipher(key []byte) (*AesPrf, error) {
	n := 11 * 4
	c := AesPrf{make([]uint32, n)}
	ExpandKeyAsm(&key[0], &c.enc[0])
	return &c, nil
}

func (c *AesPrf) BlockSize() int { return 16 }

func (c *AesPrf) Encrypt(dst, src []byte) {
	EncryptAes128(&c.enc[0], &dst[0], &src[0])
}
