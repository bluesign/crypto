// +build relic

package crypto

// #cgo CFLAGS: -g -Wall -std=c99 -I./ -I./relic/include -I./relic/include/low
// #cgo LDFLAGS: -Lrelic/build/lib -l relic_s
// #include "dkg_include.h"
import "C"
import (
	log "github.com/sirupsen/logrus"
)

func (s *feldmanVSSstate) generateShares(seed []byte) *DKGoutput {
	seedRelic(seed)
	// Generate a polyomial P in Zr[X] of degree t
	s.a = make([]scalar, s.threshold+1)
	s.A = make([]pointG2, s.threshold+1)
	s.y = make([]pointG2, s.size)
	for i := 0; i < s.threshold+1; i++ {
		randZr(&s.a[i])
		_G2scalarGenMult(&s.A[i], &s.a[i])
	}

	// prepare the DKGToSend slice and compute the shares
	out := &DKGoutput{
		result: valid,
		err:    nil,
	}

	// s.size-1 DKGToSend to be sent to the other nodes
	// One DKGToSend to be broadcasted
	out.action = make([]DKGToSend, s.size)
	for i := index(1); int(i) <= s.size; i++ {
		// the leader own share
		if i-1 == s.currentIndex {
			xdata := make([]byte, shareSize)
			ZrPolynomialImage(xdata, s.a, i, &s.y[i-1])
			C.bn_read_bin((*C.bn_st)(&s.x),
				(*C.uchar)(&xdata[0]),
				PrKeyLenBLS_BLS12381,
			)
			continue
		}
		// the other node shares
		toSend := &(out.action[indexOrder(s.currentIndex, i-1)])
		toSend.broadcast = false
		toSend.dest = int(i - 1)

		data := make([]byte, shareSize+1)
		data[0] = byte(FeldmanVSSshare)
		ZrPolynomialImage(data[1:], s.a, i, &s.y[i-1])
		toSend.data = DKGmsg(data)
	}
	// prepare the DKGToSend to be broadcasted
	toBroadcast := &(out.action[s.size-1])
	toBroadcast.broadcast = true
	vectorSize := verifVectorSize * (s.threshold + 1)
	data := make([]byte, vectorSize+1)
	data[0] = byte(FeldmanVSSVerifVec)
	writeVerifVector(data[1:], s.A)
	toBroadcast.data = DKGmsg(data)

	s.AReceived = true
	s.xReceived = true
	return out
}

func (s *feldmanVSSstate) receiveShare(origin index, data []byte) DKGresult {
	// only accept private shares from the leader.
	if origin != s.leaderIndex {
		return invalid
	}

	if s.xReceived {
		return invalid
	}

	if (len(data)) != shareSize {
		return invalid
	}
	// temporary log
	log.Debugf("%d Receiving a share from %d\n", s.currentIndex, origin)
	log.Debugf("the share is %d\n", data)

	// read the node private share
	C.bn_read_bin((*C.bn_st)(&s.x),
		(*C.uchar)(&data[0]),
		PrKeyLenBLS_BLS12381,
	)

	s.xReceived = true
	if s.AReceived {
		return s.verifyShare()
	}
	return valid
}

func (s *feldmanVSSstate) receiveVerifVector(origin index, data []byte) DKGresult {
	// only accept the verification vector from the leader.
	if origin != s.leaderIndex {
		return invalid
	}
	if s.AReceived {
		return invalid
	}
	if verifVectorSize*(s.threshold+1) != len(data) {
		return invalid
	}

	// temporary log
	log.Debugf("%d Receiving vector from %d\n", s.currentIndex, origin)
	log.Debugf("the vector is %d\n", data)
	// read the verification vector
	s.A = make([]pointG2, s.threshold+1)
	readVerifVector(s.A, data)

	s.y = make([]pointG2, s.size)
	s.computePublicKeys()

	s.AReceived = true
	if s.xReceived {
		return s.verifyShare()
	}
	return valid
}

// ZrPolynomialImage computes P(x) = a_0 + a_1*x + .. + a_n*x^n (mod r) in Z/Zr
// r being the order of G1
// P(x) is written in dest, while g2^P(x) is written in y
// x being a small integer
func ZrPolynomialImage(dest []byte, a []scalar, x index, y *pointG2) {
	C.Zr_polynomialImage((*C.uchar)(&dest[0]),
		(*C.ep2_st)(y),
		(*C.bn_st)(&a[0]), (C.int)(len(a)),
		(C.uint8_t)(x),
	)
	/*if x == 2 || x == 3 {
		dest[2] = 255
	}*/
}

// writeVerifVector exports A vector into a slice of bytes
// assuming the slice length matches the vector length
func writeVerifVector(dest []byte, A []pointG2) {
	C.ep2_vector_write_bin((*C.uchar)(&dest[0]),
		(*C.ep2_st)(&A[0]),
		(C.int)(len(A)),
	)
}

// readVerifVector imports A vector from a slice of bytes,
// assuming the slice length matches the vector length
func readVerifVector(A []pointG2, src []byte) {
	C.ep2_vector_read_bin((*C.ep2_st)(&A[0]),
		(*C.uchar)(&src[0]),
		(C.int)(len(A)),
	)
}

func (s *feldmanVSSstate) verifyShare() DKGresult {
	// check y[current] == x.G2
	if C.verifyshare((*C.bn_st)(&s.x),
		(*C.ep2_st)(&s.y[s.currentIndex])) == 1 {
		return valid
	}
	return invalid
}

// computePublicKeys computes the nodes public keys from the verification vector
// y[i] = Q(i+1) for all nodes i, with:
//  Q(x) = A_0 + A_1*x + ... +  A_n*x^n  in G2
func (s *feldmanVSSstate) computePublicKeys() {
	C.G2_polynomialImages(
		(*C.ep2_st)(&s.y[0]), (C.int)(len(s.y)),
		(*C.ep2_st)(&s.A[0]), (C.int)(len(s.A)),
	)
}
