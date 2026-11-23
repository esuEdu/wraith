package simtest

import (
	"encoding/pem"
	"errors"
)

func decodePEM(b []byte) ([]byte, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("bad PEM")
	}
	return blk.Bytes, nil
}
