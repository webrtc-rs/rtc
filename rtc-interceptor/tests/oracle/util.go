package main

import "errors"

// Copies of pion/interceptor's internal/validation and internal/rtpbuffer constants.
const uint16SizeHalf = 1 << 15

func isPowerOfTwo(size uint16) error {
	for i := 0; i < 16; i++ {
		if size == 1<<i {
			return nil
		}
	}
	return errors.New("invalid buffer size")
}
