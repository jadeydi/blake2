package blake2s

import (
	"log"
	"testing"
)

func TestExampleNewKeyedBlake2S(t *testing.T) {
	h := New256([]byte("Squeamish Ossifrage"))
	h.Write([]byte("foo"))
	log.Printf("%x\n", h.Sum(nil))

	h = New(nil)
	h.Write([]byte("foo"))
	log.Printf("%x", h.Sum(nil))

	h = New(&Config{Personal: []byte("Shaftoe")})
	h.Write([]byte("foo"))
	log.Printf("%x", h.Sum(nil))

	h = New(&Config{Key: []byte("Squeamish Ossifrage"), Personal: []byte("Shaftoe")})
	h.Write([]byte("foo"))
	log.Printf("%x", h.Sum(nil))
}
