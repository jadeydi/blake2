package blake2s

import (
	// #cgo CFLAGS: -O3
	// #include "blake2.h"
	"C"
	"hash"
	"unsafe"
)

type digest struct {
	blockSize  int
	state      C.blake2s_state
	key        []byte
	param      C.blake2s_param
	isLastNode bool
}

// Tree contains parameters for tree hashing. Each node in the tree
// can be hashed concurrently, and incremental changes can be done in
// a Merkle tree fashion.
type Tree struct {
	// Fanout: how many children each tree node has. 0 for unlimited.
	// 1 means sequential mode.
	Fanout uint8
	// Maximal depth of the tree. Beyond this height, nodes are just
	// added to the root of the tree. 255 for unlimited. 1 means
	// sequential mode.
	MaxDepth uint8
	// Leaf maximal byte length, how much data each leaf summarizes. 0
	// for unlimited or sequential mode.
	LeafSize uint32
	// Depth of this node. 0 for leaves or sequential mode.
	NodeDepth uint8
	// Offset of this node within this level of the tree. 0 for the
	// first, leftmost, leaf, or sequential mode.
	NodeOffset uint32
	// Inner hash byte length, in the range [0, 64]. 0 for sequential
	// mode.
	InnerHashSize uint8

	// IsLastNode indicates this node is the last, rightmost, node of
	// a level of the tree.
	IsLastNode bool
}

// Config contains parameters for the hash function that affect its
// output.
type Config struct {
	// Digest byte length, in the range [1, 64]. If 0, default size of 64 bytes is used.
	Size uint8
	// Key is up to 64 arbitrary bytes, for keyed hashing mode. Can be nil.
	Key []byte
	// Salt is up to 16 arbitrary bytes, used to randomize the hash. Can be nil.
	Salt []byte
	// Personal is up to 16 arbitrary bytes, used to make the hash
	// function unique for each application. Can be nil.
	Personal []byte

	// Parameters for tree hashing. Set to nil to use default
	// sequential mode.
	Tree *Tree
}

// New returns a new custom blake2s hash.
//
// If config is nil, uses a 64-byte digest size.
func New(config *Config) *digest {
	d := &digest{
		blockSize: 64,
		param: C.blake2s_param{
			digest_length: 32,
			fanout:        1,
			depth:         1,
		},
	}
	if config != nil {
		if config.Size != 0 {
			d.param.digest_length = C.uint8_t(config.Size)
		}
		if len(config.Key) > 0 {
			// let the C library worry about the exact limit; we just
			// worry about fitting into the variable
			if len(config.Key) > 255 {
				panic("blake2s key too long")
			}
			d.param.key_length = C.uint8_t(len(config.Key))
			d.key = config.Key
		}
		salt := (*[C.BLAKE2S_SALTBYTES]byte)(unsafe.Pointer(&d.param.salt[0]))
		copy(salt[:], config.Salt)
		personal := (*[C.BLAKE2S_PERSONALBYTES]byte)(unsafe.Pointer(&d.param.personal[0]))
		copy(personal[:], config.Personal)

		if config.Tree != nil {
			d.param.fanout = C.uint8_t(config.Tree.Fanout)
			d.param.depth = C.uint8_t(config.Tree.MaxDepth)
			d.param.leaf_length = C.uint32_t(config.Tree.LeafSize)
			d.param.node_offset = C.uint32_t(config.Tree.NodeOffset)
			d.param.node_depth = C.uint8_t(config.Tree.NodeDepth)
			d.param.inner_length = C.uint8_t(config.Tree.InnerHashSize)

			d.isLastNode = config.Tree.IsLastNode
		}
	}
	d.Reset()
	return d
}

// New256 returns a new 256-bit BLAKE2S hash with the given secret key.
func New256(key []byte) hash.Hash {
	d := New(nil)
	if C.blake2s_init_key(&d.state, C.size_t(32), unsafe.Pointer(&key[0]), C.size_t(len(key))) < 0 {
		panic("blake2s: unable to init key")
	}
	return d
}

func (d *digest) BlockSize() int {
	return d.blockSize
}

func (d *digest) Size() int {
	return int(d.param.digest_length)
}

func (d *digest) Reset() {
	if C.blake2s_init_param(&d.state, &d.param) < 0 {
		panic("blake2s: unable to reset")
	}
	if d.isLastNode {
		d.state.last_node = C.uint8_t(1)
	}
}

func (d *digest) Write(buf []byte) (int, error) {
	if len(buf) > 0 {
		C.blake2s_update(&d.state, unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	}
	return len(buf), nil
}

func (d *digest) Sum(buf []byte) []byte {
	digest := make([]byte, d.Size())
	// Make a copy of d.state so that caller can keep writing and summing.
	s := d.state
	C.blake2s_final(&s, unsafe.Pointer(&digest[0]), C.size_t(d.Size()))
	return append(buf, digest...)
}
