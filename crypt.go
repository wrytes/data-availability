package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"hash"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// Cascade of independent AEAD layers. Each layer has its own cipher AND its own
// key derived with its own hash function (HKDF-SHA256 / SHA3-256 / BLAKE2b), so
// breaking one primitive family does not expose the plaintext.
type layer struct {
	name string
	hash func() hash.Hash
	aead func(key []byte) (cipher.AEAD, error)
}

var layers = []layer{
	{"aes256gcm+hkdf-sha256", sha256.New, func(k []byte) (cipher.AEAD, error) {
		b, err := aes.NewCipher(k)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(b)
	}},
	{"xchacha20poly1305+hkdf-sha3-256", sha3.New256, chacha20poly1305.NewX},
	{"chacha20poly1305+hkdf-blake2b-256", func() hash.Hash { h, _ := blake2b.New256(nil); return h }, chacha20poly1305.New},
}

func layerNames() []string {
	var s []string
	for _, l := range layers {
		s = append(s, l.name)
	}
	return s
}

func layerAEAD(master []byte, l layer) (cipher.AEAD, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(l.hash, master, nil, []byte("da/v1/"+l.name)), key); err != nil {
		return nil, err
	}
	return l.aead(key)
}

// seal wraps plaintext innermost->outermost: layer 0 first.
func seal(master, pt []byte) ([]byte, error) {
	data := pt
	for i, l := range layers {
		a, err := layerAEAD(master, l)
		if err != nil {
			return nil, err
		}
		nonce := make([]byte, a.NonceSize(), a.NonceSize()+len(data)+a.Overhead())
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		data = a.Seal(nonce, nonce, data, []byte{byte(i)})
	}
	return data, nil
}

func open(master, ct []byte) ([]byte, error) {
	data := ct
	for i := len(layers) - 1; i >= 0; i-- {
		a, err := layerAEAD(master, layers[i])
		if err != nil {
			return nil, err
		}
		ns := a.NonceSize()
		if len(data) < ns+a.Overhead() {
			return nil, errors.New("ciphertext too short")
		}
		data, err = a.Open(nil, data[:ns], data[ns:], []byte{byte(i)})
		if err != nil {
			return nil, errors.New("decrypt failed at layer " + layers[i].name)
		}
	}
	return data, nil
}
