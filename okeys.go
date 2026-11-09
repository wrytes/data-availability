package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"time"
)

// Forward secrecy for onion routing.
//
// A relay used to peel packets with its long-term key, so anyone who recorded
// traffic and later got hold of that key could decrypt every hop it ever saw.
// Now relays peel with short-lived onion keys:
//
//   - a fresh X25519 key every OnionKeyLife/2, independent of the identity key
//   - announced as a certificate  ok(32) | expiry u32 | sig(64)  signed by the
//     node's identity, so gossiped keys cannot be swapped by a middleman
//   - kept for OnionKeyLife plus a grace period (reply blocks that are still in
//     flight), then deleted
//
// After deletion nobody, including the node itself, can decrypt a packet that
// was addressed to that key. Each hop's layer already used a fresh sender
// ephemeral; this closes the other half of the exchange.
const certLen = 32 + 4 + 64

type okey struct {
	priv         *ecdh.PrivateKey
	pub          [32]byte
	created, exp time.Time
	drop         time.Time
}

func (n *Node) okLife() time.Duration {
	if n.cfg.OnionKeyLife > 0 {
		return n.cfg.OnionKeyLife
	}
	return 10 * time.Minute
}

func certMsg(ok []byte, exp uint32) []byte {
	m := append([]byte("da/okey/v1"), ok...)
	return binary.BigEndian.AppendUint32(m, exp)
}

// rotateKeys makes sure there is a young onion key and forgets expired ones.
func (n *Node) rotateKeys() {
	now := time.Now()
	life := n.okLife()
	n.okMu.Lock()
	defer n.okMu.Unlock()
	if len(n.okeys) == 0 || now.Sub(n.okeys[len(n.okeys)-1].created) >= life/2 {
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err == nil {
			ok := &okey{priv: k, created: now, exp: now.Add(life), drop: now.Add(life + life/2)}
			copy(ok.pub[:], k.PublicKey().Bytes())
			n.okeys = append(n.okeys, ok)
		}
	}
	keep := n.okeys[:0]
	for _, k := range n.okeys {
		if now.Before(k.drop) {
			keep = append(keep, k)
		}
	}
	n.okeys = keep
}

// myOnionKey is the key others should currently use to reach us, with its certificate.
func (n *Node) myOnionKey() (pub [32]byte, cert []byte) {
	n.okMu.Lock()
	defer n.okMu.Unlock()
	k := n.okeys[len(n.okeys)-1]
	exp := uint32(k.exp.Unix())
	cert = append(append([]byte{}, k.pub[:]...), binary.BigEndian.AppendUint32(nil, exp)...)
	cert = append(cert, ed25519.Sign(n.sk, certMsg(k.pub[:], exp))...)
	return k.pub, cert
}

// peelAny tries the node's live onion keys, newest first.
func (n *Node) peelAny(h onionHeader) (peeled, error) {
	n.okMu.Lock()
	ks := append([]*okey(nil), n.okeys...)
	n.okMu.Unlock()
	var err error
	for i := len(ks) - 1; i >= 0; i-- {
		var p peeled
		if p, err = peelHeader(ks[i].priv, h); err == nil {
			return p, nil
		}
	}
	return peeled{}, err
}

// verifyCert checks a certificate against the identity that should have signed it.
func verifyCert(ik [32]byte, c []byte) (ok [32]byte, exp time.Time, valid bool) {
	if len(c) != certLen {
		return
	}
	copy(ok[:], c[:32])
	e := binary.BigEndian.Uint32(c[32:36])
	if !ed25519.Verify(ik[:], certMsg(c[:32], e), c[36:]) {
		return
	}
	return ok, time.Unix(int64(e), 0), true
}
