package main

// hiddenServe handles control messages that only hidden services use.
// (filled in by the hidden-service commit)
func (n *Node) hiddenServe(typ byte, body []byte) (byte, []byte, bool) { return 0, nil, false }
