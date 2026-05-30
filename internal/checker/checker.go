package checker

import "net"

// Result holds the validation outcome for an endpoint.
type Result struct {
	Address   string
	Reachable bool
	Abused    bool
	Pure      bool
	Latency   int64 // milliseconds
}

// Check performs a basic TCP connectivity check.
func Check(address string) (*Result, error) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return &Result{Address: address, Reachable: false}, nil
	}
	defer conn.Close()
	return &Result{Address: address, Reachable: true}, nil
}
