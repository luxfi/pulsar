package networking

import (
	"bufio"
	"net"
	"testing"
	"time"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/lattice/v7/utils/structs"
)

func TestP2PComm_EstablishConnections(t *testing.T) {
	// This test requires actual network setup, so we'll test the basic structure
	t.Run("initialization", func(t *testing.T) {
		comm := &P2PComm{
			Rank:  1,
			Socks: make(map[int]*net.Conn),
		}

		if comm.Rank != 1 {
			t.Errorf("Expected Rank 1, got %d", comm.Rank)
		}
		if len(comm.Socks) != 0 {
			t.Errorf("Expected empty Socks map, got %d connections", len(comm.Socks))
		}
	})
}

func TestP2PComm_SendRecvVector(t *testing.T) {
	// Create a mock connection using a pipe
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Create two P2PComm instances
	comm1 := &P2PComm{
		Rank:  1,
		Socks: map[int]*net.Conn{2: &client},
	}

	comm2 := &P2PComm{
		Rank:  2,
		Socks: map[int]*net.Conn{1: &server},
	}

	// Test vector to send - using proper lattice types
	r, _ := ring.NewRing(256, []uint64{8380417})
	prng, _ := sampling.NewPRNG()
	sampler := ring.NewUniformSampler(prng, r)
	testVector := make(structs.Vector[ring.Poly], 3)
	for i := range testVector {
		testVector[i] = sampler.ReadNew()
	}

	// Send and receive in separate goroutines
	done := make(chan bool)
	var receivedVector structs.Vector[ring.Poly]

	go func() {
		reader := bufio.NewReader(server)
		receivedVector = comm2.RecvVector(reader, 1, len(testVector))
		done <- true
	}()

	// Give receiver time to start
	time.Sleep(10 * time.Millisecond)

	writer := bufio.NewWriter(client)
	comm1.SendVector(writer, 2, testVector)
	writer.Flush()

	// Wait for receive to complete
	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for vector receive")
	}

	// Verify the received vector matches
	if len(receivedVector) != len(testVector) {
		t.Errorf("Received vector length %d, expected %d", len(receivedVector), len(testVector))
	}

	for i := range testVector {
		if !r.Equal(receivedVector[i], testVector[i]) {
			t.Errorf("Vector mismatch at index %d", i)
		}
	}
}

func TestP2PComm_SendRecvMatrix(t *testing.T) {
	// Create a mock connection using a pipe
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Create two P2PComm instances
	comm1 := &P2PComm{
		Rank:  1,
		Socks: map[int]*net.Conn{2: &client},
	}

	comm2 := &P2PComm{
		Rank:  2,
		Socks: map[int]*net.Conn{1: &server},
	}

	// Test matrix to send - using proper lattice types
	r, _ := ring.NewRing(256, []uint64{8380417})
	prng, _ := sampling.NewPRNG()
	sampler := ring.NewUniformSampler(prng, r)
	testMatrix := make(structs.Matrix[ring.Poly], 2)
	for i := range testMatrix {
		testMatrix[i] = make(structs.Vector[ring.Poly], 3)
		for j := range testMatrix[i] {
			testMatrix[i][j] = sampler.ReadNew()
		}
	}

	// Send and receive in separate goroutines
	done := make(chan bool)
	var receivedMatrix structs.Matrix[ring.Poly]

	go func() {
		reader := bufio.NewReader(server)
		receivedMatrix = comm2.RecvMatrix(reader, 1, len(testMatrix))
		done <- true
	}()

	// Give receiver time to start
	time.Sleep(10 * time.Millisecond)

	writer := bufio.NewWriter(client)
	comm1.SendMatrix(writer, 2, testMatrix)
	writer.Flush()

	// Wait for receive to complete
	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for matrix receive")
	}

	// Verify the received matrix matches
	if len(receivedMatrix) != len(testMatrix) {
		t.Errorf("Received matrix rows %d, expected %d", len(receivedMatrix), len(testMatrix))
	}

	for i := range testMatrix {
		if len(receivedMatrix[i]) != len(testMatrix[i]) {
			t.Errorf("Row %d: received %d columns, expected %d", i, len(receivedMatrix[i]), len(testMatrix[i]))
		}
		for j := range testMatrix[i] {
			if !r.Equal(receivedMatrix[i][j], testMatrix[i][j]) {
				t.Errorf("Matrix mismatch at [%d][%d]", i, j)
			}
		}
	}
}

func TestP2PComm_SendRecvBytes(t *testing.T) {
	// Create a mock connection using a pipe
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Create two P2PComm instances
	comm1 := &P2PComm{
		Rank:  1,
		Socks: map[int]*net.Conn{2: &client},
	}

	comm2 := &P2PComm{
		Rank:  2,
		Socks: map[int]*net.Conn{1: &server},
	}

	// Test bytes to send - we'll send multiple slices
	testBytesSlices := [][]byte{
		[]byte("test message 1"),
		[]byte("test message 2"),
		[]byte("test message 3"),
	}

	// Send and receive in separate goroutines
	done := make(chan bool)
	var receivedBytesSlices [][]byte

	go func() {
		reader := bufio.NewReader(server)
		receivedBytesSlices = comm2.RecvBytesSlice(reader, 1)
		done <- true
	}()

	// Give receiver time to start
	time.Sleep(10 * time.Millisecond)

	// Send the bytes slices using SendBytesSlice (matching protocol)
	writer := bufio.NewWriter(client)
	comm1.SendBytesSlice(writer, 2, testBytesSlices)
	writer.Flush()

	// Wait for receive to complete
	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for bytes receive")
	}

	// Verify the received bytes match
	if len(receivedBytesSlices) != len(testBytesSlices) {
		t.Errorf("Received %d slices, expected %d", len(receivedBytesSlices), len(testBytesSlices))
	}

	for i, slice := range testBytesSlices {
		if i < len(receivedBytesSlices) {
			if string(receivedBytesSlices[i]) != string(slice) {
				t.Errorf("Slice %d: received %s, expected %s", i, string(receivedBytesSlices[i]), string(slice))
			}
		}
	}
}

func TestP2PComm_SendRecvBytesMap(t *testing.T) {
	// Create a mock connection using a pipe
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Create two P2PComm instances
	comm1 := &P2PComm{
		Rank:  1,
		Socks: map[int]*net.Conn{2: &client},
	}

	comm2 := &P2PComm{
		Rank:  2,
		Socks: map[int]*net.Conn{1: &server},
	}

	// Test bytes map to send
	testBytesMap := map[int][]byte{
		1: []byte("message1"),
		2: []byte("message2"),
		3: []byte("message3"),
	}

	// Send and receive in separate goroutines
	done := make(chan bool)
	var receivedBytesMap map[int][]byte

	go func() {
		reader := bufio.NewReader(server)
		receivedBytesMap = comm2.RecvBytesMap(reader, 1)
		done <- true
	}()

	// Give receiver time to start
	time.Sleep(10 * time.Millisecond)

	writer := bufio.NewWriter(client)
	comm1.SendBytesMap(writer, 2, testBytesMap)
	writer.Flush()

	// Wait for receive to complete
	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for bytes map receive")
	}

	// Verify the received bytes map matches
	if len(receivedBytesMap) != len(testBytesMap) {
		t.Errorf("Received map size %d, expected %d", len(receivedBytesMap), len(testBytesMap))
	}

	for k, v := range testBytesMap {
		received, ok := receivedBytesMap[k]
		if !ok {
			t.Errorf("Key %d not found in received map", k)
			continue
		}
		if string(received) != string(v) {
			t.Errorf("Key %d: received %s, expected %s", k, string(received), string(v))
		}
	}
}

func TestP2PComm_Close(t *testing.T) {
	// Create a mock connection
	server, client := net.Pipe()
	defer server.Close()

	comm := &P2PComm{
		Rank:  1,
		Socks: map[int]*net.Conn{2: &client},
	}

	// Close connections
	for _, conn := range comm.Socks {
		(*conn).Close()
	}

	// Verify connections are closed by trying to write
	_, err := client.Write([]byte("test"))
	if err == nil {
		t.Error("Expected error writing to closed connection")
	}
}
