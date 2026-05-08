package ipc

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
)

const (
	maxMessageSize = 16 * 1024 * 1024 // 16MB
	headerSize     = 4                 // uint32 big-endian
)

// WriteEnvelope marshals an AegisEnvelope to JSON and writes it with
// a 4-byte big-endian length prefix to the connection.
func WriteEnvelope(conn net.Conn, env *AegisEnvelope) error {
	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	length := uint32(len(data))
	if err := binary.Write(conn, binary.BigEndian, length); err != nil {
		return fmt.Errorf("write length prefix: %w", err)
	}

	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}

	return nil
}

// ReadEnvelope reads a length-prefixed envelope from the connection.
// Uses io.ReadFull to handle partial reads on stream sockets.
func ReadEnvelope(conn net.Conn) (*AegisEnvelope, error) {
	var length uint32
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("read length prefix: %w", err)
	}

	if length > maxMessageSize {
		return nil, fmt.Errorf("message too large: %d bytes (max %d)", length, maxMessageSize)
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("read payload (%d bytes): %w", length, err)
	}

	var env AegisEnvelope
	if err := json.Unmarshal(buf, &env); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}

	return &env, nil
}
