package ws

import (
	"context"
	"sync"
)

const (
	replaySize     = 100
	broadcastBuf   = 256
	registerBuf    = 16
	unregisterBuf  = 16
)

// Hub maintains the set of active WebSocket clients and broadcasts messages.
type Hub struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	replay     *RingBuffer
	done       chan struct{}
	mu         sync.RWMutex
}

// RingBuffer is a fixed-size circular buffer for replaying recent events.
type RingBuffer struct {
	buf  [][]byte
	pos  int
	full bool
	mu   sync.Mutex
}

func NewRingBuffer(size int) *RingBuffer {
	return &RingBuffer{buf: make([][]byte, size)}
}

func (r *RingBuffer) Write(data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	r.buf[r.pos] = cp
	r.pos++
	if r.pos >= len(r.buf) {
		r.pos = 0
		r.full = true
	}
}

// ReadAll returns all buffered messages in chronological order.
func (r *RingBuffer) ReadAll() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.full {
		result := make([][]byte, r.pos)
		copy(result, r.buf[:r.pos])
		return result
	}
	result := make([][]byte, len(r.buf))
	copy(result, r.buf[r.pos:])
	copy(result[len(r.buf)-r.pos:], r.buf[:r.pos])
	return result
}

func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan []byte, broadcastBuf),
		register:   make(chan *Client, registerBuf),
		unregister: make(chan *Client, unregisterBuf),
		replay:     NewRingBuffer(replaySize),
		done:       make(chan struct{}),
	}
}

// Run starts the hub's main event loop. It blocks until ctx is cancelled.
func (h *Hub) Run(ctx context.Context) {
	defer close(h.done)
	for {
		select {
		case <-ctx.Done():
			h.mu.Lock()
			for c := range h.clients {
				close(c.send)
				delete(h.clients, c)
			}
			h.mu.Unlock()
			return

		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()

			for _, msg := range h.replay.ReadAll() {
				select {
				case client.send <- msg:
				default:
				}
			}

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				close(client.send)
				delete(h.clients, client)
			}
			h.mu.Unlock()

		case msg := <-h.broadcast:
			h.replay.Write(msg)
			h.mu.RLock()
			for c := range h.clients {
				select {
				case c.send <- msg:
				default:
					// slow client — drop message
				}
			}
			h.mu.RUnlock()
		}
	}
}

// Broadcast sends a message to all connected clients. Non-blocking: drops if
// the broadcast channel is full.
func (h *Hub) Broadcast(msg []byte) {
	select {
	case h.broadcast <- msg:
	default:
	}
}

// ClientCount returns the number of currently connected clients.
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// Done returns a channel that is closed when the hub stops.
func (h *Hub) Done() <-chan struct{} {
	return h.done
}
