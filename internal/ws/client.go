package ws

import (
	"context"
	"time"

	"github.com/coder/websocket"
)

const (
	sendBuf      = 256
	writeTimeout = 10 * time.Second
	pongWait     = 60 * time.Second
)

// Client is a middleman between the websocket connection and the hub.
type Client struct {
	hub  *Hub
	conn *websocket.Conn
	send chan []byte
}

func NewClient(hub *Hub, conn *websocket.Conn) *Client {
	return &Client{
		hub:  hub,
		conn: conn,
		send: make(chan []byte, sendBuf),
	}
}

// writePump pumps messages from the send channel to the websocket connection.
// Only this goroutine writes to the connection.
func (c *Client) writePump(ctx context.Context) {
	defer func() {
		c.conn.CloseNow()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-c.send:
			if !ok {
				c.conn.Close(websocket.StatusGoingAway, "server shutdown")
				return
			}
			writeCtx, cancel := context.WithTimeout(ctx, writeTimeout)
			err := c.conn.Write(writeCtx, websocket.MessageText, msg)
			cancel()
			if err != nil {
				return
			}
		}
	}
}

// readPump reads from the websocket connection to detect disconnects.
// It discards all incoming messages — only used to detect close/errors.
func (c *Client) readPump(ctx context.Context) {
	defer func() {
		c.hub.unregister <- c
		c.conn.CloseNow()
	}()

	for {
		_, _, err := c.conn.Read(ctx)
		if err != nil {
			return
		}
	}
}

// Serve registers the client with the hub and starts the read/write pumps.
func (c *Client) Serve(ctx context.Context) {
	c.hub.register <- c
	go c.writePump(ctx)
	c.readPump(ctx)
}
