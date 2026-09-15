// Copyright (c) 2021 VMware, Inc. or its affiliates. All Rights Reserved.
// Copyright (c) 2012-2021, Sean Treadway, SoundCloud Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package amqp091

import (
	"encoding/binary"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNegotiationEnforcesFrameMinSize(t *testing.T) {
	tests := []struct {
		name             string
		clientFrameSize  int
		serverFrameMax   int
		expectedFrameMin int
	}{
		{
			name:             "client unlimited, server below min",
			clientFrameSize:  0,
			serverFrameMax:   1,
			expectedFrameMin: frameMinSize,
		},
		{
			name:             "client below min, server unlimited",
			clientFrameSize:  2048,
			serverFrameMax:   0,
			expectedFrameMin: frameMinSize,
		},
		{
			name:             "client unlimited, server unlimited",
			clientFrameSize:  0,
			serverFrameMax:   0,
			expectedFrameMin: 0,
		},
		{
			name:             "client and server above min (client smaller)",
			clientFrameSize:  8192,
			serverFrameMax:   16384,
			expectedFrameMin: 8192,
		},
		{
			name:             "client and server above min (server smaller)",
			clientFrameSize:  16384,
			serverFrameMax:   8192,
			expectedFrameMin: 8192,
		},
		{
			name:             "client and server below min",
			clientFrameSize:  1,
			serverFrameMax:   1,
			expectedFrameMin: frameMinSize,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := negotiateFrameSize(tc.clientFrameSize, tc.serverFrameMax)
			if got != tc.expectedFrameMin {
				t.Errorf("negotiateFrameSize(%d, %d) = %d; want %d", tc.clientFrameSize, tc.serverFrameMax, got, tc.expectedFrameMin)
			}
		})
	}
}

// TestNegotiationFloorsMaliciousServerFrameMax drives a complete connection
// handshake against a server that tunes frame_max far below the protocol
// minimum. Before the fix the client accepted the value verbatim, so every
// published body was shredded into hundreds of tiny frames; the negotiated
// frame size must now be floored at frameMinSize and mirrored into the
// connection's atomic maxFrameSize for the reader goroutine.
func TestNegotiationFloorsMaliciousServerFrameMax(t *testing.T) {
	rwc, srv := newSession(t)
	t.Cleanup(func() { rwc.Close() })

	go func() {
		srv.expectAMQP()
		srv.connectionStart()
		srv.send(0, &connectionTune{
			ChannelMax: 11,
			FrameMax:   16, // hostile: below frameMinSize
			Heartbeat:  10,
		})
		srv.recv(0, &srv.tune)
		srv.recv(0, &connectionOpen{})
		srv.send(0, &connectionOpenOk{})
	}()

	c, err := Open(rwc, defaultConfig())
	if err != nil {
		t.Fatalf("could not create connection: %v (%s)", c, err)
	}

	if c.Config.FrameSize != frameMinSize {
		t.Errorf("expected negotiated frame size to be floored at %d, got %d", frameMinSize, c.Config.FrameSize)
	}

	if want, got := uint32(frameMinSize), srv.tune.FrameMax; want != got {
		t.Errorf("expected connection.tune-ok to advertise frame_max %d, got %d", want, got)
	}

	if want, got := uint32(c.Config.FrameSize), atomic.LoadUint32(&c.maxFrameSize); want != got {
		t.Errorf("expected maxFrameSize to mirror the negotiated frame size %d, got %d", want, got)
	}
}

// TestConnectionRejectsOversizedFrameFromServer drives the negotiated frame_max
// all the way through to the connection's reader goroutine. After a normal
// handshake the server emits a bare frame header announcing a 4 GiB payload and
// nothing else; an unguarded reader sizes its buffer from that declared length
// before it ever learns the payload is a lie, so seven bytes on the wire become
// an out-of-memory condition. The connection must instead shut down with the
// frame_max error.
func TestConnectionRejectsOversizedFrameFromServer(t *testing.T) {
	rwc, srv := newSession(t)
	t.Cleanup(func() { rwc.Close() })

	ready := make(chan struct{})

	go func() {
		srv.connectionOpen()
		<-ready

		oversized := make([]byte, 7)
		oversized[0] = frameBody
		binary.BigEndian.PutUint16(oversized[1:3], 1)
		binary.BigEndian.PutUint32(oversized[3:7], ^uint32(0)) // 4 GiB - 1
		// The pipe is closed from under us as soon as the client shuts the
		// connection down, so a short write here is expected.
		_, _ = srv.S.Write(oversized)
	}()

	c, err := Open(rwc, defaultConfig())
	if err != nil {
		t.Fatalf("could not create connection: %v (%s)", c, err)
	}

	closes := c.NotifyClose(make(chan *Error, 1))
	close(ready)

	select {
	case e := <-closes:
		if e == nil {
			t.Fatal("expected a close error describing the oversized frame, got nil")
		}
		if !strings.Contains(e.Reason, ErrFrameTooLarge.Reason) {
			t.Errorf("expected close reason to mention %q, got %q", ErrFrameTooLarge.Reason, e.Reason)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("connection did not shut down after an oversized frame")
	}
}
