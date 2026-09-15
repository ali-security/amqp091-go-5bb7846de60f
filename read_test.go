// Copyright (c) 2021 VMware, Inc. or its affiliates. All Rights Reserved.
// Copyright (c) 2012-2021, Sean Treadway, SoundCloud Ltd.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package amqp091

import (
	"bytes"
	"encoding/binary"
	"strings"
	"sync/atomic"
	"testing"
)

// TestReadFrameRejectsOversizedFrame verifies that a frame whose declared
// size exceeds the negotiated frame_max is rejected before its payload is
// allocated or read, preventing a malicious server from forcing large
// allocations by lying about a frame's size in the frame header.
func TestReadFrameRejectsOversizedFrame(t *testing.T) {
	const negotiatedMax = 4096 // total frame size, including header and frame-end byte

	header := make([]byte, 7)
	header[0] = frameBody
	binary.BigEndian.PutUint16(header[1:3], 1)
	binary.BigEndian.PutUint32(header[3:7], negotiatedMax) // payload alone already exceeds the limit

	var maxFrameSize uint32
	atomic.StoreUint32(&maxFrameSize, negotiatedMax)

	r := reader{r: bytes.NewReader(header), maxFrameSize: &maxFrameSize}
	frame, err := r.ReadFrame()
	if err != ErrFrameTooLarge {
		t.Fatalf("expected ErrFrameTooLarge, got frame=%#v err=%v", frame, err)
	}
}

// TestReadFrameRejectsHugeDeclaredFrameSize is the exploit behind the limit: a
// hostile server announces a multi-gigabyte frame in seven header bytes and
// sends nothing else. Without the negotiated frame_max check the client sizes
// its buffer from the declared length (parseBodyFrame does make([]byte, size))
// before discovering the payload was a lie, so a handful of bytes on the wire
// turn into an out-of-memory condition. The check sits ahead of the frame type
// switch, so it must hold for every frame type.
func TestReadFrameRejectsHugeDeclaredFrameSize(t *testing.T) {
	const negotiatedMax = 131072 // what a stock RabbitMQ negotiates

	for _, typ := range []byte{frameMethod, frameHeader, frameBody} {
		header := make([]byte, 7)
		header[0] = typ
		binary.BigEndian.PutUint16(header[1:3], 1)
		binary.BigEndian.PutUint32(header[3:7], ^uint32(0)) // 4 GiB - 1

		var maxFrameSize uint32
		atomic.StoreUint32(&maxFrameSize, negotiatedMax)

		r := reader{r: bytes.NewReader(header), maxFrameSize: &maxFrameSize}
		frame, err := r.ReadFrame()
		if err != ErrFrameTooLarge {
			t.Fatalf("frame type %d: expected ErrFrameTooLarge, got frame=%#v err=%v", typ, frame, err)
		}
	}
}

// TestReadFrameAllowsUnlimitedWhenNegotiatedUnbounded verifies that a nil or
// zero-valued maxFrameSize (frame_max negotiated as unlimited, or not yet
// negotiated) does not reject frames, preserving prior behavior.
func TestReadFrameAllowsUnlimitedWhenNegotiatedUnbounded(t *testing.T) {
	header := make([]byte, 7)
	header[0] = frameBody
	binary.BigEndian.PutUint16(header[1:3], 1)
	binary.BigEndian.PutUint32(header[3:7], 3)

	buf := append(header, []byte("abc")...)
	buf = append(buf, frameEnd)

	r := reader{r: bytes.NewReader(buf)}
	if _, err := r.ReadFrame(); err != nil {
		t.Fatalf("expected no error with nil maxFrameSize, got: %v", err)
	}
}

// TestReadFrameAllowsAnySizeWhenMaxFrameSizeIsZero verifies that a non-nil
// maxFrameSize storing 0 (frame_max explicitly negotiated as unlimited, per
// negotiateFrameSize when both client and server request 0) does not reject
// frames, regardless of declared size.
func TestReadFrameAllowsAnySizeWhenMaxFrameSizeIsZero(t *testing.T) {
	const declaredSize = 1 << 20 // far larger than any realistic negotiated frame_max

	header := make([]byte, 7)
	header[0] = frameBody
	binary.BigEndian.PutUint16(header[1:3], 1)
	binary.BigEndian.PutUint32(header[3:7], declaredSize)

	payload := make([]byte, declaredSize)
	buf := append(header, payload...)
	buf = append(buf, frameEnd)

	var maxFrameSize uint32 // zero value: unlimited

	r := reader{r: bytes.NewReader(buf), maxFrameSize: &maxFrameSize}
	if _, err := r.ReadFrame(); err != nil {
		t.Fatalf("expected no error with maxFrameSize == 0, got: %v", err)
	}
}

func TestGoFuzzCrashers(t *testing.T) {
	if testing.Short() {
		t.Skip("excessive allocation")
	}

	testData := []string{
		"\b000000",
		"\x02\x16\x10�[��\t\xbdui�" + "\x10\x01\x00\xff\xbf\xef\xbfｻn\x99\x00\x10r",
		"\x0300\x00\x00\x00\x040000",
	}

	for idx, testStr := range testData {
		r := reader{r: strings.NewReader(testStr)}
		frame, err := r.ReadFrame()
		if err != nil && frame != nil {
			t.Errorf("%d. frame is not nil: %#v err = %v", idx, frame, err)
		}
	}
}
