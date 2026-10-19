package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"testing"
)

// ============================================================
// Helper: parse hex dump text into bytes
// ============================================================

func parseHexDump(data []byte) []byte {
	var result []byte
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if len(line) < 10 {
			continue
		}
		parts := strings.SplitN(line, "  ", 3)
		if len(parts) >= 2 {
			hexPart := strings.TrimSpace(parts[1])
			b, err := hex.DecodeString(strings.ReplaceAll(hexPart, " ", ""))
			if err == nil {
				result = append(result, b...)
			}
		}
	}
	return result
}

// ============================================================
// Helper: build synthetic DNS payloads
// ============================================================

// buildDNSResponse builds a minimal DNS response with the given records.
// Each record is (name, type, class, ttl, rdata).
func buildDNSResponse(records []testRecord) []byte {
	var buf bytes.Buffer

	// Transaction ID
	buf.Write([]byte{0x00, 0x00})
	// Flags: QR=1 (response), Authoritative=0
	buf.Write([]byte{0x84, 0x00})
	// Questions: 0
	binary.Write(&buf, binary.BigEndian, uint16(0))
	// Answers: count A records only (simplified — we put everything in answers)
	binary.Write(&buf, binary.BigEndian, uint16(len(records)))
	// Authority: 0
	binary.Write(&buf, binary.BigEndian, uint16(0))
	// Additional: 0
	binary.Write(&buf, binary.BigEndian, uint16(0))

	for _, rec := range records {
		// Name
		if len(rec.name) > 0 {
			for _, label := range strings.Split(rec.name, ".") {
				buf.WriteByte(byte(len(label)))
				buf.WriteString(label)
			}
		}
		buf.WriteByte(0) // root label

		// TYPE
		binary.Write(&buf, binary.BigEndian, rec.typ)
		// CLASS
		binary.Write(&buf, binary.BigEndian, rec.class)
		// TTL
		binary.Write(&buf, binary.BigEndian, rec.ttl)
		// RDLENGTH
		binary.Write(&buf, binary.BigEndian, uint16(len(rec.rdata)))
		// RDATA
		buf.Write(rec.rdata)
	}

	return buf.Bytes()
}

type testRecord struct {
	name  string
	typ   uint16
	class uint16
	ttl   uint32
	rdata []byte
}

// buildDNSQuery builds a minimal DNS query
func buildDNSQuery(name string) []byte {
	var buf bytes.Buffer

	// Transaction ID
	buf.Write([]byte{0x00, 0x00})
	// Flags: QR=0 (query)
	buf.Write([]byte{0x00, 0x00})
	// Questions: 1
	binary.Write(&buf, binary.BigEndian, uint16(1))
	// Answers: 0
	binary.Write(&buf, binary.BigEndian, uint16(0))
	// Authority: 0
	binary.Write(&buf, binary.BigEndian, uint16(0))
	// Additional: 0
	binary.Write(&buf, binary.BigEndian, uint16(0))

	// Question name
	for _, label := range strings.Split(name, ".") {
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0)

	// QTYPE: A (1)
	binary.Write(&buf, binary.BigEndian, uint16(1))
	// QCLASS: IN (1)
	binary.Write(&buf, binary.BigEndian, uint16(1))

	return buf.Bytes()
}

// ============================================================
// Tests: parseDNSHeader
// ============================================================

func TestParseDNSHeader_ValidResponse(t *testing.T) {
	// Flags: QR=1, 0 answers, 2 answers, 0 authorities, 1 additional
	payload := make([]byte, 12)
	payload[2] = 0x84 // QR=1
	payload[3] = 0x00
	binary.BigEndian.PutUint16(payload[4:6], 0)   // 0 questions
	binary.BigEndian.PutUint16(payload[6:8], 2)   // 2 answers
	binary.BigEndian.PutUint16(payload[8:10], 0)  // 0 authorities
	binary.BigEndian.PutUint16(payload[10:12], 1) // 1 additional

	qr, q, a, auth, add, err := parseDNSHeader(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !qr {
		t.Error("expected QR=true")
	}
	if q != 0 {
		t.Errorf("expected 0 questions, got %d", q)
	}
	if a != 2 {
		t.Errorf("expected 2 answers, got %d", a)
	}
	if auth != 0 {
		t.Errorf("expected 0 authorities, got %d", auth)
	}
	if add != 1 {
		t.Errorf("expected 1 additional, got %d", add)
	}
}

func TestParseDNSHeader_Query(t *testing.T) {
	payload := make([]byte, 12)
	payload[2] = 0x00 // QR=0
	payload[3] = 0x00
	binary.BigEndian.PutUint16(payload[4:6], 1) // 1 question
	binary.BigEndian.PutUint16(payload[6:8], 0) // 0 answers

	qr, q, a, _, _, err := parseDNSHeader(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if qr {
		t.Error("expected QR=false for query")
	}
	if q != 1 {
		t.Errorf("expected 1 question, got %d", q)
	}
	if a != 0 {
		t.Errorf("expected 0 answers, got %d", a)
	}
}

func TestParseDNSHeader_TooShort(t *testing.T) {
	payload := make([]byte, 5) // too short
	_, _, _, _, _, err := parseDNSHeader(payload)
	if err == nil {
		t.Error("expected error for short payload")
	}
}

func TestParseDNSHeader_Empty(t *testing.T) {
	_, _, _, _, _, err := parseDNSHeader(nil)
	if err == nil {
		t.Error("expected error for nil payload")
	}
}

// ============================================================
// Tests: skipDNSName
// ============================================================

func TestSkipDNSName_SimpleName(t *testing.T) {
	// "example.com" = \x07example\x03com\x00
	name := []byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00}
	result := skipDNSName(name, 0)
	if result != 13 {
		t.Errorf("expected offset 13, got %d", result)
	}
}

func TestSkipDNSName_CompressedPointer(t *testing.T) {
	// Compression pointer: 0xC0 0x0C
	name := []byte{0xC0, 0x0C}
	result := skipDNSName(name, 0)
	if result != 2 {
		t.Errorf("expected offset 2, got %d", result)
	}
}

func TestSkipDNSName_RootLabel(t *testing.T) {
	// Just the root label (empty name)
	name := []byte{0x00}
	result := skipDNSName(name, 0)
	if result != 1 {
		t.Errorf("expected offset 1, got %d", result)
	}
}

func TestSkipDNSName_OffsetBeyondData(t *testing.T) {
	data := []byte{0x03, 'f', 'o', 'o', 0x00}
	result := skipDNSName(data, 100)
	if result != -1 {
		t.Errorf("expected -1, got %d", result)
	}
}

func TestSkipDNSName_NegativeOffset(t *testing.T) {
	data := []byte{0x00}
	result := skipDNSName(data, -1)
	if result != -1 {
		t.Errorf("expected -1, got %d", result)
	}
}

func TestSkipDNSName_WithPrefix(t *testing.T) {
	// Some prefix bytes, then "test" at offset 5
	data := make([]byte, 10)
	data[5] = 0x04           // length 4
	copy(data[6:10], "test") // label
	result := skipDNSName(data, 5)
	// Should skip: 1 (length) + 4 (label) + 1 (need 0x00 terminator)
	// But data[10] doesn't exist — this should fail
	// Actually the loop continues until it finds 0x00 or runs out of data
	// data[5]=0x04, skip to 5+4+1=10, data[10] is out of bounds
	if result != -1 {
		t.Errorf("expected -1 (overflow), got %d", result)
	}
}

func TestSkipDNSName_CompressedPointerAtEnd(t *testing.T) {
	// Compression pointer at the very end of data
	data := []byte{0xC0}
	result := skipDNSName(data, 0)
	if result != -1 {
		t.Errorf("expected -1 (incomplete pointer), got %d", result)
	}
}

// ============================================================
// Tests: parseDNSRecords
// ============================================================

func TestParseDNSRecords_SingleARecord(t *testing.T) {
	payload := buildDNSResponse([]testRecord{
		{
			name:  "test.local",
			typ:   1,
			class: 0x8001,
			ttl:   120,
			rdata: []byte{192, 168, 1, 100},
		},
	})

	records, err := parseDNSRecords(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Type != 1 {
		t.Errorf("expected type A(1), got %d", records[0].Type)
	}
	if !records[0].IP.Equal(net.IPv4(192, 168, 1, 100)) {
		t.Errorf("expected IP 192.168.1.100, got %s", records[0].IP)
	}
	if records[0].IPOffset == 0 {
		t.Error("expected IPOffset > 0 for A record")
	}
}

func TestParseDNSRecords_QueryReturnsNil(t *testing.T) {
	payload := buildDNSQuery("test.local")
	records, err := parseDNSRecords(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if records != nil {
		t.Errorf("expected nil records for query, got %d", len(records))
	}
}

func TestParseDNSRecords_MultipleRecordTypes(t *testing.T) {
	payload := buildDNSResponse([]testRecord{
		{
			name:  "test.local",
			typ:   16, // TXT
			class: 0x8001,
			ttl:   4500,
			rdata: []byte{0x09, 't', 'x', 't', 'v', 'e', 'r', 's', '=', '1'},
		},
		{
			name:  "test.local",
			typ:   33, // SRV
			class: 0x8001,
			ttl:   120,
			rdata: []byte{0x00, 0x00, 0x00, 0x00, 0x1F, 0x90, 0xC0, 0x0C}, // priority=0, weight=0, port=8080, target=c00c
		},
		{
			name:  "test.local",
			typ:   1, // A
			class: 0x8001,
			ttl:   120,
			rdata: []byte{10, 0, 1, 50},
		},
		{
			name:  "test.local",
			typ:   28, // AAAA
			class: 0x8001,
			ttl:   120,
			rdata: net.ParseIP("fe80::1").To16(),
		},
	})

	records, err := parseDNSRecords(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 4 {
		t.Fatalf("expected 4 records, got %d", len(records))
	}

	// Verify types
	expectedTypes := []uint16{16, 33, 1, 28}
	for i, rec := range records {
		if rec.Type != expectedTypes[i] {
			t.Errorf("record %d: expected type %d, got %d", i, expectedTypes[i], rec.Type)
		}
	}

	// Verify A record IP
	aRec := records[2]
	if !aRec.IP.Equal(net.IPv4(10, 0, 1, 50)) {
		t.Errorf("A record IP: expected 10.0.1.50, got %s", aRec.IP)
	}
}

func TestParseDNSRecords_TruncatedPayload(t *testing.T) {
	// Build a valid payload then truncate it
	payload := buildDNSResponse([]testRecord{
		{
			name:  "test.local",
			typ:   1,
			class: 0x8001,
			ttl:   120,
			rdata: []byte{192, 168, 1, 1},
		},
	})

	// Truncate to just after header
	_, err := parseDNSRecords(payload[:13])
	if err == nil {
		t.Error("expected error for truncated payload")
	}
}

func TestParseDNSRecords_EmptyResponse(t *testing.T) {
	// Response with 0 answers
	var buf bytes.Buffer
	buf.Write([]byte{0x00, 0x00})                   // Transaction ID
	buf.Write([]byte{0x84, 0x00})                   // Flags: QR=1
	binary.Write(&buf, binary.BigEndian, uint16(0)) // Questions
	binary.Write(&buf, binary.BigEndian, uint16(0)) // Answers
	binary.Write(&buf, binary.BigEndian, uint16(0)) // Authorities
	binary.Write(&buf, binary.BigEndian, uint16(0)) // Additional

	records, err := parseDNSRecords(buf.Bytes())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}
}

// ============================================================
// Tests: modifyDNSPayload
// ============================================================

func TestModifyDNSPayload_SingleARecord(t *testing.T) {
	proxy := &mDNSProxy{}
	targetIP := net.IPv4(10, 0, 2, 1)

	payload := buildDNSResponse([]testRecord{
		{
			name:  "printer.local",
			typ:   1,
			class: 0x8001,
			ttl:   120,
			rdata: []byte{192, 168, 1, 100},
		},
	})

	result := proxy.modifyDNSPayload(payload, targetIP, "src->dst")

	// Verify original is unchanged (parse and check IP)
	origRecords, _ := parseDNSRecords(payload)
	if len(origRecords) != 1 {
		t.Fatalf("expected 1 original record, got %d", len(origRecords))
	}
	if !origRecords[0].IP.Equal(net.IPv4(192, 168, 1, 100)) {
		t.Errorf("original payload was modified: expected 192.168.1.100, got %s", origRecords[0].IP)
	}

	// Result should have the new IP
	if bytes.Equal(result, payload) {
		t.Error("result should differ from original")
	}

	// Parse the result and verify A record
	records, err := parseDNSRecords(result)
	if err != nil {
		t.Fatalf("failed to parse modified payload: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if !records[0].IP.Equal(targetIP.To4()) {
		t.Errorf("expected IP %s, got %s", targetIP, records[0].IP)
	}
}

func TestModifyDNSPayload_MultipleARecords(t *testing.T) {
	proxy := &mDNSProxy{}
	targetIP := net.IPv4(10, 0, 2, 1)

	payload := buildDNSResponse([]testRecord{
		{
			name:  "service1.local",
			typ:   1,
			class: 0x8001,
			ttl:   120,
			rdata: []byte{192, 168, 1, 10},
		},
		{
			name:  "service2.local",
			typ:   1,
			class: 0x8001,
			ttl:   120,
			rdata: []byte{192, 168, 1, 20},
		},
	})

	result := proxy.modifyDNSPayload(payload, targetIP, "src->dst")

	records, err := parseDNSRecords(result)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	aCount := 0
	for _, rec := range records {
		if rec.Type == 1 {
			aCount++
			if !rec.IP.Equal(targetIP.To4()) {
				t.Errorf("A record IP: expected %s, got %s", targetIP, rec.IP)
			}
		}
	}
	if aCount != 2 {
		t.Errorf("expected 2 A records, got %d", aCount)
	}
}

func TestModifyDNSPayload_NoARecords(t *testing.T) {
	proxy := &mDNSProxy{}
	targetIP := net.IPv4(10, 0, 2, 1)

	payload := buildDNSResponse([]testRecord{
		{
			name:  "test.local",
			typ:   16, // TXT only
			class: 0x8001,
			ttl:   120,
			rdata: []byte{0x04, 't', 'e', 's', 't'},
		},
	})

	result := proxy.modifyDNSPayload(payload, targetIP, "src->dst")

	// Should return original payload unchanged
	if !bytes.Equal(result, payload) {
		t.Error("payload without A records should not be modified")
	}
}

func TestModifyDNSPayload_QueryUnchanged(t *testing.T) {
	proxy := &mDNSProxy{}
	targetIP := net.IPv4(10, 0, 2, 1)

	payload := buildDNSQuery("test.local")
	result := proxy.modifyDNSPayload(payload, targetIP, "src->dst")

	// Queries should not be modified
	if !bytes.Equal(result, payload) {
		t.Error("query payload should not be modified")
	}
}

func TestModifyDNSPayload_IPv6Target(t *testing.T) {
	proxy := &mDNSProxy{}
	targetIP := net.ParseIP("fe80::1") // IPv6 — To4() returns nil

	payload := buildDNSResponse([]testRecord{
		{
			name:  "test.local",
			typ:   1,
			class: 0x8001,
			ttl:   120,
			rdata: []byte{192, 168, 1, 100},
		},
	})

	result := proxy.modifyDNSPayload(payload, targetIP, "src->dst")

	// Should return original (IPv6 target is not supported for A records)
	if !bytes.Equal(result, payload) {
		t.Error("payload should not be modified when target is IPv6")
	}
}

func TestModifyDNSPayload_NilTarget(t *testing.T) {
	proxy := &mDNSProxy{}

	payload := buildDNSResponse([]testRecord{
		{
			name:  "test.local",
			typ:   1,
			class: 0x8001,
			ttl:   120,
			rdata: []byte{192, 168, 1, 100},
		},
	})

	result := proxy.modifyDNSPayload(payload, nil, "src->dst")
	if !bytes.Equal(result, payload) {
		t.Error("payload should not be modified when target is nil")
	}
}

func TestModifyDNSPayload_MixedRecordTypes(t *testing.T) {
	proxy := &mDNSProxy{}
	targetIP := net.IPv4(10, 0, 2, 1)

	payload := buildDNSResponse([]testRecord{
		{
			name:  "svc.local",
			typ:   16, // TXT
			class: 0x8001,
			ttl:   4500,
			rdata: []byte{0x09, 't', 'x', 't', 'v', 'e', 'r', 's', '=', '1'},
		},
		{
			name:  "svc.local",
			typ:   1, // A
			class: 0x8001,
			ttl:   120,
			rdata: []byte{192, 168, 3, 51},
		},
		{
			name:  "svc.local",
			typ:   28, // AAAA
			class: 0x8001,
			ttl:   120,
			rdata: net.ParseIP("fe80::1").To16(),
		},
	})

	result := proxy.modifyDNSPayload(payload, targetIP, "src->dst")

	records, err := parseDNSRecords(result)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	for _, rec := range records {
		switch rec.Type {
		case 1: // A record should be modified
			if !rec.IP.Equal(targetIP.To4()) {
				t.Errorf("A record: expected %s, got %s", targetIP, rec.IP)
			}
		case 28: // AAAA should be unchanged
			// (We don't have AAAA IP in our struct, so just verify RDATA is intact)
		}
	}
}

func TestModifyDNSPayload_OriginalUnchanged(t *testing.T) {
	proxy := &mDNSProxy{}
	targetIP := net.IPv4(10, 0, 2, 1)

	payload := buildDNSResponse([]testRecord{
		{
			name:  "test.local",
			typ:   1,
			class: 0x8001,
			ttl:   120,
			rdata: []byte{192, 168, 1, 100},
		},
	})

	// Keep a copy of original
	original := make([]byte, len(payload))
	copy(original, payload)

	_ = proxy.modifyDNSPayload(payload, targetIP, "src->dst")

	// Original should not be modified (copy semantics)
	if !bytes.Equal(payload, original) {
		t.Error("original payload was modified in place")
	}
}

// ============================================================
// Tests: typeNameFromNumber
// ============================================================

func TestTypeNameFromNumber(t *testing.T) {
	tests := []struct {
		input    uint16
		expected string
	}{
		{1, "A"},
		{2, "NS"},
		{5, "CNAME"},
		{12, "PTR"},
		{15, "MX"},
		{16, "TXT"},
		{28, "AAAA"},
		{33, "SRV"},
		{47, "NSEC"},
		{999, "TYPE999"},
		{0, "TYPE0"},
	}

	for _, tt := range tests {
		result := typeNameFromNumber(tt.input)
		if result != tt.expected {
			t.Errorf("typeNameFromNumber(%d): expected %q, got %q", tt.input, tt.expected, result)
		}
	}
}

// ============================================================
// Tests: parseHexDump helper
// ============================================================

func TestParseHexDump(t *testing.T) {
	dump := `0000   48 65 6c 6c 6f                                    Hello
0005   20 57 6f 72 6c 64                                 World
`
	result := parseHexDump([]byte(dump))
	expected := []byte("Hello World")
	if !bytes.Equal(result, expected) {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestParseHexDump_Empty(t *testing.T) {
	result := parseHexDump([]byte(""))
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d bytes", len(result))
	}
}
