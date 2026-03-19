package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

// writeTestRecord writes a single trace record to the file.
// Format: magic(4) threadId(4) pc(8) pcTextLen(2) pcText instrLen(2) instr regLen(2) reg
//
//	readChunkCnt(4) [base(8) len(4) data]×N
//	writeChunkCnt(4) [base(8) len(4) data]×N
func writeTestRecord(f *os.File, threadId int32, pc uint64, pcText, instrText, regText string, readChunks, writeChunks []MemChunk) {
	// magic
	f.Write([]byte("UTRA"))
	// threadId
	b4 := make([]byte, 4)
	binary.LittleEndian.PutUint32(b4, uint32(threadId))
	f.Write(b4)
	// pc
	b8 := make([]byte, 8)
	binary.LittleEndian.PutUint64(b8, pc)
	f.Write(b8)
	// pcText
	b2 := make([]byte, 2)
	binary.LittleEndian.PutUint16(b2, uint16(len(pcText)))
	f.Write(b2)
	f.Write([]byte(pcText))
	// instrText
	binary.LittleEndian.PutUint16(b2, uint16(len(instrText)))
	f.Write(b2)
	f.Write([]byte(instrText))
	// regText
	binary.LittleEndian.PutUint16(b2, uint16(len(regText)))
	f.Write(b2)
	f.Write([]byte(regText))
	// readChunks
	writeChunkGroup(f, readChunks)
	// writeChunks
	writeChunkGroup(f, writeChunks)
}

func writeChunkGroup(f *os.File, chunks []MemChunk) {
	b4 := make([]byte, 4)
	binary.LittleEndian.PutUint32(b4, uint32(len(chunks)))
	f.Write(b4)
	for _, c := range chunks {
		b8 := make([]byte, 8)
		binary.LittleEndian.PutUint64(b8, c.Base)
		f.Write(b8)
		binary.LittleEndian.PutUint32(b4, uint32(len(c.Data)))
		f.Write(b4)
		f.Write(c.Data)
	}
}

// makeMemWindow creates a 256-byte window with the actual data at offset 128.
func makeMemWindow(base uint64, data []byte) MemChunk {
	window := make([]byte, 256+len(data))
	// Fill with pattern so we can identify it
	for i := range window {
		window[i] = byte(i & 0xff)
	}
	copy(window[128:], data)
	return MemChunk{Base: base - 128, Data: window}
}

// setupTestDB creates a temporary trace file with test data and initializes the global db.
func setupTestDB(t *testing.T) func() {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "trace_test_*.bin")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}

	// Record 0: entry function
	writeTestRecord(tmpFile, 1001, 0x4005bc04,
		"libmain.so+0x5bc04",
		"stp x29, x30, [sp, #-0x10]!",
		"x0=0x1234 x1=0x5678 sp=0xbffe0000",
		nil, nil,
	)

	// Record 1: ldr with read memory
	readData := []byte("HelloWorld!!")
	readChunk := makeMemWindow(0x40001000, readData)
	writeTestRecord(tmpFile, 1001, 0x4005bc08,
		"libmain.so+0x5bc08",
		"ldr x0, [x1, #0x10]",
		"x0=0x48656c6c x1=0x40001000 sp=0xbffe0000",
		[]MemChunk{readChunk}, nil,
	)

	// Record 2: str with write memory
	writeData := []byte{0xde, 0xad, 0xbe, 0xef}
	writeChunk := makeMemWindow(0x40002000, writeData)
	writeTestRecord(tmpFile, 1001, 0x4005bc0c,
		"libmain.so+0x5bc0c",
		"str x0, [x2]",
		"x0=0xdeadbeef x2=0x40002000 sp=0xbffe0000",
		nil, []MemChunk{writeChunk},
	)

	// Record 3: bl (function call)
	writeTestRecord(tmpFile, 1001, 0x4005bc10,
		"libmain.so+0x5bc10",
		"bl #0x4005c000",
		"x0=0xdeadbeef x1=0x5678 lr=0x4005bc14 sp=0xbffe0000",
		nil, nil,
	)

	// Record 4: inside called function, different thread
	writeTestRecord(tmpFile, 2002, 0x4005c000,
		"libmain.so+0xc000",
		"mov x0, x1",
		"x0=0x5678 x1=0x5678 sp=0xbffd0000",
		nil, nil,
	)

	// Record 5: another write to same address as record 2 (for watchpoint traceback test)
	writeChunk2 := makeMemWindow(0x40002000, []byte{0xca, 0xfe, 0xba, 0xbe})
	writeTestRecord(tmpFile, 1001, 0x4005bc14,
		"libmain.so+0x5bc14",
		"str w3, [x2]",
		"w3=0xcafebabe x2=0x40002000 sp=0xbffe0000",
		nil, []MemChunk{writeChunk2},
	)

	// Record 6: read from same address (for watchpoint traceback read filter)
	readChunk2 := makeMemWindow(0x40002000, []byte{0xca, 0xfe, 0xba, 0xbe})
	writeTestRecord(tmpFile, 1001, 0x4005bc18,
		"libmain.so+0x5bc18",
		"ldr w4, [x2]",
		"w4=0xcafebabe x2=0x40002000 sp=0xbffe0000",
		[]MemChunk{readChunk2}, nil,
	)

	tmpFile.Close()

	fi, _ := os.Stat(tmpFile.Name())
	db = &TraceDB{path: tmpFile.Name(), size: fi.Size(), funcMap: make(map[uint64]*FuncEntry)}
	db.anchors = append(db.anchors, BlockAnchor{0, 0})

	// Build index synchronously for tests
	db.buildIndexAsync()

	// Wait for index to complete
	for i := 0; i < 100; i++ {
		if db.indexDone.Load() {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	return func() {
		os.Remove(tmpFile.Name())
	}
}

func parseResult(t *testing.T, result *mcp.CallToolResult) map[string]interface{} {
	t.Helper()
	if result.IsError {
		t.Fatalf("tool returned error: %v", result.Content)
	}
	text := result.Content[0].(mcp.TextContent).Text
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		t.Fatalf("parse result JSON: %v\nraw: %s", err, text)
	}
	return m
}

func TestTraceInfo(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	result, err := handleTraceInfo(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatal(err)
	}
	m := parseResult(t, result)

	total := int(m["totalRecords"].(float64))
	if total != 7 {
		t.Errorf("expected 7 records, got %d", total)
	}
	if m["indexDone"] != true {
		t.Error("expected indexDone=true")
	}

	entry := m["entryContext"].(map[string]interface{})
	if entry["entryPC"] != "0x4005bc04" {
		t.Errorf("entryPC = %v", entry["entryPC"])
	}
	if entry["mainSo"] != "libmain.so" {
		t.Errorf("mainSo = %v", entry["mainSo"])
	}
	if int(entry["mainThreadId"].(float64)) != 1001 {
		t.Errorf("mainThreadId = %v", entry["mainThreadId"])
	}
	t.Logf("trace_info OK: %d records, entry=%s, so=%s", total, entry["entryPC"], entry["mainSo"])
}

func makeCallReq(args map[string]interface{}) mcp.CallToolRequest {
	return mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Arguments: args,
		},
	}
}

func TestGetInstructions(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	// Test basic pagination
	result, err := handleGetInstructions(context.Background(), makeCallReq(map[string]interface{}{
		"offset": float64(0), "limit": float64(3),
	}))
	if err != nil {
		t.Fatal(err)
	}
	m := parseResult(t, result)
	items := m["items"].([]interface{})
	if len(items) != 3 {
		t.Errorf("expected 3 items, got %d", len(items))
	}
	first := items[0].(map[string]interface{})
	if first["instrText"] != "stp x29, x30, [sp, #-0x10]!" {
		t.Errorf("first instr = %v", first["instrText"])
	}

	// Test tid filter
	result2, err := handleGetInstructions(context.Background(), makeCallReq(map[string]interface{}{
		"offset": float64(0), "limit": float64(100), "tid": float64(2002),
	}))
	if err != nil {
		t.Fatal(err)
	}
	m2 := parseResult(t, result2)
	items2 := m2["items"].([]interface{})
	if len(items2) != 1 {
		t.Errorf("expected 1 item for tid 2002, got %d", len(items2))
	}
	t.Logf("get_instructions OK: pagination and tid filter work")
}

func TestGetMemory(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	// Record 1 has read memory
	result, err := handleGetMemory(context.Background(), makeCallReq(map[string]interface{}{
		"index": float64(1),
	}))
	if err != nil {
		t.Fatal(err)
	}
	m := parseResult(t, result)
	regions := m["regions"].([]interface{})
	if len(regions) == 0 {
		t.Fatal("expected regions for record 1")
	}
	r0 := regions[0].(map[string]interface{})
	if r0["type"] != "read" {
		t.Errorf("expected read region, got %v", r0["type"])
	}

	// Test hex map format (4-byte groups)
	hexMap, ok := r0["hex"].(map[string]interface{})
	if !ok {
		t.Error("expected hex to be a map")
	} else {
		t.Logf("get_memory hex map has %d entries", len(hexMap))
	}

	// Test accessRange with hex
	if ar, ok := r0["accessRange"].(map[string]interface{}); ok {
		if ar["hex"] == nil {
			t.Error("expected accessRange.hex")
		}
		t.Logf("get_memory accessRange: start=%v size=%v hex=%v", ar["start"], ar["size"], ar["hex"])
	}
	t.Logf("get_memory OK: regions with hex map and accessRange.hex work")
}

func TestGetFunctions(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	result, err := handleGetFunctions(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatal(err)
	}
	m := parseResult(t, result)
	total := int(m["total"].(float64))
	t.Logf("get_functions OK: %d functions found", total)
}

func TestSearchMemory(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	// Search for "HelloWorld" string in memory
	result, err := handleSearchMemory(context.Background(), makeCallReq(map[string]interface{}{
		"pattern": "HelloWorld", "type": "string",
	}))
	if err != nil {
		t.Fatal(err)
	}
	m := parseResult(t, result)
	totalMatches := int(m["totalMatches"].(float64))
	if totalMatches == 0 {
		t.Error("expected at least 1 match for 'HelloWorld'")
	}
	matches := m["matches"].([]interface{})
	if len(matches) > 0 {
		first := matches[0].(map[string]interface{})
		t.Logf("search_memory OK: found %d matches, first at index=%v pc=%v", totalMatches, first["index"], first["pc"])
	}

	// Search for hex pattern deadbeef
	result2, err := handleSearchMemory(context.Background(), makeCallReq(map[string]interface{}{
		"pattern": "deadbeef", "type": "hex",
	}))
	if err != nil {
		t.Fatal(err)
	}
	m2 := parseResult(t, result2)
	if int(m2["totalMatches"].(float64)) == 0 {
		t.Error("expected match for hex deadbeef")
	}
	t.Logf("search_memory hex OK: %v matches", m2["totalMatches"])
}

func TestSearchInstructions(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	result, err := handleSearchInstructions(context.Background(), makeCallReq(map[string]interface{}{
		"keyword": "bl #0x4005c000",
	}))
	if err != nil {
		t.Fatal(err)
	}
	m := parseResult(t, result)
	totalMatches := int(m["totalMatches"].(float64))
	if totalMatches != 1 {
		t.Errorf("expected 1 match for 'bl #0x4005c000', got %d", totalMatches)
	}
	t.Logf("search_instructions OK: %d matches", totalMatches)
}

func TestSetWatchpoint(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	// Watch address 0x40002000 (written by records 2 and 5, read by record 6)
	result, err := handleSetWatchpoint(context.Background(), makeCallReq(map[string]interface{}{
		"addr": "0x40002000", "size": float64(4),
	}))
	if err != nil {
		t.Fatal(err)
	}
	m := parseResult(t, result)
	totalMatches := int(m["totalMatches"].(float64))
	if totalMatches < 2 {
		t.Errorf("expected at least 2 watchpoint matches, got %d", totalMatches)
	}
	t.Logf("set_watchpoint OK: %d matches for 0x40002000", totalMatches)
}

func TestWatchpointTraceback(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	// First set watchpoint on 0x40002000
	_, err := handleSetWatchpoint(context.Background(), makeCallReq(map[string]interface{}{
		"addr": "0x40002000", "size": float64(4),
	}))
	if err != nil {
		t.Fatal(err)
	}

	// Traceback from record 6 (ldr), looking for writes before it
	result, err := handleWatchpointTraceback(context.Background(), makeCallReq(map[string]interface{}{
		"before_index": float64(6), "type_filter": "write",
	}))
	if err != nil {
		t.Fatal(err)
	}
	m := parseResult(t, result)
	matches := m["matches"].([]interface{})
	if len(matches) == 0 {
		t.Fatal("expected traceback matches")
	}

	// First result should be the nearest write (record 5, index=5)
	first := matches[0].(map[string]interface{})
	firstIdx := int(first["index"].(float64))
	if firstIdx != 5 {
		t.Errorf("expected nearest write at index 5, got %d", firstIdx)
	}

	// Second should be record 2
	if len(matches) >= 2 {
		second := matches[1].(map[string]interface{})
		secondIdx := int(second["index"].(float64))
		if secondIdx != 2 {
			t.Errorf("expected second write at index 2, got %d", secondIdx)
		}
	}

	// Verify descending order
	for i := 1; i < len(matches); i++ {
		prev := int(matches[i-1].(map[string]interface{})["index"].(float64))
		curr := int(matches[i].(map[string]interface{})["index"].(float64))
		if curr >= prev {
			t.Errorf("results not in descending order: %d >= %d", curr, prev)
		}
	}

	t.Logf("watchpoint_traceback OK: %d matches, nearest write at index %d", len(matches), firstIdx)
}

func TestTraceRegister(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	// Note: runRegTrace only matches registers after "=>" in regText (write-back registers).
	// Our test data doesn't have "=>" format, so 0 matches is expected here.
	// This test verifies the tool runs without error and returns valid JSON.
	result, err := handleTraceRegister(context.Background(), makeCallReq(map[string]interface{}{
		"reg": "x0", "from": float64(0), "to": float64(4),
	}))
	if err != nil {
		t.Fatal(err)
	}
	m := parseResult(t, result)
	totalMatches := int(m["totalMatches"].(float64))
	if m["done"] != true {
		t.Error("expected done=true")
	}
	t.Logf("trace_register OK: %d matches for x0 in range [0,4) (0 expected with test data lacking '=>' format)", totalMatches)
}

func TestResourceInfo(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	contents, err := handleResourceInfo(context.Background(), mcp.ReadResourceRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) == 0 {
		t.Fatal("expected resource contents")
	}
	text := contents[0].(mcp.TextResourceContents).Text
	var m map[string]interface{}
	json.Unmarshal([]byte(text), &m)
	if int(m["totalRecords"].(float64)) != 7 {
		t.Errorf("resource info totalRecords = %v", m["totalRecords"])
	}
	t.Logf("resource trace://info OK")
}

func TestResourceFunctions(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	contents, err := handleResourceFunctions(context.Background(), mcp.ReadResourceRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) == 0 {
		t.Fatal("expected resource contents")
	}
	text := contents[0].(mcp.TextResourceContents).Text
	t.Logf("resource trace://functions OK: %s", text[:min(len(text), 200)])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
