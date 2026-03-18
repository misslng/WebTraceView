package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

const baseURL = "http://localhost:8080"

// callHTTP calls the existing HTTP API and returns parsed JSON.
func callHTTP(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	resp, err := http.Get(baseURL + path)
	if err != nil {
		t.Fatalf("HTTP GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("HTTP parse %s: %v\nraw: %s", path, err, string(body))
	}
	return m
}

// callMCP calls the MCP tool via JSON-RPC and returns the parsed tool result.
func callMCP(t *testing.T, tool string, args map[string]interface{}) map[string]interface{} {
	t.Helper()
	if args == nil {
		args = map[string]interface{}{}
	}
	rpcReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      tool,
			"arguments": args,
		},
	}
	b, _ := json.Marshal(rpcReq)
	resp, err := http.Post(baseURL+"/mcp", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("MCP call %s: %v", tool, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var rpcResp map[string]interface{}
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		t.Fatalf("MCP parse %s: %v\nraw: %s", tool, err, string(body))
	}
	if rpcErr, ok := rpcResp["error"]; ok {
		t.Fatalf("MCP error %s: %v", tool, rpcErr)
	}

	// Extract text content from MCP result
	result := rpcResp["result"].(map[string]interface{})
	content := result["content"].([]interface{})
	text := content[0].(map[string]interface{})["text"].(string)

	var m map[string]interface{}
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		t.Fatalf("MCP result parse %s: %v\nraw: %s", tool, err, text)
	}
	return m
}

// TestCompare_Info compares /api/info with trace_info MCP tool.
func TestCompare_Info(t *testing.T) {
	if os.Getenv("COMPARE_TEST") == "" {
		t.Skip("set COMPARE_TEST=1 to run against live server")
	}

	httpResult := callHTTP(t, "/api/info")
	mcpResult := callMCP(t, "trace_info", nil)

	// Compare totalRecords
	httpTotal := int(httpResult["totalRecords"].(float64))
	mcpTotal := int(mcpResult["totalRecords"].(float64))
	if httpTotal != mcpTotal {
		t.Errorf("totalRecords mismatch: HTTP=%d MCP=%d", httpTotal, mcpTotal)
	}

	// Compare indexDone
	if httpResult["indexDone"] != mcpResult["indexDone"] {
		t.Errorf("indexDone mismatch: HTTP=%v MCP=%v", httpResult["indexDone"], mcpResult["indexDone"])
	}

	// Compare threadIds
	httpTids := fmt.Sprintf("%v", httpResult["threadIds"])
	mcpTids := fmt.Sprintf("%v", mcpResult["threadIds"])
	if httpTids != mcpTids {
		t.Errorf("threadIds mismatch:\n  HTTP=%s\n  MCP =%s", httpTids, mcpTids)
	}

	// MCP should have extra entryContext
	entry := mcpResult["entryContext"].(map[string]interface{})
	if entry["mainSo"] == nil || entry["mainSo"] == "" {
		t.Error("MCP entryContext.mainSo is empty")
	}

	t.Logf("OK: totalRecords=%d, indexDone=%v, threads=%s, mainSo=%v",
		mcpTotal, mcpResult["indexDone"], mcpTids, entry["mainSo"])
}

// TestCompare_Instructions compares /api/instructions with get_instructions MCP tool.
func TestCompare_Instructions(t *testing.T) {
	if os.Getenv("COMPARE_TEST") == "" {
		t.Skip("set COMPARE_TEST=1 to run against live server")
	}

	httpResult := callHTTP(t, "/api/instructions?offset=0&limit=10")
	mcpResult := callMCP(t, "get_instructions", map[string]interface{}{
		"offset": 0, "limit": 10,
	})

	httpItems := httpResult["items"].([]interface{})
	mcpItems := mcpResult["items"].([]interface{})

	if len(httpItems) != len(mcpItems) {
		t.Fatalf("item count mismatch: HTTP=%d MCP=%d", len(httpItems), len(mcpItems))
	}

	for i := range httpItems {
		h := httpItems[i].(map[string]interface{})
		m := mcpItems[i].(map[string]interface{})

		hPC := h["pc"].(string)
		mPC := m["pc"].(string)
		if hPC != mPC {
			t.Errorf("[%d] pc mismatch: HTTP=%s MCP=%s", i, hPC, mPC)
		}

		hInstr := h["instrText"].(string)
		mInstr := m["instrText"].(string)
		if hInstr != mInstr {
			t.Errorf("[%d] instrText mismatch: HTTP=%s MCP=%s", i, hInstr, mInstr)
		}

		hRegs := h["regText"].(string)
		mRegs := m["regText"].(string)
		if hRegs != mRegs {
			t.Errorf("[%d] regText mismatch:\n  HTTP=%s\n  MCP =%s", i, hRegs, mRegs)
		}

		hTid := int(h["threadId"].(float64))
		mTid := int(m["threadId"].(float64))
		if hTid != mTid {
			t.Errorf("[%d] threadId mismatch: HTTP=%d MCP=%d", i, hTid, mTid)
		}
	}
	t.Logf("OK: %d instructions match perfectly", len(httpItems))
}

// TestCompare_Instructions_TidFilter compares tid-filtered results.
func TestCompare_Instructions_TidFilter(t *testing.T) {
	if os.Getenv("COMPARE_TEST") == "" {
		t.Skip("set COMPARE_TEST=1 to run against live server")
	}

	// Get thread list first
	info := callMCP(t, "trace_info", nil)
	tids := info["threadIds"].([]interface{})
	if len(tids) < 2 {
		t.Skip("need at least 2 threads for tid filter test")
	}
	// Use the second thread (non-main)
	tid := int(tids[1].(float64))

	httpResult := callHTTP(t, fmt.Sprintf("/api/instructions?offset=0&limit=5&tid=%d", tid))
	mcpResult := callMCP(t, "get_instructions", map[string]interface{}{
		"offset": 0, "limit": 5, "tid": float64(tid),
	})

	httpItems := httpResult["items"].([]interface{})
	mcpItems := mcpResult["items"].([]interface{})

	if len(httpItems) != len(mcpItems) {
		t.Fatalf("tid=%d item count mismatch: HTTP=%d MCP=%d", tid, len(httpItems), len(mcpItems))
	}

	for i := range httpItems {
		h := httpItems[i].(map[string]interface{})
		m := mcpItems[i].(map[string]interface{})
		if h["pc"] != m["pc"] || h["instrText"] != m["instrText"] {
			t.Errorf("[%d] mismatch for tid=%d", i, tid)
		}
	}
	t.Logf("OK: tid=%d, %d instructions match", tid, len(httpItems))
}

// TestCompare_Memory compares /api/memory with get_memory MCP tool.
func TestCompare_Memory(t *testing.T) {
	if os.Getenv("COMPARE_TEST") == "" {
		t.Skip("set COMPARE_TEST=1 to run against live server")
	}

	// Find a record with memory access
	instrs := callHTTP(t, "/api/instructions?offset=0&limit=50")
	items := instrs["items"].([]interface{})
	memIdx := -1
	for _, item := range items {
		m := item.(map[string]interface{})
		if flag, ok := m["memFlag"]; ok && flag != nil && flag != "" {
			memIdx = int(m["index"].(float64))
			break
		}
	}
	if memIdx < 0 {
		t.Skip("no memory access in first 50 instructions")
	}

	httpResult := callHTTP(t, fmt.Sprintf("/api/memory?index=%d", memIdx))
	mcpResult := callMCP(t, "get_memory", map[string]interface{}{
		"index": float64(memIdx),
	})

	httpRegions := httpResult["regions"].([]interface{})
	mcpRegions := mcpResult["regions"].([]interface{})

	if len(httpRegions) != len(mcpRegions) {
		t.Fatalf("index=%d region count mismatch: HTTP=%d MCP=%d", memIdx, len(httpRegions), len(mcpRegions))
	}

	for i := range httpRegions {
		h := httpRegions[i].(map[string]interface{})
		m := mcpRegions[i].(map[string]interface{})

		hBase := h["base"].(string)
		mBase := m["base"].(string)
		if hBase != mBase {
			t.Errorf("[%d] base mismatch: HTTP=%s MCP=%s", i, hBase, mBase)
		}

		hHex := h["hex"].(string)
		mHex := m["hex"].(string)
		if hHex != mHex {
			t.Errorf("[%d] hex data mismatch (len HTTP=%d MCP=%d)", i, len(hHex), len(mHex))
		}

		hType := h["type"].(string)
		mType := m["type"].(string)
		if hType != mType {
			t.Errorf("[%d] type mismatch: HTTP=%s MCP=%s", i, hType, mType)
		}
	}
	t.Logf("OK: index=%d, %d memory regions match perfectly", memIdx, len(httpRegions))
}

// TestCompare_Functions compares /api/functions with get_functions MCP tool.
func TestCompare_Functions(t *testing.T) {
	if os.Getenv("COMPARE_TEST") == "" {
		t.Skip("set COMPARE_TEST=1 to run against live server")
	}

	httpResult := callHTTP(t, "/api/functions")
	mcpResult := callMCP(t, "get_functions", nil)

	httpFuncs := httpResult["functions"].([]interface{})
	mcpFuncs := mcpResult["functions"].([]interface{})

	if len(httpFuncs) != len(mcpFuncs) {
		t.Fatalf("function count mismatch: HTTP=%d MCP=%d", len(httpFuncs), len(mcpFuncs))
	}

	// Both should be sorted by callCount desc, compare first 10
	limit := len(httpFuncs)
	if limit > 10 {
		limit = 10
	}
	for i := 0; i < limit; i++ {
		h := httpFuncs[i].(map[string]interface{})
		m := mcpFuncs[i].(map[string]interface{})

		hPC := h["targetPC"].(string)
		mPC := m["targetPC"].(string)
		// HTTP might format as "0x..." while MCP also does "0x...", should match
		if !strings.EqualFold(hPC, mPC) {
			t.Errorf("[%d] targetPC mismatch: HTTP=%s MCP=%s", i, hPC, mPC)
		}

		hCount := int(h["callCount"].(float64))
		mCount := int(m["callCount"].(float64))
		if hCount != mCount {
			t.Errorf("[%d] callCount mismatch: HTTP=%d MCP=%d", i, hCount, mCount)
		}
	}
	t.Logf("OK: %d functions match (checked top %d)", len(httpFuncs), limit)
}

// TestCompare_SearchInstr does a real instruction search and verifies MCP results make sense.
func TestCompare_SearchInstr(t *testing.T) {
	if os.Getenv("COMPARE_TEST") == "" {
		t.Skip("set COMPARE_TEST=1 to run against live server")
	}

	// Search for the entry function address (should always exist)
	info := callMCP(t, "trace_info", nil)
	entry := info["entryContext"].(map[string]interface{})
	entrySymbol := entry["entrySymbol"].(string)

	mcpResult := callMCP(t, "search_instructions", map[string]interface{}{
		"keyword": entrySymbol, "limit": 5,
	})

	totalMatches := int(mcpResult["totalMatches"].(float64))
	if totalMatches == 0 {
		t.Fatalf("expected matches for entry symbol '%s'", entrySymbol)
	}

	matches := mcpResult["matches"].([]interface{})
	// First match should be index 0 (the entry point)
	first := matches[0].(map[string]interface{})
	if int(first["index"].(float64)) != 0 {
		t.Errorf("expected first match at index 0, got %v", first["index"])
	}

	t.Logf("OK: search '%s' found %d matches, first at index %v", entrySymbol, totalMatches, first["index"])
}
