package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

// waitForSearchDone polls until a search job is done or timeout (5 min).
func waitForDone(isDone func() bool, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		if isDone() {
			return true
		}
		select {
		case <-deadline:
			return false
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// ==================== Tool: search_memory ====================

func handleSearchMemory(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	patternStr := req.GetString("pattern", "")
	searchType := req.GetString("type", "hex")
	off := req.GetInt("offset", 0)
	limit := req.GetInt("limit", 50)
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	var pattern []byte
	if searchType == "hex" {
		clean := ""
		for _, c := range patternStr {
			if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
				clean += string(c)
			}
		}
		var err error
		pattern, err = hex.DecodeString(clean)
		if err != nil || len(pattern) == 0 {
			return mcpErr("invalid hex pattern")
		}
	} else {
		pattern = []byte(patternStr)
		if len(pattern) == 0 {
			return mcpErr("empty pattern")
		}
	}

	// Start search (reuse existing global search mechanism)
	currentSearchMu.Lock()
	if currentSearch != nil && currentSearch.cancel != nil {
		currentSearch.cancel()
	}
	searchCtx, cancel := context.WithCancel(context.Background())
	job := &SearchJob{
		id:      fmt.Sprintf("mcp_%d", time.Now().UnixNano()),
		pattern: pattern,
		cancel:  cancel,
	}
	currentSearch = job
	currentSearchMu.Unlock()

	go runSearch(searchCtx, job)

	// Wait for completion
	if !waitForDone(func() bool { return job.done.Load() }, 5*time.Minute) {
		return mcpErr("搜索超时（5分钟）")
	}

	// Return paginated results
	job.mu.Lock()
	total := len(job.matches)
	end := off + limit
	if end > total {
		end = total
	}
	var slice []SearchMatch
	if off < total {
		slice = make([]SearchMatch, end-off)
		copy(slice, job.matches[off:end])
	}
	job.mu.Unlock()
	if slice == nil {
		slice = []SearchMatch{}
	}

	return mcpJSON(map[string]interface{}{
		"done": true, "scanned": job.scanned.Load(),
		"totalMatches": total, "totalRecords": db.totalRecs.Load(),
		"matches": slice,
	})
}

// ==================== Tool: search_instructions ====================

func handleSearchInstructions(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	keyword := req.GetString("keyword", "")
	if keyword == "" {
		return mcpErr("keyword is required")
	}
	off := req.GetInt("offset", 0)
	limit := req.GetInt("limit", 50)
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	instrSearchMu.Lock()
	if instrSearch != nil && instrSearch.cancel != nil {
		instrSearch.cancel()
	}
	searchCtx, cancel := context.WithCancel(context.Background())
	job := &InstrSearchJob{
		id:      fmt.Sprintf("mcp_%d", time.Now().UnixNano()),
		keyword: strings.ToLower(keyword),
		cancel:  cancel,
	}
	instrSearch = job
	instrSearchMu.Unlock()

	go runInstrSearch(searchCtx, job)

	if !waitForDone(func() bool { return job.done.Load() }, 5*time.Minute) {
		return mcpErr("搜索超时（5分钟）")
	}

	job.mu.Lock()
	total := len(job.matches)
	end := off + limit
	if end > total {
		end = total
	}
	var slice []InstrSearchMatch
	if off < total {
		slice = make([]InstrSearchMatch, end-off)
		copy(slice, job.matches[off:end])
	}
	job.mu.Unlock()
	if slice == nil {
		slice = []InstrSearchMatch{}
	}

	return mcpJSON(map[string]interface{}{
		"done": true, "scanned": job.scanned.Load(),
		"totalMatches": total, "totalRecords": db.totalRecs.Load(),
		"matches": slice,
	})
}

// ==================== Tool: set_watchpoint ====================

func handleSetWatchpoint(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	addrStr := req.GetString("addr", "")
	size := req.GetInt("size", 0)
	off := req.GetInt("offset", 0)
	limit := req.GetInt("limit", 50)
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	addr, err := strconv.ParseUint(strings.TrimPrefix(addrStr, "0x"), 16, 64)
	if err != nil || size <= 0 {
		return mcpErr("invalid addr or size")
	}

	wpJobMu.Lock()
	if wpJob != nil && wpJob.cancel != nil {
		wpJob.cancel()
	}
	wpCtx, cancel := context.WithCancel(context.Background())
	job := &WatchpointJob{
		id: fmt.Sprintf("mcp_%d", time.Now().UnixNano()), addr: addr, size: uint64(size), cancel: cancel,
	}
	wpJob = job
	wpJobMu.Unlock()

	go runWatchpoint(wpCtx, job)

	if !waitForDone(func() bool { return job.done.Load() }, 5*time.Minute) {
		return mcpErr("监控点搜索超时（5分钟）")
	}

	job.mu.Lock()
	total := len(job.matches)
	end := off + limit
	if end > total {
		end = total
	}
	var slice []WatchpointMatch
	if off < total {
		slice = make([]WatchpointMatch, end-off)
		copy(slice, job.matches[off:end])
	}
	job.mu.Unlock()
	if slice == nil {
		slice = []WatchpointMatch{}
	}

	return mcpJSON(map[string]interface{}{
		"done": true, "scanned": job.scanned.Load(),
		"totalMatches": total, "totalRecords": db.totalRecs.Load(),
		"matches": slice,
	})
}

// ==================== Tool: watchpoint_traceback ====================

func handleWatchpointTraceback(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	beforeIndex := req.GetInt("before_index", -1)
	if beforeIndex < 0 {
		return mcpErr("before_index is required")
	}
	typeFilter := req.GetString("type_filter", "write")
	off := req.GetInt("offset", 0)
	limit := req.GetInt("limit", 50)
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	// Get current watchpoint job
	wpJobMu.Lock()
	job := wpJob
	wpJobMu.Unlock()

	if job == nil {
		return mcpErr("没有活跃的监控点，请先调用 set_watchpoint")
	}

	// Wait if still running
	if !job.done.Load() {
		if !waitForDone(func() bool { return job.done.Load() }, 5*time.Minute) {
			return mcpErr("监控点搜索超时")
		}
	}

	// Filter: index < beforeIndex, optional type filter, then reverse sort
	job.mu.Lock()
	var filtered []WatchpointMatch
	for _, m := range job.matches {
		if m.Index >= beforeIndex {
			continue
		}
		if typeFilter == "write" && m.ChunkType != "write" {
			continue
		}
		if typeFilter == "read" && m.ChunkType != "read" {
			continue
		}
		filtered = append(filtered, m)
	}
	job.mu.Unlock()

	// Sort descending by index (nearest first)
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].Index > filtered[j].Index })

	total := len(filtered)
	end := off + limit
	if end > total {
		end = total
	}
	var slice []WatchpointMatch
	if off < total {
		slice = filtered[off:end]
	}
	if slice == nil {
		slice = []WatchpointMatch{}
	}

	return mcpJSON(map[string]interface{}{
		"totalMatches": total,
		"beforeIndex":  beforeIndex,
		"typeFilter":   typeFilter,
		"matches":      slice,
	})
}

// ==================== Tool: trace_register ====================

func handleTraceRegister(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	reg := req.GetString("reg", "")
	if reg == "" {
		return mcpErr("reg is required")
	}
	from := req.GetInt("from", 0)
	to := req.GetInt("to", 0)
	off := req.GetInt("offset", 0)
	limit := req.GetInt("limit", 200)
	if limit <= 0 || limit > 10000 {
		limit = 200
	}

	regJobMu.Lock()
	if regJob != nil && regJob.cancel != nil {
		regJob.cancel()
	}
	regCtx, cancel := context.WithCancel(context.Background())
	job := &RegTraceJob{
		id: fmt.Sprintf("mcp_%d", time.Now().UnixNano()), reg: strings.ToLower(reg), cancel: cancel,
		from: from, to: to,
	}
	regJob = job
	regJobMu.Unlock()

	go runRegTrace(regCtx, job)

	if !waitForDone(func() bool { return job.done.Load() }, 5*time.Minute) {
		return mcpErr("寄存器追踪超时（5分钟）")
	}

	job.mu.Lock()
	total := len(job.matches)
	end := off + limit
	if end > total {
		end = total
	}
	var slice []RegTraceMatch
	if off < total {
		slice = make([]RegTraceMatch, end-off)
		copy(slice, job.matches[off:end])
	}
	job.mu.Unlock()
	if slice == nil {
		slice = []RegTraceMatch{}
	}

	totalRecs := db.totalRecs.Load()
	if to > 0 && from >= 0 {
		totalRecs = int64(to - from)
	}

	return mcpJSON(map[string]interface{}{
		"done": true, "scanned": job.scanned.Load(),
		"totalMatches": total, "totalRecords": totalRecs,
		"matches": slice,
	})
}

// ==================== Resources ====================

func handleResourceInfo(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	db.tidSetMu.RLock()
	tids := db.tidSet
	db.tidSetMu.RUnlock()

	result := map[string]interface{}{
		"totalRecords": db.totalRecs.Load(),
		"indexDone":    db.indexDone.Load(),
		"threadIds":    tids,
		"entryContext": parseEntryContext(),
	}
	b, _ := json.Marshal(result)
	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      "trace://info",
			MIMEType: "application/json",
			Text:     string(b),
		},
	}, nil
}

func handleResourceFunctions(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	if !db.indexDone.Load() {
		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      "trace://functions",
				MIMEType: "application/json",
				Text:     `{"error":"索引未完成"}`,
			},
		}, nil
	}

	db.funcMu.RLock()
	funcs := make([]FuncInfo, 0, len(db.funcMap))
	for pc, info := range db.funcMap {
		funcs = append(funcs, FuncInfo{
			TargetPC:   fmt.Sprintf("0x%x", pc),
			CallCount:  info.CallCount,
			FirstCall:  info.FirstCall,
			TotalInstr: info.TotalInstr,
		})
	}
	db.funcMu.RUnlock()

	sort.Slice(funcs, func(i, j int) bool { return funcs[i].CallCount > funcs[j].CallCount })

	b, _ := json.Marshal(map[string]interface{}{
		"total": len(funcs), "functions": funcs,
	})
	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      "trace://functions",
			MIMEType: "application/json",
			Text:     string(b),
		},
	}, nil
}
