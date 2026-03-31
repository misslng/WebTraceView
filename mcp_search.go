package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

// waitForDone polls until isDone returns true or timeout.
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

// MCP watchpoint jobs indexed by ID (supports multiple concurrent watchpoints)
var (
	mcpWpJobs  = make(map[string]*WatchpointJob)
	mcpWpJobMu sync.Mutex
)

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

	// Independent job — does NOT touch global currentSearch
	searchCtx, cancel := context.WithCancel(context.Background())
	job := &SearchJob{
		id:      fmt.Sprintf("mcp_%d", time.Now().UnixNano()),
		pattern: pattern,
		cancel:  cancel,
	}

	go runSearch(searchCtx, job)

	if !waitForDone(func() bool { return job.done.Load() }, 5*time.Minute) {
		cancel()
		return mcpErr("搜索超时（5分钟）")
	}

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

	lineJump := -1
	if args := req.GetArguments(); args != nil {
		if _, ok := args["line"]; ok {
			lineJump = req.GetInt("line", -1)
		}
	}

	searchCtx, cancel := context.WithCancel(context.Background())
	kwLower := strings.ToLower(keyword)
	job := &InstrSearchJob{
		id:      fmt.Sprintf("mcp_%d", time.Now().UnixNano()),
		keyword: kwLower,
		tokens:  strings.Fields(kwLower),
		cancel:  cancel,
	}

	go runInstrSearch(searchCtx, job)

	if !waitForDone(func() bool { return job.done.Load() }, 5*time.Minute) {
		cancel()
		return mcpErr("搜索超时（5分钟）")
	}

	job.mu.Lock()
	total := len(job.matches)

	foundPosition := -1
	if lineJump >= 0 {
		for i, m := range job.matches {
			if m.Index == lineJump {
				foundPosition = i
				break
			}
		}
		if foundPosition >= 0 {
			off = (foundPosition / limit) * limit
		}
	}

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

	result := map[string]interface{}{
		"done": true, "scanned": job.scanned.Load(),
		"totalMatches": total, "totalRecords": db.totalRecs.Load(),
		"offset": off, "matches": slice,
	}
	if lineJump >= 0 {
		result["foundPosition"] = foundPosition
		result["lineFound"] = foundPosition >= 0
	}

	return mcpJSON(result)
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

	// Independent job — does NOT touch global wpJob
	wpCtx, cancel := context.WithCancel(context.Background())
	jobId := fmt.Sprintf("wp_%s_%d", addrStr, time.Now().UnixNano())
	job := &WatchpointJob{
		id: jobId, addr: addr, size: uint64(size), cancel: cancel,
	}

	go runWatchpoint(wpCtx, job)

	if !waitForDone(func() bool { return job.done.Load() }, 5*time.Minute) {
		cancel()
		return mcpErr("监控点搜索超时（5分钟）")
	}

	// Save to map for traceback
	mcpWpJobMu.Lock()
	mcpWpJobs[jobId] = job
	mcpWpJobMu.Unlock()

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
		"watchpoint_id": jobId,
		"done":          true, "scanned": job.scanned.Load(),
		"totalMatches": total, "totalRecords": db.totalRecs.Load(),
		"matches": slice,
	})
}

// ==================== Tool: watchpoint_traceback ====================

func handleWatchpointTraceback(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	wpId := req.GetString("watchpoint_id", "")
	beforeIndex := req.GetInt("before_index", -1)
	if beforeIndex < 0 {
		return mcpErr("before_index is required")
	}
	if wpId == "" {
		return mcpErr("watchpoint_id is required，请传入 set_watchpoint 返回的 watchpoint_id")
	}
	typeFilter := req.GetString("type_filter", "write")
	off := req.GetInt("offset", 0)
	limit := req.GetInt("limit", 50)
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	mcpWpJobMu.Lock()
	job, ok := mcpWpJobs[wpId]
	mcpWpJobMu.Unlock()

	if !ok || job == nil {
		return mcpErr("watchpoint_id 不存在，请先调用 set_watchpoint")
	}

	if !job.done.Load() {
		if !waitForDone(func() bool { return job.done.Load() }, 5*time.Minute) {
			return mcpErr("监控点搜索超时")
		}
	}

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

	// Independent job — does NOT touch global regJob
	regCtx, cancel := context.WithCancel(context.Background())
	job := &RegTraceJob{
		id: fmt.Sprintf("mcp_%d", time.Now().UnixNano()), reg: strings.ToLower(reg), cancel: cancel,
		from: from, to: to,
	}

	go runRegTrace(regCtx, job)

	if !waitForDone(func() bool { return job.done.Load() }, 5*time.Minute) {
		cancel()
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
