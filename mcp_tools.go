package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
)

// ==================== Helper ====================

func mcpJSON(v interface{}) (*mcp.CallToolResult, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("json marshal: %w", err)
	}
	return mcp.NewToolResultText(string(b)), nil
}

func mcpErr(msg string) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.TextContent{Type: "text", Text: msg}},
		IsError: true,
	}, nil
}

// parseEntryContext extracts entry info from the first record.
func parseEntryContext() map[string]interface{} {
	result := map[string]interface{}{}
	if db.totalRecs.Load() == 0 {
		return result
	}
	f := db.getFile()
	if f == nil {
		return result
	}
	defer db.putFile(f)

	info, err := readInstrAt(f, 0)
	if err != nil {
		return result
	}

	result["mainThreadId"] = info.ThreadId
	result["entryInstr"] = info.InstrText

	pcText := info.PCText
	// PCText format: "(0x4005bc04)libmain.so+0x5bc04"
	if idx := strings.Index(pcText, ")"); idx >= 0 {
		addrPart := pcText[1:idx] // "0x4005bc04"
		rest := pcText[idx+1:]    // "libmain.so+0x5bc04"
		result["entryPC"] = addrPart
		result["entrySymbol"] = rest
		if plusIdx := strings.Index(rest, "+"); plusIdx > 0 {
			result["mainSo"] = rest[:plusIdx]
		}
	} else {
		result["entryPC"] = fmt.Sprintf("0x%x", info.PC)
		result["entrySymbol"] = pcText
	}
	return result
}

// ==================== Tool: trace_info ====================

func handleTraceInfo(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	db.tidSetMu.RLock()
	tids := db.tidSet
	db.tidSetMu.RUnlock()

	result := map[string]interface{}{
		"totalRecords": db.totalRecs.Load(),
		"indexDone":    db.indexDone.Load(),
		"threadIds":    tids,
		"entryContext": parseEntryContext(),
	}
	return mcpJSON(result)
}

// ==================== Tool: get_instructions ====================

func handleGetInstructions(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	off := req.GetInt("offset", 0)
	limit := req.GetInt("limit", 100)
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if off < 0 {
		off = 0
	}

	// Center mode: convert center + context_size to offset + limit
	if args := req.GetArguments(); args != nil {
		if _, ok := args["center"]; ok {
			center := req.GetInt("center", 0)
			ctxSize := req.GetInt("context_size", 20)
			if ctxSize <= 0 {
				ctxSize = 20
			}
			off = center - ctxSize
			if off < 0 {
				off = 0
			}
			limit = ctxSize*2 + 1
			if limit > 500 {
				limit = 500
			}
		}
	}

	tidFilter := int32(-1)
	if args := req.GetArguments(); args != nil {
		if _, ok := args["tid"]; ok {
			tidFilter = int32(req.GetInt("tid", -1))
		}
	}

	total := int(db.totalRecs.Load())

	type Item struct {
		Index    int    `json:"index"`
		ThreadId int32  `json:"threadId"`
		PC       string `json:"pc"`
		Instr    string `json:"instrText"`
		Regs     string `json:"regText"`
		Depth    int    `json:"depth"`
		MemFlag  string `json:"memFlag,omitempty"`
	}

	if tidFilter >= 0 {
		db.tidIndexMu.RLock()
		matched := db.tidIndex[tidFilter]
		db.tidIndexMu.RUnlock()

		filteredTotal := len(matched)
		end := off + limit
		if end > filteredTotal {
			end = filteredTotal
		}
		if off >= filteredTotal {
			return mcpJSON(map[string]interface{}{
				"offset": off, "limit": limit, "total": filteredTotal, "items": []interface{}{},
			})
		}

		f := db.getFile()
		if f == nil {
			return mcpErr("文件打开失败")
		}
		defer db.putFile(f)

		slice := matched[off:end]
		items := make([]Item, 0, len(slice))
		for _, globalIdx := range slice {
			fileOff := db.seekToRecord(globalIdx)
			if fileOff < 0 {
				continue
			}
			info, err := readInstrAt(f, fileOff)
			if err != nil {
				continue
			}
			depth := 0
			db.depthMu.RLock()
			if globalIdx < len(db.depths) {
				depth = int(db.depths[globalIdx])
			}
			db.depthMu.RUnlock()
			items = append(items, Item{
				Index: globalIdx, ThreadId: info.ThreadId,
				PC: info.PCText, Instr: info.InstrText, Regs: info.RegText,
				Depth: depth, MemFlag: info.MemFlag,
			})
		}
		return mcpJSON(map[string]interface{}{
			"offset": off, "limit": limit, "total": filteredTotal, "items": items,
		})
	}

	// No tid filter
	end := off + limit
	if end > total {
		end = total
	}
	if off >= total {
		return mcpJSON(map[string]interface{}{
			"offset": off, "limit": limit, "total": total, "items": []interface{}{},
		})
	}

	f := db.getFile()
	if f == nil {
		return mcpErr("文件打开失败")
	}
	defer db.putFile(f)

	items := make([]Item, 0, end-off)
	fileOff := db.seekToRecord(off)
	if fileOff < 0 {
		return mcpErr("定位失败")
	}
	for i := off; i < end; i++ {
		info, err := readInstrAt(f, fileOff)
		if err != nil {
			break
		}
		depth := 0
		db.depthMu.RLock()
		if i < len(db.depths) {
			depth = int(db.depths[i])
		}
		db.depthMu.RUnlock()
		items = append(items, Item{
			Index: i, ThreadId: info.ThreadId,
			PC: info.PCText, Instr: info.InstrText, Regs: info.RegText,
			Depth: depth, MemFlag: info.MemFlag,
		})
		fileOff = info.NextOffset
	}
	return mcpJSON(map[string]interface{}{
		"offset": off, "limit": limit, "total": total, "items": items,
	})
}

// ==================== Tool: get_memory ====================

func handleGetMemory(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	idx := req.GetInt("index", -1)
	total := db.totalRecs.Load()
	if idx < 0 || idx >= int(total) {
		return mcpErr("无效的 index")
	}

	fileOff := db.seekToRecord(idx)
	if fileOff < 0 {
		return mcpErr("定位失败")
	}

	f := db.getFile()
	if f == nil {
		return mcpErr("文件打开失败")
	}
	defer db.putFile(f)

	readChunks, writeChunks, err := readChunksFromFile(f, fileOff)
	if err != nil {
		return mcpErr("读取失败")
	}

	type AccessRange struct {
		Start string `json:"start"`
		Size  int    `json:"size"`
		Hex   string `json:"hex"`
	}
	type Region struct {
		Base        string            `json:"base"`
		Size        int               `json:"size"`
		Hex         map[string]string `json:"hex"`
		Type        string            `json:"type"`
		AccessRange *AccessRange      `json:"accessRange,omitempty"`
	}

	const contextBytes = 32

	regions := make([]Region, 0)
	processChunks := func(chunks []MemChunk, chunkType string) {
		for _, c := range chunks {
			// Calculate access range (middle of 256-byte window)
			const windowSize = 256
			accessSize := len(c.Data) - windowSize
			if accessSize < 1 {
				accessSize = 1
			}
			accessStartOff := windowSize / 2
			accessEndOff := accessStartOff + accessSize
			if accessEndOff > len(c.Data) {
				accessEndOff = len(c.Data)
			}
			accessStartAddr := c.Base + uint64(accessStartOff)

			// 提取 accessRange 的 hex
			accessHex := hex.EncodeToString(c.Data[accessStartOff:accessEndOff])

			// 截取上下 contextBytes 字节的窗口
			windowStart := accessStartOff - contextBytes
			if windowStart < 0 {
				windowStart = 0
			}
			windowEnd := accessEndOff + contextBytes
			if windowEnd > len(c.Data) {
				windowEnd = len(c.Data)
			}
			windowData := c.Data[windowStart:windowEnd]
			windowBase := c.Base + uint64(windowStart)

			// 4字节分组格式化 hex
			hexMap := make(map[string]string)
			for off := 0; off < len(windowData); off += 4 {
				end := off + 4
				if end > len(windowData) {
					end = len(windowData)
				}
				addr := windowBase + uint64(off)
				hexMap[fmt.Sprintf("0x%x", addr)] = hex.EncodeToString(windowData[off:end])
			}

			r := Region{
				Base: fmt.Sprintf("0x%x", windowBase),
				Size: len(windowData),
				Hex:  hexMap,
				Type: chunkType,
				AccessRange: &AccessRange{
					Start: fmt.Sprintf("0x%x", accessStartAddr),
					Size:  accessSize,
					Hex:   accessHex,
				},
			}
			regions = append(regions, r)
		}
	}
	processChunks(readChunks, "read")
	processChunks(writeChunks, "write")

	return mcpJSON(map[string]interface{}{
		"index": idx, "regions": regions,
	})
}

// ==================== Tool: get_functions ====================

func handleGetFunctions(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if !db.indexDone.Load() {
		return mcpErr("索引未完成，请稍后再试")
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

	return mcpJSON(map[string]interface{}{
		"total": len(funcs), "functions": funcs,
	})
}
