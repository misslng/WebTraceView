package main

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed index.html
var frontendHTML []byte

// ==================== 核心设计 ====================
// 一条指令一条记录，格式：
//   magic(4) threadId(4) pc(8) pcTextLen(2) pcText instrLen(2) instr regLen(2) reg
//   readChunkCnt(4) [base(8) len(4) data]×N
//   writeChunkCnt(4) [base(8) len(4) data]×N
// 第0条是 baseline，之后每条 = 一条指令

const BLOCK_SIZE = 10000

type BlockAnchor struct {
	RecordIdx int
	Offset    int64
}

type TraceDB struct {
	path string
	size int64

	anchors   []BlockAnchor
	anchorMu  sync.RWMutex
	indexDone atomic.Bool
	totalRecs atomic.Int64

	// 每条记录的调用深度
	depths  []int16
	depthMu sync.RWMutex

	// 每条记录的线程 ID
	tids  []int32
	tidMu sync.RWMutex

	// 所有出现过的线程 ID（去重有序）
	tidSet   []int32
	tidSetMu sync.RWMutex

	// 每个 tid 对应的记录索引列表（预建索引，加速过滤）
	tidIndex   map[int32][]int
	tidIndexMu sync.RWMutex

	// 函数摘要
	funcMap map[uint64]*FuncEntry
	funcMu  sync.RWMutex

	// 函数调用时间线（bl/ret 事件）
	funcEvents   []FuncEvent
	funcEventsMu sync.RWMutex

	// 调用树缓存
	callFlowLines []CallFlowLine
	callFlowBuilt atomic.Bool

	pool sync.Pool
}

type FuncEntry struct {
	CallCount   int
	FirstCall   int
	TotalInstr  int
	lastCallIdx int
}

type FuncEvent struct {
	Index int    `json:"index"`
	PC    uint64 `json:"pc"`
	Depth int16  `json:"depth"`
	Type  byte   `json:"type"` // 'C' = call, 'R' = ret
}

type CallFlowLine struct {
	Type  string `json:"type"` // "call" or "ret"
	PC    string `json:"pc"`
	Depth int    `json:"depth"`
	From  int    `json:"from"`
	To    int    `json:"to"`
}

func (db *TraceDB) getFile() *os.File {
	if v := db.pool.Get(); v != nil {
		return v.(*os.File)
	}
	f, err := os.Open(db.path)
	if err != nil {
		log.Printf("打开文件失败: %v", err)
		return nil
	}
	return f
}

func (db *TraceDB) putFile(f *os.File) {
	if f != nil {
		db.pool.Put(f)
	}
}

var db *TraceDB

// ==================== 全局搜索 ====================

type SearchMatch struct {
	Index       int    `json:"index"`
	PC          string `json:"pc"`
	InstrText   string `json:"instrText"`
	ChunkBase   string `json:"chunkBase"`
	MatchOff    int    `json:"matchOffset"`
	ChunkType   string `json:"type"` // "read" or "write"
	PatternLen  int    `json:"patternLen"`
	DataPreview string `json:"dataPreview"`
}

type SearchJob struct {
	id      string
	pattern []byte

	mu      sync.Mutex
	matches []SearchMatch

	scanned atomic.Int64
	done    atomic.Bool
	cancel  context.CancelFunc
}

var (
	currentSearch   *SearchJob
	currentSearchMu sync.Mutex
)

func main() {
	binPath := "trace_output.bin"
	if len(os.Args) > 1 {
		binPath = os.Args[1]
	}

	fi, err := os.Stat(binPath)
	if err != nil {
		log.Fatalf("无法访问文件: %v", err)
	}
	log.Printf("文件大小: %.2f GB", float64(fi.Size())/(1024*1024*1024))

	db = &TraceDB{path: binPath, size: fi.Size(), funcMap: make(map[uint64]*FuncEntry)}
	db.anchors = append(db.anchors, BlockAnchor{0, 0})
	sessionPath = binPath + ".session.json"

	go db.buildIndexAsync()

	http.HandleFunc("/api/info", handleInfo)
	http.HandleFunc("/api/instructions", handleInstructions)
	http.HandleFunc("/api/memory", handleMemory)
	http.HandleFunc("/api/search", handleSearch)
	http.HandleFunc("/api/search/results", handleSearchResults)
	http.HandleFunc("/api/search/instr", handleSearchInstr)
	http.HandleFunc("/api/watchpoint", handleWatchpoint)
	http.HandleFunc("/api/watchpoint/results", handleWatchpointResults)
	http.HandleFunc("/api/search/reg", handleSearchReg)
	http.HandleFunc("/api/search/reg/results", handleSearchRegResults)
	http.HandleFunc("/api/functions", handleFunctions)
	http.HandleFunc("/api/calltree", handleCallTimeline)
	http.HandleFunc("/api/session", handleSession)
	http.HandleFunc("/api/tid", handleTid)
	http.HandleFunc("/api/tid-position", handleTidPosition)
	http.Handle("/mcp", setupMCP())
	http.HandleFunc("/", handleFrontend)

	addr := ":8080"
	log.Printf("服务已启动: http://localhost%s", addr)
	log.Printf("MCP 端点: http://localhost%s/mcp", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

// ==================== 后台索引 ====================

func (db *TraceDB) buildIndexAsync() {
	t0 := time.Now()
	f, err := os.Open(db.path)
	if err != nil {
		log.Fatalf("索引: 打开文件失败: %v", err)
	}
	defer f.Close()

	br := bufio.NewReaderSize(f, 8*1024*1024)
	offset := int64(0)
	count := 0
	magic := make([]byte, 4)
	hdr := make([]byte, 12)
	callDepth := int16(0)
	retStack := make([]uint64, 0, 256)
	pendingRet := false
	pendingCallIdx := -1 // 上一条是 bl/blr 时记录其 index

	for {
		if _, err := io.ReadFull(br, magic); err != nil {
			break
		}
		if string(magic) != "UTRA" {
			break
		}
		offset += 4

		// 读 threadId(4)
		var tidBuf [4]byte
		if _, err := io.ReadFull(br, tidBuf[:]); err != nil {
			break
		}
		tid := int32(binary.LittleEndian.Uint32(tidBuf[:]))
		offset += 4

		// 读 pc(8)
		var pc uint64
		pcBuf := make([]byte, 8)
		if _, err := io.ReadFull(br, pcBuf); err != nil {
			break
		}
		pc = binary.LittleEndian.Uint64(pcBuf)
		offset += 8

		// 读 pcTextLen(2) + pcText
		var pcTextLen uint16
		if err := binary.Read(br, binary.LittleEndian, &pcTextLen); err != nil {
			break
		}
		offset += 2
		if _, err := io.CopyN(io.Discard, br, int64(pcTextLen)); err != nil {
			break
		}
		offset += int64(pcTextLen)

		// 如果上一条是 bl/blr，当前 PC 就是被调用函数的入口
		if pendingCallIdx >= 0 {
			db.funcMu.Lock()
			entry, ok := db.funcMap[pc]
			if !ok {
				entry = &FuncEntry{FirstCall: pendingCallIdx}
				db.funcMap[pc] = entry
			}
			entry.CallCount++
			entry.lastCallIdx = count
			db.funcMu.Unlock()
			pendingCallIdx = -1
		}

		// 如果上一条是 ret，用当前 PC 去栈里匹配
		if pendingRet {
			pendingRet = false
			matched := false
			// 从栈顶往下找（最近的 bl 优先匹配）
			for i := len(retStack) - 1; i >= 0; i-- {
				if retStack[i] == pc {
					// 匹配成功，弹出这个及以上的所有条目
					retStack = retStack[:i]
					callDepth = int16(i)
					matched = true
					// 记录 ret 事件
					db.funcEventsMu.Lock()
					db.funcEvents = append(db.funcEvents, FuncEvent{Index: count, PC: pc, Depth: callDepth, Type: 'R'})
					db.funcEventsMu.Unlock()
					break
				}
			}
			if !matched {
				// 没匹配到，说明是 tail call 的 ret，depth 不变
				// callDepth 保持不变（ret 时没减，所以不用加回来）
			}
			// 回填 ret 那条指令的 depth（ret 应该和返回后的 depth 一致）
			db.depthMu.Lock()
			db.depths[len(db.depths)-1] = callDepth
			db.depthMu.Unlock()
		}

		// 读 instrText
		var instrLen uint16
		if err := binary.Read(br, binary.LittleEndian, &instrLen); err != nil {
			break
		}
		offset += 2
		instrBuf := make([]byte, instrLen)
		if _, err := io.ReadFull(br, instrBuf); err != nil {
			break
		}
		offset += int64(instrLen)

		// 判断指令类型
		instrText := strings.ToLower(string(instrBuf))
		mnemonic := instrText
		if idx := strings.IndexByte(instrText, ' '); idx > 0 {
			mnemonic = instrText[:idx]
		}

		isRet := mnemonic == "ret"
		isCall := mnemonic == "bl" || mnemonic == "blr" || mnemonic == "blx" ||
			mnemonic == "blraa" || mnemonic == "blrab" || mnemonic == "blraaz" || mnemonic == "blrabz"

		if isRet {
			pendingRet = true
			// 先用当前 callDepth 占位，下一条指令匹配后会回填正确值
		}

		db.depthMu.Lock()
		db.depths = append(db.depths, callDepth)
		db.depthMu.Unlock()

		// 记录 tid
		db.tidMu.Lock()
		db.tids = append(db.tids, tid)
		db.tidMu.Unlock()

		if isCall {
			// bl 的返回地址 = pc + 4
			retStack = append(retStack, pc+4)
			callDepth++
			pendingCallIdx = count
			// 记录 call 事件
			db.funcEventsMu.Lock()
			db.funcEvents = append(db.funcEvents, FuncEvent{Index: count, PC: pc, Depth: callDepth, Type: 'C'})
			db.funcEventsMu.Unlock()
		}

		// 跳 regText
		var regLen uint16
		if err := binary.Read(br, binary.LittleEndian, &regLen); err != nil {
			break
		}
		offset += 2
		if _, err := io.CopyN(io.Discard, br, int64(regLen)); err != nil {
			break
		}
		offset += int64(regLen)

		// 跳 readChunks
		if !skipChunkGroup(br, hdr, &offset) {
			break
		}
		// 跳 writeChunks
		if !skipChunkGroup(br, hdr, &offset) {
			break
		}

		count++
		if count%BLOCK_SIZE == 0 {
			db.anchorMu.Lock()
			db.anchors = append(db.anchors, BlockAnchor{count, offset})
			db.anchorMu.Unlock()
		}
		db.totalRecs.Store(int64(count))

		if count%1000000 == 0 {
			pct := float64(offset) / float64(db.size) * 100
			log.Printf("索引: %dM 条 (%.1f%%), %.0f 条/秒",
				count/1000000, pct, float64(count)/time.Since(t0).Seconds())
		}
	}

	db.totalRecs.Store(int64(count))
	db.indexDone.Store(true)

	// 归一化 depth：找到最小值，全部提升，让最小值变为 0
	db.depthMu.Lock()
	minDepth := int16(0)
	maxDepth := int16(0)
	for _, d := range db.depths {
		if d < minDepth {
			minDepth = d
		}
		if d > maxDepth {
			maxDepth = d
		}
	}
	if minDepth < 0 {
		for i := range db.depths {
			db.depths[i] -= minDepth
		}
	}
	finalDepth := int16(0)
	if len(db.depths) > 0 {
		finalDepth = db.depths[len(db.depths)-1]
	}
	db.depthMu.Unlock()

	// 收集所有出现过的 tid，同时构建 tid -> []recordIndex 索引
	tidIdx := make(map[int32][]int)
	db.tidMu.RLock()
	for i, t := range db.tids {
		tidIdx[t] = append(tidIdx[t], i)
	}
	db.tidMu.RUnlock()
	tidList := make([]int32, 0, len(tidIdx))
	for t := range tidIdx {
		tidList = append(tidList, t)
	}
	sort.Slice(tidList, func(i, j int) bool { return tidList[i] < tidList[j] })
	db.tidSetMu.Lock()
	db.tidSet = tidList
	db.tidSetMu.Unlock()
	db.tidIndexMu.Lock()
	db.tidIndex = tidIdx
	db.tidIndexMu.Unlock()

	log.Printf("索引完成: %d 条, %d 个锚点, %d 个线程, 耗时 %v", count, len(db.anchors), len(tidList), time.Since(t0))
	log.Printf("调用层级: rawMin=%d, rawMax=%d, 归一化后 max=%d, final=%d",
		minDepth, maxDepth, maxDepth-minDepth, finalDepth)
	log.Printf("函数摘要: 共识别 %d 个不同函数", len(db.funcMap))
	runtime.GC()
}

// skipChunkGroup 跳过一组 chunks: chunkCount(4) + [base(8)+len(4)+data]×N
func skipChunkGroup(br *bufio.Reader, hdr []byte, offset *int64) bool {
	var chunkCount uint32
	if err := binary.Read(br, binary.LittleEndian, &chunkCount); err != nil {
		return false
	}
	*offset += 4
	for i := uint32(0); i < chunkCount; i++ {
		if _, err := io.ReadFull(br, hdr); err != nil {
			return false
		}
		dataLen := int64(binary.LittleEndian.Uint32(hdr[8:]))
		*offset += 12
		if _, err := io.CopyN(io.Discard, br, dataLen); err != nil {
			return false
		}
		*offset += dataLen
	}
	return true
}

// ==================== 锚点二分查找 ====================

func (db *TraceDB) findAnchor(idx int) BlockAnchor {
	db.anchorMu.RLock()
	anchors := db.anchors
	db.anchorMu.RUnlock()
	lo, hi := 0, len(anchors)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if anchors[mid].RecordIdx <= idx {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return anchors[lo]
}

func (db *TraceDB) seekToRecord(idx int) int64 {
	a := db.findAnchor(idx)
	if a.RecordIdx == idx {
		return a.Offset
	}
	f := db.getFile()
	if f == nil {
		return -1
	}
	defer db.putFile(f)

	offset := a.Offset
	cur := a.RecordIdx
	buf := make([]byte, 18)
	for cur < idx {
		next := skipRecordFile(f, offset, buf)
		if next <= offset {
			return -1
		}
		offset = next
		cur++
	}
	return offset
}

// skipRecordFile 跳过一条完整记录（新格式：threadId + pcText + instrText + regText + readChunks + writeChunks）
func skipRecordFile(f *os.File, offset int64, buf []byte) int64 {
	if _, err := f.ReadAt(buf[:18], offset); err != nil {
		return offset
	}
	p := offset + 4 + 4 + 8 // skip magic + threadId + pc

	// skip pcText
	pcTextLen := int64(binary.LittleEndian.Uint16(buf[16:18]))
	p += 2 + pcTextLen

	// read instrLen
	if _, err := f.ReadAt(buf[:2], p); err != nil {
		return offset
	}
	instrLen := int64(binary.LittleEndian.Uint16(buf[:2]))
	p += 2 + instrLen

	if _, err := f.ReadAt(buf[:2], p); err != nil {
		return offset
	}
	regLen := int64(binary.LittleEndian.Uint16(buf[:2]))
	p += 2 + regLen

	// 跳 readChunks
	p = skipChunkGroupFile(f, p, buf)
	if p < 0 {
		return offset
	}
	// 跳 writeChunks
	p = skipChunkGroupFile(f, p, buf)
	if p < 0 {
		return offset
	}
	return p
}

func skipChunkGroupFile(f *os.File, p int64, buf []byte) int64 {
	if _, err := f.ReadAt(buf[:4], p); err != nil {
		return -1
	}
	cnt := binary.LittleEndian.Uint32(buf[:4])
	p += 4
	for i := uint32(0); i < cnt; i++ {
		if _, err := f.ReadAt(buf[:12], p); err != nil {
			return -1
		}
		dataLen := int64(binary.LittleEndian.Uint32(buf[8:12]))
		p += 12 + dataLen
	}
	return p
}

// ==================== 按需读取 ====================

type InstrInfo struct {
	ThreadId   int32
	PC         uint64
	PCText     string // "libc.so+0x1a3b4" 或 "0x..."
	InstrText  string
	RegText    string
	MemFlag    string // "", "R", "W", "RW"
	NextOffset int64
}

func readInstrAt(f *os.File, offset int64) (*InstrInfo, error) {
	hdr := make([]byte, 18)
	if _, err := f.ReadAt(hdr, offset); err != nil {
		return nil, err
	}
	if string(hdr[:4]) != "UTRA" {
		return nil, fmt.Errorf("invalid magic")
	}
	threadId := int32(binary.LittleEndian.Uint32(hdr[4:8]))
	pc := binary.LittleEndian.Uint64(hdr[8:16])
	pcTextLen := int(binary.LittleEndian.Uint16(hdr[16:18]))
	p := offset + 18

	pcTextBuf := make([]byte, pcTextLen)
	if _, err := f.ReadAt(pcTextBuf, p); err != nil {
		return nil, err
	}
	p += int64(pcTextLen)

	ilBuf := make([]byte, 2)
	if _, err := f.ReadAt(ilBuf, p); err != nil {
		return nil, err
	}
	instrLen := int(binary.LittleEndian.Uint16(ilBuf))
	p += 2

	instrBuf := make([]byte, instrLen)
	if _, err := f.ReadAt(instrBuf, p); err != nil {
		return nil, err
	}
	p += int64(instrLen)

	rlBuf := make([]byte, 2)
	if _, err := f.ReadAt(rlBuf, p); err != nil {
		return nil, err
	}
	regLen := int(binary.LittleEndian.Uint16(rlBuf))
	p += 2

	regBuf := make([]byte, regLen)
	if _, err := f.ReadAt(regBuf, p); err != nil {
		return nil, err
	}
	p += int64(regLen)

	// 读 readChunks count
	cntBuf := make([]byte, 4)
	if _, err := f.ReadAt(cntBuf, p); err != nil {
		return nil, fmt.Errorf("read chunk count failed")
	}
	readCnt := binary.LittleEndian.Uint32(cntBuf)

	buf := make([]byte, 16)
	p = skipChunkGroupFile(f, p, buf)
	if p < 0 {
		return nil, fmt.Errorf("skip read chunks failed")
	}

	// 读 writeChunks count
	if _, err := f.ReadAt(cntBuf, p); err != nil {
		return nil, fmt.Errorf("write chunk count failed")
	}
	writeCnt := binary.LittleEndian.Uint32(cntBuf)

	p = skipChunkGroupFile(f, p, buf)
	if p < 0 {
		return nil, fmt.Errorf("skip write chunks failed")
	}

	memFlag := ""
	if readCnt > 0 && writeCnt > 0 {
		memFlag = "RW"
	} else if readCnt > 0 {
		memFlag = "R"
	} else if writeCnt > 0 {
		memFlag = "W"
	}

	return &InstrInfo{
		ThreadId: threadId, PC: pc, PCText: fmt.Sprintf("(0x%x)%s", pc, string(pcTextBuf)), InstrText: string(instrBuf), RegText: string(regBuf), MemFlag: memFlag, NextOffset: p,
	}, nil
}

type MemChunk struct {
	Base uint64
	Data []byte
}

// readChunksFromFile 读取一条记录的 readChunks + writeChunks
func readChunksFromFile(f *os.File, offset int64) (readChunks, writeChunks []MemChunk, err error) {
	hdr := make([]byte, 18)
	if _, err = f.ReadAt(hdr, offset); err != nil {
		return
	}
	pcTextLen := int64(binary.LittleEndian.Uint16(hdr[16:18]))
	p := offset + 18 + pcTextLen

	// read instrLen
	ilBuf := make([]byte, 2)
	if _, err = f.ReadAt(ilBuf, p); err != nil {
		return
	}
	instrLen := int64(binary.LittleEndian.Uint16(ilBuf))
	p += 2 + instrLen

	rlBuf := make([]byte, 2)
	if _, err = f.ReadAt(rlBuf, p); err != nil {
		return
	}
	regLen := int64(binary.LittleEndian.Uint16(rlBuf))
	p += 2 + regLen

	readChunks, p, err = readChunkGroup(f, p)
	if err != nil {
		return
	}
	writeChunks, _, err = readChunkGroup(f, p)
	return
}

func readChunkGroup(f *os.File, p int64) ([]MemChunk, int64, error) {
	buf := make([]byte, 12)
	cntBuf := make([]byte, 4)
	if _, err := f.ReadAt(cntBuf, p); err != nil {
		return nil, p, err
	}
	cnt := int(binary.LittleEndian.Uint32(cntBuf))
	p += 4

	chunks := make([]MemChunk, 0, cnt)
	for i := 0; i < cnt; i++ {
		if _, err := f.ReadAt(buf, p); err != nil {
			break
		}
		base := binary.LittleEndian.Uint64(buf[:8])
		dataLen := int(binary.LittleEndian.Uint32(buf[8:12]))
		p += 12
		data := make([]byte, dataLen)
		if _, err := f.ReadAt(data, p); err != nil {
			break
		}
		chunks = append(chunks, MemChunk{Base: base, Data: data})
		p += int64(dataLen)
	}
	return chunks, p, nil
}

// ==================== HTTP Handlers ====================

func handleInfo(w http.ResponseWriter, r *http.Request) {
	db.tidSetMu.RLock()
	tids := db.tidSet
	db.tidSetMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"totalRecords": db.totalRecs.Load(),
		"indexDone":    db.indexDone.Load(),
		"threadIds":    tids,
	})
}

func handleTid(w http.ResponseWriter, r *http.Request) {
	idx, err := strconv.Atoi(r.URL.Query().Get("index"))
	if err != nil || idx < 0 {
		http.Error(w, "invalid index", 400)
		return
	}
	db.tidMu.RLock()
	defer db.tidMu.RUnlock()
	if idx >= len(db.tids) {
		http.Error(w, "index out of range", 400)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"tid": db.tids[idx]})
}

// handleTidPosition: 给定全局 index 和 tid，返回该 index 在 tid 过滤结果中的位置（第几条）
func handleTidPosition(w http.ResponseWriter, r *http.Request) {
	idx, err := strconv.Atoi(r.URL.Query().Get("index"))
	if err != nil || idx < 0 {
		http.Error(w, "invalid index", 400)
		return
	}
	tidVal, err := strconv.Atoi(r.URL.Query().Get("tid"))
	if err != nil {
		http.Error(w, "invalid tid", 400)
		return
	}
	tid := int32(tidVal)

	db.tidIndexMu.RLock()
	matched := db.tidIndex[tid]
	db.tidIndexMu.RUnlock()

	if len(matched) == 0 {
		http.Error(w, "tid not found", 404)
		return
	}

	// 二分查找：找到 >= idx 的第一个位置
	pos := sort.SearchInts(matched, idx)
	// 如果精确命中，pos 就是位置；否则返回最近的位置
	found := false
	if pos < len(matched) && matched[pos] == idx {
		found = true
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"position": pos,
		"total":    len(matched),
		"found":    found,
	})
}

func handleInstructions(w http.ResponseWriter, r *http.Request) {
	off, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	tidFilter := int32(-1)
	if tidStr := r.URL.Query().Get("tid"); tidStr != "" {
		if v, err := strconv.Atoi(tidStr); err == nil {
			tidFilter = int32(v)
		}
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if off < 0 {
		off = 0
	}

	total := int(db.totalRecs.Load())

	if tidFilter >= 0 {
		// tid 过滤模式：用预建索引直接查表
		db.tidIndexMu.RLock()
		matched := db.tidIndex[tidFilter]
		db.tidIndexMu.RUnlock()

		filteredTotal := len(matched)
		end := off + limit
		if end > filteredTotal {
			end = filteredTotal
		}
		if off >= filteredTotal {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"offset": off, "limit": limit, "total": filteredTotal, "items": []interface{}{}, "tid": tidFilter,
			})
			return
		}

		f := db.getFile()
		if f == nil {
			http.Error(w, "文件打开失败", 500)
			return
		}
		defer db.putFile(f)

		type Item struct {
			Index    int    `json:"index"`
			PC       string `json:"pc"`
			Instr    string `json:"instrText"`
			Regs     string `json:"regText"`
			Depth    int    `json:"depth"`
			MemFlag  string `json:"memFlag,omitempty"`
			ThreadId int32  `json:"threadId"`
		}

		slice := matched[off:end]
		items := make([]Item, 0, len(slice))
		// 顺序读取优化：记录上一条的 NextOffset，如果下一条紧邻就复用
		lastIdx := -1
		lastNextOff := int64(-1)
		for _, globalIdx := range slice {
			var fileOff int64
			if lastIdx >= 0 && globalIdx == lastIdx+1 && lastNextOff > 0 {
				// 紧邻上一条，直接用上一条的 NextOffset
				fileOff = lastNextOff
			} else {
				fileOff = db.seekToRecord(globalIdx)
			}
			if fileOff < 0 {
				lastIdx = globalIdx
				lastNextOff = -1
				continue
			}
			info, err := readInstrAt(f, fileOff)
			if err != nil {
				lastIdx = globalIdx
				lastNextOff = -1
				continue
			}
			lastIdx = globalIdx
			lastNextOff = info.NextOffset
			depth := 0
			db.depthMu.RLock()
			if globalIdx < len(db.depths) {
				depth = int(db.depths[globalIdx])
			}
			db.depthMu.RUnlock()
			items = append(items, Item{
				Index:    globalIdx,
				PC:       info.PCText,
				Instr:    info.InstrText,
				Regs:     info.RegText,
				Depth:    depth,
				MemFlag:  info.MemFlag,
				ThreadId: info.ThreadId,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"offset": off, "limit": limit, "total": filteredTotal, "items": items, "tid": tidFilter,
		})
		return
	}

	// 无过滤模式（原逻辑）
	end := off + limit
	if end > total {
		end = total
	}
	if off >= total {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"offset": off, "limit": limit, "total": total, "items": []interface{}{},
		})
		return
	}

	fileOff := db.seekToRecord(off)
	if fileOff < 0 {
		http.Error(w, "定位失败", 500)
		return
	}

	f := db.getFile()
	if f == nil {
		http.Error(w, "文件打开失败", 500)
		return
	}
	defer db.putFile(f)

	type Item struct {
		Index    int    `json:"index"`
		PC       string `json:"pc"`
		Instr    string `json:"instrText"`
		Regs     string `json:"regText"`
		Depth    int    `json:"depth"`
		MemFlag  string `json:"memFlag,omitempty"`
		ThreadId int32  `json:"threadId"`
	}

	items := make([]Item, 0, end-off)
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
			Index:    i,
			PC:       info.PCText,
			Instr:    info.InstrText,
			Regs:     info.RegText,
			Depth:    depth,
			MemFlag:  info.MemFlag,
			ThreadId: info.ThreadId,
		})
		fileOff = info.NextOffset
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"offset": off, "limit": limit, "total": total, "items": items,
	})
}

func handleMemory(w http.ResponseWriter, r *http.Request) {
	idxStr := r.URL.Query().Get("index")
	idx, err := strconv.Atoi(idxStr)
	total := db.totalRecs.Load()
	if err != nil || idx < 0 || idx >= int(total) {
		http.Error(w, "无效的 index", 400)
		return
	}

	fileOff := db.seekToRecord(idx)
	if fileOff < 0 {
		http.Error(w, "定位失败", 500)
		return
	}

	f := db.getFile()
	if f == nil {
		http.Error(w, "文件打开失败", 500)
		return
	}
	defer db.putFile(f)

	readChunks, writeChunks, err := readChunksFromFile(f, fileOff)
	if err != nil {
		http.Error(w, "读取失败", 500)
		return
	}

	type Region struct {
		Base string `json:"base"`
		Size int    `json:"size"`
		Hex  string `json:"hex"`
		Type string `json:"type"` // "read" or "write"
	}

	result := make([]Region, 0)
	for _, c := range readChunks {
		result = append(result, Region{
			Base: fmt.Sprintf("0x%x", c.Base), Size: len(c.Data),
			Hex: hex.EncodeToString(c.Data), Type: "read",
		})
	}
	for _, c := range writeChunks {
		result = append(result, Region{
			Base: fmt.Sprintf("0x%x", c.Base), Size: len(c.Data),
			Hex: hex.EncodeToString(c.Data), Type: "write",
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Base < result[j].Base })

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"index": idx, "regions": result,
	})
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		Pattern string `json:"pattern"`
		Type    string `json:"type"` // "hex" or "string"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", 400)
		return
	}

	var pattern []byte
	if req.Type == "hex" {
		clean := ""
		for _, c := range req.Pattern {
			if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
				clean += string(c)
			}
		}
		var err error
		pattern, err = hex.DecodeString(clean)
		if err != nil || len(pattern) == 0 {
			http.Error(w, "invalid hex pattern", 400)
			return
		}
	} else {
		pattern = []byte(req.Pattern)
		if len(pattern) == 0 {
			http.Error(w, "empty pattern", 400)
			return
		}
	}

	// 取消旧搜索
	currentSearchMu.Lock()
	if currentSearch != nil && currentSearch.cancel != nil {
		currentSearch.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	job := &SearchJob{
		id:      fmt.Sprintf("%d", time.Now().UnixNano()),
		pattern: pattern,
		cancel:  cancel,
	}
	currentSearch = job
	currentSearchMu.Unlock()

	go runSearch(ctx, job)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"searchId": job.id,
	})
}

func handleSearchResults(w http.ResponseWriter, r *http.Request) {
	currentSearchMu.Lock()
	job := currentSearch
	currentSearchMu.Unlock()

	if job == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"matches": []interface{}{}, "done": true, "scanned": 0, "total": 0,
		})
		return
	}

	off, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"matches":      slice,
		"done":         job.done.Load(),
		"scanned":      job.scanned.Load(),
		"totalMatches": total,
		"totalRecords": db.totalRecs.Load(),
	})
}

func runSearch(ctx context.Context, job *SearchJob) {
	defer job.done.Store(true)

	// 等索引至少有一些锚点
	for db.totalRecs.Load() == 0 {
		time.Sleep(100 * time.Millisecond)
	}

	// 获取当前锚点快照
	db.anchorMu.RLock()
	anchors := make([]BlockAnchor, len(db.anchors))
	copy(anchors, db.anchors)
	db.anchorMu.RUnlock()

	totalRecs := int(db.totalRecs.Load())

	// 构建分段：每段覆盖若干锚点区间
	type segment struct {
		startIdx int
		endIdx   int
		offset   int64
	}

	// 并行度：CPU 核数，但不超过锚点数
	workers := runtime.NumCPU()
	if workers > len(anchors) {
		workers = len(anchors)
	}
	if workers < 1 {
		workers = 1
	}

	// 均匀分段
	segments := make([]segment, 0, workers)
	recsPerWorker := (totalRecs + workers - 1) / workers
	for i := 0; i < workers; i++ {
		startRec := i * recsPerWorker
		endRec := (i + 1) * recsPerWorker
		if endRec > totalRecs {
			endRec = totalRecs
		}
		if startRec >= totalRecs {
			break
		}
		// 找到最近的锚点
		anchorIdx := sort.Search(len(anchors), func(j int) bool { return anchors[j].RecordIdx > startRec }) - 1
		if anchorIdx < 0 {
			anchorIdx = 0
		}
		seg := segment{
			startIdx: anchors[anchorIdx].RecordIdx,
			endIdx:   endRec,
			offset:   anchors[anchorIdx].Offset,
		}
		// 避免和上一段重叠
		if len(segments) > 0 && seg.startIdx <= segments[len(segments)-1].startIdx {
			continue
		}
		segments = append(segments, seg)
	}
	// 修正段边界：每段的 endIdx = 下一段的 startIdx
	for i := 0; i < len(segments)-1; i++ {
		segments[i].endIdx = segments[i+1].startIdx
	}
	if len(segments) > 0 {
		segments[len(segments)-1].endIdx = totalRecs
	}

	log.Printf("搜索: 启动 %d 个并行 worker, 总记录 %d", len(segments), totalRecs)

	// 每个 worker 收集局部结果，最后按 segment 顺序合并
	localResults := make([][]SearchMatch, len(segments))
	var wg sync.WaitGroup
	for i, seg := range segments {
		wg.Add(1)
		go func(i int, seg segment) {
			defer wg.Done()
			localResults[i] = runSearchSegment(ctx, job, seg.offset, seg.startIdx, seg.endIdx)
		}(i, seg)
	}
	wg.Wait()

	// 按 segment 顺序合并
	job.mu.Lock()
	for _, local := range localResults {
		job.matches = append(job.matches, local...)
	}
	job.mu.Unlock()
}

const SEARCH_MATCH_LIMIT = 500000

func runSearchSegment(ctx context.Context, job *SearchJob, fileOffset int64, startIdx, endIdx int) []SearchMatch {
	var local []SearchMatch
	f, err := os.Open(db.path)
	if err != nil {
		log.Printf("搜索: 打开文件失败: %v", err)
		return local
	}
	defer f.Close()

	if _, err := f.Seek(fileOffset, 0); err != nil {
		return local
	}

	br := bufio.NewReaderSize(f, 8*1024*1024)
	idx := startIdx

	// 复用缓冲区减少 GC
	instrBuf := make([]byte, 0, 256)
	hdr := make([]byte, 18)

	for idx < endIdx {
		select {
		case <-ctx.Done():
			return local
		default:
		}

		// 读 magic(4) + threadId(4) + pc(8) + pcTextLen(2) = 18 bytes
		if _, err := io.ReadFull(br, hdr); err != nil {
			return local
		}
		if string(hdr[:4]) != "UTRA" {
			return local
		}
		// hdr[4:8] = threadId (unused here), hdr[8:16] = pc, hdr[16:18] = pcTextLen
		pc := binary.LittleEndian.Uint64(hdr[8:16])
		pcTextLen := int(binary.LittleEndian.Uint16(hdr[16:18]))
		pcTextBuf := make([]byte, pcTextLen)
		if _, err := io.ReadFull(br, pcTextBuf); err != nil {
			return local
		}
		pcText := fmt.Sprintf("(0x%x)%s", pc, string(pcTextBuf))

		var instrLen16 uint16
		if err := binary.Read(br, binary.LittleEndian, &instrLen16); err != nil {
			return local
		}
		instrLen := int(instrLen16)

		// 复用 instrBuf
		if cap(instrBuf) < instrLen {
			instrBuf = make([]byte, instrLen, instrLen*2)
		} else {
			instrBuf = instrBuf[:instrLen]
		}
		if _, err := io.ReadFull(br, instrBuf); err != nil {
			return local
		}

		// 跳 regText
		var regLen uint16
		if err := binary.Read(br, binary.LittleEndian, &regLen); err != nil {
			return local
		}
		if _, err := io.CopyN(io.Discard, br, int64(regLen)); err != nil {
			return local
		}

		// 读 readChunks 并搜索
		local = searchChunkGroup(br, job, idx, pcText, string(instrBuf), "read", local)
		// 读 writeChunks 并搜索
		local = searchChunkGroup(br, job, idx, pcText, string(instrBuf), "write", local)

		idx++
		job.scanned.Add(1)

		// 匹配数上限
		if len(local) >= SEARCH_MATCH_LIMIT {
			return local
		}
	}
	return local
}

func searchChunkGroup(br *bufio.Reader, job *SearchJob, idx int, pcText string, instrText string, chunkType string, local []SearchMatch) []SearchMatch {
	var cnt uint32
	if err := binary.Read(br, binary.LittleEndian, &cnt); err != nil {
		return local
	}
	hdr := make([]byte, 12)
	for i := uint32(0); i < cnt; i++ {
		if _, err := io.ReadFull(br, hdr); err != nil {
			return local
		}
		base := binary.LittleEndian.Uint64(hdr[:8])
		dataLen := int(binary.LittleEndian.Uint32(hdr[8:12]))
		data := make([]byte, dataLen)
		if _, err := io.ReadFull(br, data); err != nil {
			return local
		}

		// 实际访问区域：固定窗口 = 前128 + 后128，实际操作从 offset 128 开始
		const windowSize = 256
		accessSize := dataLen - windowSize
		if accessSize < 1 {
			accessSize = 1
		}
		centerLo := windowSize / 2
		centerHi := centerLo + accessSize
		if centerHi > dataLen {
			centerHi = dataLen
		}

		// 搜索所有匹配位置，只保留与中心区域有交集的
		off := 0
		for {
			pos := bytes.Index(data[off:], job.pattern)
			if pos < 0 {
				break
			}
			matchStart := off + pos
			matchEnd := matchStart + len(job.pattern)

			// 匹配范围和中心区域有交集才算命中
			if matchStart < centerHi && matchEnd > centerLo {
				matchAddr := base + uint64(matchStart)
				// 提取匹配位置附近的 string 预览
				previewStart := matchStart
				previewEnd := matchStart + 64
				if previewEnd > dataLen {
					previewEnd = dataLen
				}
				preview := extractStringPreview(data[previewStart:previewEnd], 64)
				local = append(local, SearchMatch{
					Index:       idx,
					PC:          pcText,
					InstrText:   instrText,
					ChunkBase:   fmt.Sprintf("0x%x", matchAddr),
					MatchOff:    matchStart,
					ChunkType:   chunkType,
					PatternLen:  len(job.pattern),
					DataPreview: preview,
				})
			}
			off += pos + len(job.pattern)
		}
	}
	return local
}

// ==================== 指令搜索 ====================

var (
	instrSearch   *InstrSearchJob
	instrSearchMu sync.Mutex
)

type InstrSearchMatch struct {
	Index int    `json:"index"`
	PC    string `json:"pc"`
	Instr string `json:"instrText"`
	Regs  string `json:"regText"`
	Depth int    `json:"depth"`
}

type InstrSearchJob struct {
	id      string
	keyword string

	mu      sync.Mutex
	matches []InstrSearchMatch

	scanned atomic.Int64
	done    atomic.Bool
	cancel  context.CancelFunc
}

func handleSearchInstr(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var req struct {
			Keyword string `json:"keyword"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Keyword == "" {
			http.Error(w, "bad request", 400)
			return
		}

		instrSearchMu.Lock()
		if instrSearch != nil && instrSearch.cancel != nil {
			instrSearch.cancel()
		}
		ctx, cancel := context.WithCancel(context.Background())
		job := &InstrSearchJob{
			id:      fmt.Sprintf("%d", time.Now().UnixNano()),
			keyword: strings.ToLower(req.Keyword),
			cancel:  cancel,
		}
		instrSearch = job
		instrSearchMu.Unlock()

		go runInstrSearch(ctx, job)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"searchId": job.id})
		return
	}

	// GET — 获取结果
	instrSearchMu.Lock()
	job := instrSearch
	instrSearchMu.Unlock()

	if job == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"matches": []interface{}{}, "done": true, "scanned": 0, "totalMatches": 0, "totalRecords": 0,
		})
		return
	}

	off, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"matches":      slice,
		"done":         job.done.Load(),
		"scanned":      job.scanned.Load(),
		"totalMatches": total,
		"totalRecords": db.totalRecs.Load(),
	})
}

func runInstrSearch(ctx context.Context, job *InstrSearchJob) {
	defer job.done.Store(true)

	for db.totalRecs.Load() == 0 {
		time.Sleep(100 * time.Millisecond)
	}

	db.anchorMu.RLock()
	anchors := make([]BlockAnchor, len(db.anchors))
	copy(anchors, db.anchors)
	db.anchorMu.RUnlock()

	totalRecs := int(db.totalRecs.Load())

	type segment struct {
		startIdx int
		endIdx   int
		offset   int64
	}

	workers := runtime.NumCPU()
	if workers > len(anchors) {
		workers = len(anchors)
	}
	if workers < 1 {
		workers = 1
	}

	segments := make([]segment, 0, workers)
	recsPerWorker := (totalRecs + workers - 1) / workers
	for i := 0; i < workers; i++ {
		startRec := i * recsPerWorker
		endRec := (i + 1) * recsPerWorker
		if endRec > totalRecs {
			endRec = totalRecs
		}
		if startRec >= totalRecs {
			break
		}
		anchorIdx := sort.Search(len(anchors), func(j int) bool { return anchors[j].RecordIdx > startRec }) - 1
		if anchorIdx < 0 {
			anchorIdx = 0
		}
		seg := segment{
			startIdx: anchors[anchorIdx].RecordIdx,
			endIdx:   endRec,
			offset:   anchors[anchorIdx].Offset,
		}
		if len(segments) > 0 && seg.startIdx <= segments[len(segments)-1].startIdx {
			continue
		}
		segments = append(segments, seg)
	}
	for i := 0; i < len(segments)-1; i++ {
		segments[i].endIdx = segments[i+1].startIdx
	}
	if len(segments) > 0 {
		segments[len(segments)-1].endIdx = totalRecs
	}

	log.Printf("指令搜索: 启动 %d 个并行 worker, 总记录 %d", len(segments), totalRecs)

	localResults := make([][]InstrSearchMatch, len(segments))
	var wg sync.WaitGroup
	for i, seg := range segments {
		wg.Add(1)
		go func(i int, seg segment) {
			defer wg.Done()
			localResults[i] = runInstrSearchSegment(ctx, job, seg.offset, seg.startIdx, seg.endIdx)
		}(i, seg)
	}
	wg.Wait()

	job.mu.Lock()
	for _, local := range localResults {
		job.matches = append(job.matches, local...)
	}
	job.mu.Unlock()
}

func runInstrSearchSegment(ctx context.Context, job *InstrSearchJob, fileOffset int64, startIdx, endIdx int) []InstrSearchMatch {
	var local []InstrSearchMatch
	f, err := os.Open(db.path)
	if err != nil {
		return local
	}
	defer f.Close()

	if _, err := f.Seek(fileOffset, 0); err != nil {
		return local
	}

	br := bufio.NewReaderSize(f, 8*1024*1024)
	hdr := make([]byte, 18)
	idx := startIdx
	instrBuf := make([]byte, 0, 256)
	regBuf := make([]byte, 0, 512)

	for idx < endIdx {
		select {
		case <-ctx.Done():
			return local
		default:
		}

		if _, err := io.ReadFull(br, hdr); err != nil {
			return local
		}
		if string(hdr[:4]) != "UTRA" {
			return local
		}

		// hdr[8:16] = pc, hdr[16:18] = pcTextLen
		pc := binary.LittleEndian.Uint64(hdr[8:16])
		pcTextLen := int(binary.LittleEndian.Uint16(hdr[16:18]))
		pcTextBuf := make([]byte, pcTextLen)
		if _, err := io.ReadFull(br, pcTextBuf); err != nil {
			return local
		}
		pcText := fmt.Sprintf("(0x%x)%s", pc, string(pcTextBuf))

		var instrLen16 uint16
		if err := binary.Read(br, binary.LittleEndian, &instrLen16); err != nil {
			return local
		}
		instrLen := int(instrLen16)

		if cap(instrBuf) < instrLen {
			instrBuf = make([]byte, instrLen, instrLen*2)
		} else {
			instrBuf = instrBuf[:instrLen]
		}
		if _, err := io.ReadFull(br, instrBuf); err != nil {
			return local
		}

		var regLen uint16
		if err := binary.Read(br, binary.LittleEndian, &regLen); err != nil {
			return local
		}
		if cap(regBuf) < int(regLen) {
			regBuf = make([]byte, regLen, int(regLen)*2)
		} else {
			regBuf = regBuf[:regLen]
		}
		if _, err := io.ReadFull(br, regBuf); err != nil {
			return local
		}

		// 跳 chunks
		skipChunkGroupBufio(br)
		skipChunkGroupBufio(br)

		instrText := string(instrBuf)
		regText := string(regBuf)

		haystack := strings.ToLower(instrText + " " + pcText + " " + regText)
		if strings.Contains(haystack, job.keyword) {
			depth := 0
			db.depthMu.RLock()
			if idx < len(db.depths) {
				depth = int(db.depths[idx])
			}
			db.depthMu.RUnlock()

			local = append(local, InstrSearchMatch{
				Index: idx, PC: pcText, Instr: instrText, Regs: regText, Depth: depth,
			})
		}

		idx++
		job.scanned.Add(1)

		if len(local) >= SEARCH_MATCH_LIMIT {
			return local
		}
	}
	return local
}

func skipChunkGroupBufio(br *bufio.Reader) {
	var cnt uint32
	if err := binary.Read(br, binary.LittleEndian, &cnt); err != nil {
		return
	}
	hdr := make([]byte, 12)
	for i := uint32(0); i < cnt; i++ {
		if _, err := io.ReadFull(br, hdr); err != nil {
			return
		}
		dataLen := int64(binary.LittleEndian.Uint32(hdr[8:12]))
		io.CopyN(io.Discard, br, dataLen)
	}
}

// ==================== Watchpoint ====================

// extractStringPreview 从字节数据中提取可打印字符串预览（最多 maxLen 字节）
func extractStringPreview(data []byte, maxLen int) string {
	if len(data) == 0 {
		return ""
	}
	if len(data) > maxLen {
		data = data[:maxLen]
	}
	var sb strings.Builder
	for _, b := range data {
		if b >= 32 && b < 127 {
			sb.WriteByte(b)
		} else if b == 0 {
			if sb.Len() > 0 {
				break // null terminator
			}
		} else {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}

var (
	wpJob   *WatchpointJob
	wpJobMu sync.Mutex
)

type WatchpointMatch struct {
	Index       int    `json:"index"`
	PC          string `json:"pc"`
	InstrText   string `json:"instrText"`
	ChunkBase   string `json:"chunkBase"`
	ChunkType   string `json:"type"`
	DataPreview string `json:"dataPreview"`
}

type WatchpointJob struct {
	id      string
	addr    uint64
	size    uint64
	mu      sync.Mutex
	matches []WatchpointMatch
	scanned atomic.Int64
	done    atomic.Bool
	cancel  context.CancelFunc
}

func handleWatchpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		Addr string `json:"addr"`
		Size int    `json:"size"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	addr, err := strconv.ParseUint(strings.TrimPrefix(req.Addr, "0x"), 16, 64)
	if err != nil || req.Size <= 0 {
		http.Error(w, "invalid params", 400)
		return
	}

	wpJobMu.Lock()
	if wpJob != nil && wpJob.cancel != nil {
		wpJob.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	job := &WatchpointJob{
		id: fmt.Sprintf("%d", time.Now().UnixNano()), addr: addr, size: uint64(req.Size), cancel: cancel,
	}
	wpJob = job
	wpJobMu.Unlock()

	go runWatchpoint(ctx, job)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"searchId": job.id})
}

func handleWatchpointResults(w http.ResponseWriter, r *http.Request) {
	wpJobMu.Lock()
	job := wpJob
	wpJobMu.Unlock()
	if job == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"matches": []interface{}{}, "done": true, "scanned": 0, "totalMatches": 0, "totalRecords": 0,
		})
		return
	}
	off, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
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
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"matches": slice, "done": job.done.Load(), "scanned": job.scanned.Load(),
		"totalMatches": total, "totalRecords": db.totalRecs.Load(),
	})
}

func runWatchpoint(ctx context.Context, job *WatchpointJob) {
	defer job.done.Store(true)

	for db.totalRecs.Load() == 0 {
		time.Sleep(100 * time.Millisecond)
	}

	db.anchorMu.RLock()
	anchors := make([]BlockAnchor, len(db.anchors))
	copy(anchors, db.anchors)
	db.anchorMu.RUnlock()

	totalRecs := int(db.totalRecs.Load())

	type segment struct {
		startIdx int
		endIdx   int
		offset   int64
	}

	workers := runtime.NumCPU()
	if workers > len(anchors) {
		workers = len(anchors)
	}
	if workers < 1 {
		workers = 1
	}

	segments := make([]segment, 0, workers)
	recsPerWorker := (totalRecs + workers - 1) / workers
	for i := 0; i < workers; i++ {
		startRec := i * recsPerWorker
		endRec := (i + 1) * recsPerWorker
		if endRec > totalRecs {
			endRec = totalRecs
		}
		if startRec >= totalRecs {
			break
		}
		anchorIdx := sort.Search(len(anchors), func(j int) bool { return anchors[j].RecordIdx > startRec }) - 1
		if anchorIdx < 0 {
			anchorIdx = 0
		}
		seg := segment{
			startIdx: anchors[anchorIdx].RecordIdx,
			endIdx:   endRec,
			offset:   anchors[anchorIdx].Offset,
		}
		if len(segments) > 0 && seg.startIdx <= segments[len(segments)-1].startIdx {
			continue
		}
		segments = append(segments, seg)
	}
	for i := 0; i < len(segments)-1; i++ {
		segments[i].endIdx = segments[i+1].startIdx
	}
	if len(segments) > 0 {
		segments[len(segments)-1].endIdx = totalRecs
	}

	log.Printf("Watchpoint: 启动 %d 个并行 worker, 总记录 %d", len(segments), totalRecs)

	localResults := make([][]WatchpointMatch, len(segments))
	var wg sync.WaitGroup
	for i, seg := range segments {
		wg.Add(1)
		go func(i int, seg segment) {
			defer wg.Done()
			localResults[i] = runWatchpointSegment(ctx, job, seg.offset, seg.startIdx, seg.endIdx)
		}(i, seg)
	}
	wg.Wait()

	job.mu.Lock()
	for _, local := range localResults {
		job.matches = append(job.matches, local...)
	}
	job.mu.Unlock()
}

func runWatchpointSegment(ctx context.Context, job *WatchpointJob, fileOffset int64, startIdx, endIdx int) []WatchpointMatch {
	var local []WatchpointMatch
	f, err := os.Open(db.path)
	if err != nil {
		return local
	}
	defer f.Close()
	if _, err := f.Seek(fileOffset, 0); err != nil {
		return local
	}
	br := bufio.NewReaderSize(f, 8*1024*1024)
	hdr := make([]byte, 18)
	idx := startIdx
	wLo, wHi := job.addr, job.addr+job.size

	for idx < endIdx {
		select {
		case <-ctx.Done():
			return local
		default:
		}
		if _, err := io.ReadFull(br, hdr); err != nil {
			return local
		}
		if string(hdr[:4]) != "UTRA" {
			return local
		}
		pc := binary.LittleEndian.Uint64(hdr[8:16])
		pcTextLen := int(binary.LittleEndian.Uint16(hdr[16:18]))
		pcTextBuf := make([]byte, pcTextLen)
		if _, err := io.ReadFull(br, pcTextBuf); err != nil {
			return local
		}
		pcText := fmt.Sprintf("(0x%x)%s", pc, string(pcTextBuf))
		var instrLen16 uint16
		binary.Read(br, binary.LittleEndian, &instrLen16)
		instrLen := int(instrLen16)
		instrBuf := make([]byte, instrLen)
		io.ReadFull(br, instrBuf)
		var regLen uint16
		binary.Read(br, binary.LittleEndian, &regLen)
		io.CopyN(io.Discard, br, int64(regLen))

		local = wpCheckChunks(br, job, idx, pcText, string(instrBuf), "read", wLo, wHi, local)
		local = wpCheckChunks(br, job, idx, pcText, string(instrBuf), "write", wLo, wHi, local)

		idx++
		job.scanned.Add(1)
		if len(local) >= SEARCH_MATCH_LIMIT {
			return local
		}
	}
	return local
}

func wpCheckChunks(br *bufio.Reader, job *WatchpointJob, idx int, pcText string, instrText, chunkType string, wLo, wHi uint64, local []WatchpointMatch) []WatchpointMatch {
	var cnt uint32
	binary.Read(br, binary.LittleEndian, &cnt)
	hdr := make([]byte, 12)
	for i := uint32(0); i < cnt; i++ {
		io.ReadFull(br, hdr)
		base := binary.LittleEndian.Uint64(hdr[:8])
		dataLen := int(binary.LittleEndian.Uint32(hdr[8:12]))

		// 实际访问区域：固定窗口 = 前128 + 后128，实际操作从 offset 128 开始
		const windowSize = 256
		accessSize := dataLen - windowSize
		if accessSize < 1 {
			accessSize = 1
		}
		centerLoOff := windowSize / 2
		centerHiOff := centerLoOff + accessSize
		if centerHiOff > dataLen {
			centerHiOff = dataLen
		}
		// 实际访问的绝对地址范围
		accessLo := base + uint64(centerLoOff)
		accessHi := base + uint64(centerHiOff)

		if accessLo < wHi && accessHi > wLo {
			// 命中：读取数据提取 string 预览
			data := make([]byte, dataLen)
			io.ReadFull(br, data)
			// 提取监控范围内的字节
			previewStart := 0
			previewEnd := dataLen
			if wLo > base {
				previewStart = int(wLo - base)
			}
			if wHi < base+uint64(dataLen) {
				previewEnd = int(wHi - base)
			}
			if previewStart < 0 {
				previewStart = 0
			}
			if previewEnd > dataLen {
				previewEnd = dataLen
			}
			preview := extractStringPreview(data[previewStart:previewEnd], 64)
			local = append(local, WatchpointMatch{
				Index: idx, PC: pcText, InstrText: instrText,
				ChunkBase: fmt.Sprintf("0x%x", base), ChunkType: chunkType,
				DataPreview: preview,
			})
		} else {
			io.CopyN(io.Discard, br, int64(dataLen))
		}
	}
	return local
}

// ==================== 寄存器追踪 ====================

var (
	regJob   *RegTraceJob
	regJobMu sync.Mutex
)

type RegTraceMatch struct {
	Index int    `json:"index"`
	PC    string `json:"pc"`
	Instr string `json:"instrText"`
	Value string `json:"value"`
}

type RegTraceJob struct {
	id      string
	reg     string
	from    int
	to      int
	mu      sync.Mutex
	matches []RegTraceMatch
	scanned atomic.Int64
	done    atomic.Bool
	cancel  context.CancelFunc
}

func handleSearchReg(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	var req struct {
		Reg  string `json:"reg"`
		From int    `json:"from"`
		To   int    `json:"to"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Reg == "" {
		http.Error(w, "bad request", 400)
		return
	}

	regJobMu.Lock()
	if regJob != nil && regJob.cancel != nil {
		regJob.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	job := &RegTraceJob{
		id: fmt.Sprintf("%d", time.Now().UnixNano()), reg: strings.ToLower(req.Reg), cancel: cancel,
		from: req.From, to: req.To,
	}
	regJob = job
	regJobMu.Unlock()

	go runRegTrace(ctx, job)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"searchId": job.id})
}

func handleSearchRegResults(w http.ResponseWriter, r *http.Request) {
	regJobMu.Lock()
	job := regJob
	regJobMu.Unlock()
	if job == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"matches": []interface{}{}, "done": true, "scanned": 0, "totalMatches": 0, "totalRecords": 0,
		})
		return
	}
	off, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 10000 {
		limit = 200
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
	w.Header().Set("Content-Type", "application/json")
	totalRecs := db.totalRecs.Load()
	if job.to > 0 && job.from >= 0 {
		totalRecs = int64(job.to - job.from)
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"matches": slice, "done": job.done.Load(), "scanned": job.scanned.Load(),
		"totalMatches": total, "totalRecords": totalRecs,
	})
}

func runRegTrace(ctx context.Context, job *RegTraceJob) {
	defer job.done.Store(true)
	f, err := os.Open(db.path)
	if err != nil {
		return
	}
	defer f.Close()

	// 如果指定了 from，用锚点跳过前面的记录
	startIdx := 0
	if job.from > 0 {
		startIdx = job.from
		seekOff := db.seekToRecord(startIdx)
		if seekOff < 0 {
			log.Printf("寄存器追踪: seekToRecord(%d) 失败", startIdx)
			return
		}
		log.Printf("寄存器追踪: from=%d, seekOff=%d", startIdx, seekOff)
		if _, err := f.Seek(seekOff, 0); err != nil {
			log.Printf("寄存器追踪: Seek 失败: %v", err)
			return
		}
	}

	br := bufio.NewReaderSize(f, 4*1024*1024)
	magic := make([]byte, 4)
	idx := startIdx
	endIdx := job.to
	if endIdx <= 0 {
		endIdx = int(db.totalRecs.Load())
	}
	regPrefix := job.reg + "="
	totalRange := endIdx - startIdx
	if totalRange <= 0 {
		totalRange = int(db.totalRecs.Load())
	}

	for {
		// 如果指定了 to 且已超过范围，结束
		if endIdx > 0 && idx > endIdx {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		if _, err := io.ReadFull(br, magic); err != nil {
			return
		}
		if string(magic) != "UTRA" {
			return
		}
		// read threadId(4) + pc(8), then pcText
		tidPcBuf := make([]byte, 12)
		io.ReadFull(br, tidPcBuf)
		pc := binary.LittleEndian.Uint64(tidPcBuf[4:12])
		var pcTextLen uint16
		binary.Read(br, binary.LittleEndian, &pcTextLen)
		pcTextBuf := make([]byte, pcTextLen)
		io.ReadFull(br, pcTextBuf)
		pcText := fmt.Sprintf("(0x%x)%s", pc, string(pcTextBuf))
		var instrLen uint16
		binary.Read(br, binary.LittleEndian, &instrLen)
		instrBuf := make([]byte, instrLen)
		io.ReadFull(br, instrBuf)
		var regLen uint16
		binary.Read(br, binary.LittleEndian, &regLen)
		regBuf := make([]byte, regLen)
		io.ReadFull(br, regBuf)

		skipChunkGroupBufio(br)
		skipChunkGroupBufio(br)

		regText := strings.ToLower(string(regBuf))
		arrowIdx := strings.Index(regText, "=>")
		if arrowIdx >= 0 {
			writeRegs := regText[arrowIdx+2:]
			if valIdx := strings.Index(writeRegs, regPrefix); valIdx >= 0 {
				valStart := valIdx + len(regPrefix)
				valEnd := valStart
				for valEnd < len(writeRegs) && writeRegs[valEnd] != ' ' {
					valEnd++
				}
				value := writeRegs[valStart:valEnd]
				job.mu.Lock()
				job.matches = append(job.matches, RegTraceMatch{
					Index: idx, PC: pcText,
					Instr: string(instrBuf), Value: value,
				})
				job.mu.Unlock()
			}
		}

		idx++
		job.scanned.Store(int64(idx) - int64(startIdx))
		job.mu.Lock()
		n := len(job.matches)
		job.mu.Unlock()
		if n >= SEARCH_MATCH_LIMIT {
			return
		}
	}
}

// ==================== 函数摘要 ====================

type FuncInfo struct {
	TargetPC   string `json:"targetPC"`
	CallCount  int    `json:"callCount"`
	FirstCall  int    `json:"firstCall"`
	TotalInstr int    `json:"totalInstr"`
}

func handleFunctions(w http.ResponseWriter, r *http.Request) {
	if !db.indexDone.Load() {
		http.Error(w, "索引未完成", 503)
		return
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"functions": funcs,
		"total":     len(funcs),
	})
}

// ==================== 函数调用时间线 ====================

func handleCallTimeline(w http.ResponseWriter, r *http.Request) {
	if !db.indexDone.Load() {
		http.Error(w, "索引未完成", 503)
		return
	}

	// 首次请求时构建缓存
	if !db.callFlowBuilt.Load() {
		buildCallFlowLines()
	}

	// 分页参数
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}

	total := len(db.callFlowLines)
	end := offset + limit
	if end > total {
		end = total
	}

	var slice []CallFlowLine
	if offset < total {
		slice = db.callFlowLines[offset:end]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"lines": slice,
		"total": total,
	})
}

func buildCallFlowLines() {
	db.funcEventsMu.RLock()
	events := db.funcEvents
	db.funcEventsMu.RUnlock()

	total := int(db.totalRecs.Load())

	type StackEntry struct {
		index int
		pc    uint64
		depth int16
	}
	stack := make([]StackEntry, 0, 256)
	lines := make([]CallFlowLine, 0, len(events)*2+1)

	// 根函数
	firstPC := uint64(0)
	fileOff := db.seekToRecord(0)
	if fileOff >= 0 {
		f := db.getFile()
		if f != nil {
			info, err := readInstrAt(f, fileOff)
			if err == nil {
				firstPC = info.PC
			}
			db.putFile(f)
		}
	}
	lines = append(lines, CallFlowLine{
		Type: "call", PC: fmt.Sprintf("0x%x", firstPC), Depth: 0, From: 0, To: total,
	})

	for _, ev := range events {
		if ev.Type == 'C' {
			stack = append(stack, StackEntry{index: ev.Index, pc: ev.PC, depth: ev.Depth})
			lines = append(lines, CallFlowLine{
				Type: "call", PC: fmt.Sprintf("0x%x", ev.PC), Depth: int(ev.Depth), From: ev.Index, To: 0,
			})
		} else if ev.Type == 'R' {
			if len(stack) > 0 {
				top := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				// call 行补上 To
				// ret 行的 idx 指向返回后的下一条指令
				lines = append(lines, CallFlowLine{
					Type: "ret", PC: fmt.Sprintf("0x%x", top.pc), Depth: int(top.depth), From: top.index, To: ev.Index,
				})
			}
		}
	}
	// 栈里剩余的
	for i := len(stack) - 1; i >= 0; i-- {
		s := stack[i]
		lines = append(lines, CallFlowLine{
			Type: "ret", PC: fmt.Sprintf("0x%x", s.pc), Depth: int(s.depth), From: s.index, To: total,
		})
	}

	db.callFlowLines = lines
	db.callFlowBuilt.Store(true)
	log.Printf("调用流程缓存已构建，共 %d 行", len(lines))
}

// ==================== 会话持久化 ====================

var sessionPath string
var sessionMu sync.Mutex

func handleSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case "GET":
		sessionMu.Lock()
		data, err := os.ReadFile(sessionPath)
		sessionMu.Unlock()
		if err != nil {
			w.Write([]byte("{}"))
			return
		}
		w.Write(data)
	case "POST":
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body failed", 400)
			return
		}
		// 校验是合法 JSON
		var check json.RawMessage
		if json.Unmarshal(body, &check) != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		sessionMu.Lock()
		err = os.WriteFile(sessionPath, body, 0644)
		sessionMu.Unlock()
		if err != nil {
			http.Error(w, "write failed", 500)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func handleFrontend(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(frontendHTML)
}
