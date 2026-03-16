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
//   magic(4) pc(8) instrLen(2) instr regLen(2) reg
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

	// 函数摘要
	funcMap map[uint64]*FuncEntry
	funcMu  sync.RWMutex

	pool sync.Pool
}

type FuncEntry struct {
	CallCount   int
	FirstCall   int
	TotalInstr  int
	lastCallIdx int
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
	Index      int    `json:"index"`
	PC         string `json:"pc"`
	InstrText  string `json:"instrText"`
	ChunkBase  string `json:"chunkBase"`
	MatchOff   int    `json:"matchOffset"`
	ChunkType  string `json:"type"` // "read" or "write"
	PatternLen int    `json:"patternLen"`
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
	http.HandleFunc("/", handleFrontend)

	addr := ":8080"
	log.Printf("服务已启动: http://localhost%s", addr)
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

		// 读 pc(8)
		var pc uint64
		pcBuf := make([]byte, 8)
		if _, err := io.ReadFull(br, pcBuf); err != nil {
			break
		}
		pc = binary.LittleEndian.Uint64(pcBuf)
		offset += 8

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

		if isCall {
			// bl 的返回地址 = pc + 4
			retStack = append(retStack, pc+4)
			callDepth++
			pendingCallIdx = count
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

	log.Printf("索引完成: %d 条, %d 个锚点, 耗时 %v", count, len(db.anchors), time.Since(t0))
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
	buf := make([]byte, 16)
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

// skipRecordFile 跳过一条完整记录（新格式：读chunks + 写chunks）
func skipRecordFile(f *os.File, offset int64, buf []byte) int64 {
	if _, err := f.ReadAt(buf[:14], offset); err != nil {
		return offset
	}
	p := offset + 4 + 8
	instrLen := int64(binary.LittleEndian.Uint16(buf[12:14]))
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
	PC         uint64
	InstrText  string
	RegText    string
	NextOffset int64
}

func readInstrAt(f *os.File, offset int64) (*InstrInfo, error) {
	hdr := make([]byte, 14)
	if _, err := f.ReadAt(hdr, offset); err != nil {
		return nil, err
	}
	if string(hdr[:4]) != "UTRA" {
		return nil, fmt.Errorf("invalid magic")
	}
	pc := binary.LittleEndian.Uint64(hdr[4:12])
	instrLen := int(binary.LittleEndian.Uint16(hdr[12:14]))
	p := offset + 14

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

	// 跳过 readChunks + writeChunks 算 nextOffset
	buf := make([]byte, 16)
	p = skipChunkGroupFile(f, p, buf)
	if p < 0 {
		return nil, fmt.Errorf("skip read chunks failed")
	}
	p = skipChunkGroupFile(f, p, buf)
	if p < 0 {
		return nil, fmt.Errorf("skip write chunks failed")
	}

	return &InstrInfo{
		PC: pc, InstrText: string(instrBuf), RegText: string(regBuf), NextOffset: p,
	}, nil
}

type MemChunk struct {
	Base uint64
	Data []byte
}

// readChunksFromFile 读取一条记录的 readChunks + writeChunks
func readChunksFromFile(f *os.File, offset int64) (readChunks, writeChunks []MemChunk, err error) {
	hdr := make([]byte, 14)
	if _, err = f.ReadAt(hdr, offset); err != nil {
		return
	}
	instrLen := int64(binary.LittleEndian.Uint16(hdr[12:14]))
	p := offset + 14 + instrLen

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
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"totalRecords": db.totalRecs.Load(),
		"indexDone":    db.indexDone.Load(),
	})
}

func handleInstructions(w http.ResponseWriter, r *http.Request) {
	off, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if off < 0 {
		off = 0
	}

	total := int(db.totalRecs.Load())
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
		Index int    `json:"index"`
		PC    string `json:"pc"`
		Instr string `json:"instrText"`
		Regs  string `json:"regText"`
		Depth int    `json:"depth"`
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
			Index: i,
			PC:    fmt.Sprintf("0x%x", info.PC),
			Instr: info.InstrText,
			Regs:  info.RegText,
			Depth: depth,
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

	f, err := os.Open(db.path)
	if err != nil {
		log.Printf("搜索: 打开文件失败: %v", err)
		return
	}
	defer f.Close()

	br := bufio.NewReaderSize(f, 4*1024*1024)
	magic := make([]byte, 4)
	idx := 0

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// 读 magic
		if _, err := io.ReadFull(br, magic); err != nil {
			return
		}
		if string(magic) != "UTRA" {
			return
		}

		// 读 pc
		var pc uint64
		if err := binary.Read(br, binary.LittleEndian, &pc); err != nil {
			return
		}

		// 读 instrText
		var instrLen uint16
		if err := binary.Read(br, binary.LittleEndian, &instrLen); err != nil {
			return
		}
		instrBuf := make([]byte, instrLen)
		if _, err := io.ReadFull(br, instrBuf); err != nil {
			return
		}

		// 跳 regText
		var regLen uint16
		if err := binary.Read(br, binary.LittleEndian, &regLen); err != nil {
			return
		}
		if _, err := io.CopyN(io.Discard, br, int64(regLen)); err != nil {
			return
		}

		// 读 readChunks 并搜索
		searchChunkGroup(br, job, idx, pc, string(instrBuf), "read")
		// 读 writeChunks 并搜索
		searchChunkGroup(br, job, idx, pc, string(instrBuf), "write")

		idx++
		job.scanned.Store(int64(idx))

		// 匹配数上限
		job.mu.Lock()
		n := len(job.matches)
		job.mu.Unlock()
		if n >= 50000 {
			return
		}
	}
}

func searchChunkGroup(br *bufio.Reader, job *SearchJob, idx int, pc uint64, instrText string, chunkType string) {
	var cnt uint32
	if err := binary.Read(br, binary.LittleEndian, &cnt); err != nil {
		return
	}
	hdr := make([]byte, 12)
	for i := uint32(0); i < cnt; i++ {
		if _, err := io.ReadFull(br, hdr); err != nil {
			return
		}
		base := binary.LittleEndian.Uint64(hdr[:8])
		dataLen := int(binary.LittleEndian.Uint32(hdr[8:12]))
		data := make([]byte, dataLen)
		if _, err := io.ReadFull(br, data); err != nil {
			return
		}

		// 搜索所有匹配位置
		off := 0
		for {
			pos := bytes.Index(data[off:], job.pattern)
			if pos < 0 {
				break
			}
			matchAddr := base + uint64(off+pos)
			job.mu.Lock()
			job.matches = append(job.matches, SearchMatch{
				Index:      idx,
				PC:         fmt.Sprintf("0x%x", pc),
				InstrText:  instrText,
				ChunkBase:  fmt.Sprintf("0x%x", matchAddr),
				MatchOff:   off + pos,
				ChunkType:  chunkType,
				PatternLen: len(job.pattern),
			})
			job.mu.Unlock()
			off += pos + len(job.pattern)
		}
	}
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

	f, err := os.Open(db.path)
	if err != nil {
		return
	}
	defer f.Close()

	br := bufio.NewReaderSize(f, 4*1024*1024)
	magic := make([]byte, 4)
	idx := 0

	for {
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

		var pc uint64
		if err := binary.Read(br, binary.LittleEndian, &pc); err != nil {
			return
		}

		var instrLen uint16
		if err := binary.Read(br, binary.LittleEndian, &instrLen); err != nil {
			return
		}
		instrBuf := make([]byte, instrLen)
		if _, err := io.ReadFull(br, instrBuf); err != nil {
			return
		}

		var regLen uint16
		if err := binary.Read(br, binary.LittleEndian, &regLen); err != nil {
			return
		}
		regBuf := make([]byte, regLen)
		if _, err := io.ReadFull(br, regBuf); err != nil {
			return
		}

		// 跳 chunks
		skipChunkGroupBufio(br)
		skipChunkGroupBufio(br)

		instrText := string(instrBuf)
		regText := string(regBuf)
		pcStr := fmt.Sprintf("0x%x", pc)

		// 搜索：指令文本、PC、寄存器文本
		haystack := strings.ToLower(instrText + " " + pcStr + " " + regText)
		if strings.Contains(haystack, job.keyword) {
			depth := 0
			db.depthMu.RLock()
			if idx < len(db.depths) {
				depth = int(db.depths[idx])
			}
			db.depthMu.RUnlock()

			job.mu.Lock()
			job.matches = append(job.matches, InstrSearchMatch{
				Index: idx, PC: pcStr, Instr: instrText, Regs: regText, Depth: depth,
			})
			job.mu.Unlock()
		}

		idx++
		job.scanned.Store(int64(idx))

		job.mu.Lock()
		n := len(job.matches)
		job.mu.Unlock()
		if n >= 50000 {
			return
		}
	}
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

var (
	wpJob   *WatchpointJob
	wpJobMu sync.Mutex
)

type WatchpointMatch struct {
	Index     int    `json:"index"`
	PC        string `json:"pc"`
	InstrText string `json:"instrText"`
	ChunkBase string `json:"chunkBase"`
	ChunkType string `json:"type"`
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
	f, err := os.Open(db.path)
	if err != nil {
		return
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 4*1024*1024)
	magic := make([]byte, 4)
	idx := 0
	wLo, wHi := job.addr, job.addr+job.size

	for {
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
		var pc uint64
		binary.Read(br, binary.LittleEndian, &pc)
		var instrLen uint16
		binary.Read(br, binary.LittleEndian, &instrLen)
		instrBuf := make([]byte, instrLen)
		io.ReadFull(br, instrBuf)
		var regLen uint16
		binary.Read(br, binary.LittleEndian, &regLen)
		io.CopyN(io.Discard, br, int64(regLen))

		// 检查 read chunks
		wpCheckChunks(br, job, idx, pc, string(instrBuf), "read", wLo, wHi)
		wpCheckChunks(br, job, idx, pc, string(instrBuf), "write", wLo, wHi)

		idx++
		job.scanned.Store(int64(idx))
		job.mu.Lock()
		n := len(job.matches)
		job.mu.Unlock()
		if n >= 50000 {
			return
		}
	}
}

func wpCheckChunks(br *bufio.Reader, job *WatchpointJob, idx int, pc uint64, instrText, chunkType string, wLo, wHi uint64) {
	var cnt uint32
	binary.Read(br, binary.LittleEndian, &cnt)
	hdr := make([]byte, 12)
	for i := uint32(0); i < cnt; i++ {
		io.ReadFull(br, hdr)
		base := binary.LittleEndian.Uint64(hdr[:8])
		dataLen := int(binary.LittleEndian.Uint32(hdr[8:12]))
		io.CopyN(io.Discard, br, int64(dataLen))
		cLo, cHi := base, base+uint64(dataLen)
		if cLo < wHi && cHi > wLo {
			job.mu.Lock()
			job.matches = append(job.matches, WatchpointMatch{
				Index: idx, PC: fmt.Sprintf("0x%x", pc), InstrText: instrText,
				ChunkBase: fmt.Sprintf("0x%x", base), ChunkType: chunkType,
			})
			job.mu.Unlock()
		}
	}
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
		var pc uint64
		binary.Read(br, binary.LittleEndian, &pc)
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
					Index: idx, PC: fmt.Sprintf("0x%x", pc),
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
		if n >= 50000 {
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

func handleFrontend(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(frontendHTML)
}
