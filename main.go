package main

import (
	"bufio"
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

	pool sync.Pool
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

	db = &TraceDB{path: binPath, size: fi.Size()}
	db.anchors = append(db.anchors, BlockAnchor{0, 0})

	go db.buildIndexAsync()

	http.HandleFunc("/api/info", handleInfo)
	http.HandleFunc("/api/instructions", handleInstructions)
	http.HandleFunc("/api/memory", handleMemory)
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

	for {
		if _, err := io.ReadFull(br, magic); err != nil {
			break
		}
		if string(magic) != "UTRA" {
			break
		}
		offset += 4

		// 跳 pc(8)
		if _, err := io.CopyN(io.Discard, br, 8); err != nil {
			break
		}
		offset += 8

		// 跳 instrText
		var instrLen uint16
		if err := binary.Read(br, binary.LittleEndian, &instrLen); err != nil {
			break
		}
		offset += 2
		if _, err := io.CopyN(io.Discard, br, int64(instrLen)); err != nil {
			break
		}
		offset += int64(instrLen)

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
	log.Printf("索引完成: %d 条, %d 个锚点, 耗时 %v", count, len(db.anchors), time.Since(t0))
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
	}

	items := make([]Item, 0, end-off)
	for i := off; i < end; i++ {
		info, err := readInstrAt(f, fileOff)
		if err != nil {
			break
		}
		items = append(items, Item{
			Index: i,
			PC:    fmt.Sprintf("0x%x", info.PC),
			Instr: info.InstrText,
			Regs:  info.RegText,
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

func handleFrontend(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(frontendHTML)
}
