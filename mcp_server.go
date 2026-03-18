package main

import (
	"net/http"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// setupMCP creates the MCP server and returns an http.Handler to mount on the main HTTP server.
func setupMCP() http.Handler {
	s := server.NewMCPServer(
		"unidbg-trace",
		"1.0.0",
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, false),
	)

	// ==================== Core Tools ====================

	s.AddTool(mcp.NewTool("trace_info",
		mcp.WithDescription(`获取当前加载的 unidbg trace 文件的基本信息。这是分析的起点，应首先调用。
返回值包括：总指令记录数、索引构建状态、所有线程 ID 列表，以及从第一条记录自动推断的上下文。
因为 unidbg trace 是对某个函数的调用追踪，所以第一条记录就是入口函数，其线程 ID 就是主线程，其 PC 地址中的 SO 名就是被分析的主 SO。

返回字段说明:
- totalRecords: int, trace 中的总指令记录数
- indexDone: bool, 后台索引是否构建完成（false 时 get_functions 等依赖索引的接口不可用）
- threadIds: int[], 所有出现过的线程 ID 列表（去重有序）
- entryContext: object, 从第一条记录推断的入口上下文
  - entryPC: string, 入口函数的绝对 PC 地址，如 "0x4005bc04"
  - entrySymbol: string, 入口函数的符号化地址，如 "libmain.so+0x5bc04"
  - mainThreadId: int, 主线程 ID（第一条记录的线程 ID）
  - mainSo: string, 被分析的主 SO 名称，如 "libmain.so"
  - entryInstr: string, 入口处的第一条 ARM 汇编指令`),
	), handleTraceInfo)

	s.AddTool(mcp.NewTool("get_instructions",
		mcp.WithDescription(`分页获取 trace 中的 ARM 指令列表。支持按线程 ID 过滤。结果按执行顺序（行号升序）排列。

返回字段说明:
- offset: int, 当前偏移
- limit: int, 当前分页大小
- total: int, 总记录数（如果指定了 tid 则为该线程的记录数）
- items: array, 指令列表，每条包含:
  - index: int, 全局行号（trace 中的第 N 条指令，从 0 开始）
  - threadId: int, 该指令所属的线程 ID
  - pc: string, PC 地址，格式为 "(0x绝对地址)SO名+偏移"，如 "(0x4005bc04)libmain.so+0x5bc04"
  - instrText: string, ARM 汇编指令文本，如 "ldr x0, [x1, #0x10]"
  - regText: string, 寄存器状态快照，格式为 "寄存器=值 ... => 被修改的寄存器=新值"，=> 前是输入寄存器，=> 后是该指令写回的寄存器
  - depth: int, 函数调用嵌套深度（0=入口函数层级，每进入一个子函数 +1，返回时 -1）
  - memFlag: string, 内存访问标记，""=无内存访问, "R"=有读, "W"=有写, "RW"=同时有读写`),
		mcp.WithNumber("offset", mcp.Required(), mcp.Description("起始位置（行号偏移），从 0 开始")),
		mcp.WithNumber("limit", mcp.Description("返回条数，默认 100，最大 500")),
		mcp.WithNumber("tid", mcp.Description("线程 ID 过滤，不传则返回所有线程。传入后 offset 是该线程内的偏移")),
	), handleGetInstructions)

	s.AddTool(mcp.NewTool("get_memory",
		mcp.WithDescription(`获取指定行号的指令在执行时的内存读写数据。每个内存区域包含实际访问地址前后各约 128 字节的上下文快照窗口，数据为 hex 编码。
可选传入 highlight 参数来标记关注的地址范围（如搜索命中地址或监控点地址），返回值会额外提取该范围的数据片段。

返回字段说明:
- index: int, 指令行号
- regions: array, 内存区域列表，每个包含:
  - base: string, 该内存窗口的起始地址（hex），注意这是窗口起始，比实际访问地址小约 128 字节
  - size: int, 窗口数据总字节数
  - hex: string, 窗口内所有字节的 hex 编码
  - type: string, "read" 或 "write"，表示该区域是被指令读取还是写入
  - accessRange: object|null, 该窗口中实际被指令访问的字节范围
    - start: string, 实际访问起始地址（hex）
    - size: int, 实际访问字节数
  - highlight: object|null, 仅当传入 highlight_addr 且地址落在该窗口内时返回
    - addr: string, 高亮起始地址（hex）
    - size: int, 高亮字节数
    - offsetInHex: int, 高亮数据在 hex 字符串中的字符偏移（除以 2 得字节偏移）
    - dataHex: string, 从窗口中提取出的高亮范围数据的 hex 编码，可直接读取`),
		mcp.WithNumber("index", mcp.Required(), mcp.Description("指令行号")),
		mcp.WithString("highlight_addr", mcp.Description("需要关注的地址，hex 格式如 0x40001000。搜索内存时可直接传入结果中的 chunkBase")),
		mcp.WithNumber("highlight_size", mcp.Description("关注的字节数，配合 highlight_addr 使用。搜索内存时可传入结果中的 patternLen")),
	), handleGetMemory)

	s.AddTool(mcp.NewTool("get_functions",
		mcp.WithDescription(`获取 trace 中识别出的所有函数摘要。按调用次数降序排列。需要索引构建完成（trace_info 中 indexDone=true）。

返回字段说明:
- total: int, 识别出的不同函数总数
- functions: array, 函数列表，每个包含:
  - targetPC: string, 函数入口的绝对 PC 地址（hex），如 "0x4005c000"
  - callCount: int, 该函数在 trace 中被调用的总次数
  - firstCall: int, 该函数首次被调用时的行号（index）
  - totalInstr: int, 该函数所有调用累计执行的指令总数`),
	), handleGetFunctions)

	// ==================== Search Tools ====================

	s.AddTool(mcp.NewTool("search_memory",
		mcp.WithDescription(`在 trace 所有指令的内存读写数据中搜索指定的 hex 字节序列或字符串。用于追踪特定数据（如密钥、明文、魔数）在哪些指令中出现。
结果按行号升序排列。搜索可能耗时较长（1.3亿条约需40秒），结果可能有成千上万条，请使用分页获取。
提示：结果中的 chunkBase 就是匹配数据的内存地址，可直接传给 get_memory 的 highlight_addr 参数（highlight_size 用 patternLen），即可在内存快照中高亮定位命中数据。

返回字段说明:
- done: bool, 搜索是否完成
- scanned: int, 已扫描的记录数
- totalMatches: int, 总匹配数
- totalRecords: int, trace 总记录数
- matches: array, 匹配列表，每条包含:
  - index: int, 命中指令的全局行号
  - pc: string, 命中指令的 PC 地址（含符号名）
  - instrText: string, 命中指令的 ARM 汇编文本
  - chunkBase: string, 匹配数据所在的内存地址（hex），可直接传给 get_memory 的 highlight_addr
  - matchOffset: int, 匹配位置在该内存 chunk 原始数据中的字节偏移
  - type: string, "read" 或 "write"，表示匹配数据是在读操作还是写操作中发现的
  - patternLen: int, 搜索模式的字节长度，可传给 get_memory 的 highlight_size
  - dataPreview: string, 匹配位置附近的可打印字符串预览（最多 64 字节）`),
		mcp.WithString("pattern", mcp.Required(), mcp.Description("搜索模式。hex 模式如 0a1b2c3d，string 模式如 hello")),
		mcp.WithString("type", mcp.Required(), mcp.Description("hex 或 string")),
		mcp.WithNumber("offset", mcp.Description("结果分页偏移，默认 0")),
		mcp.WithNumber("limit", mcp.Description("结果分页大小，默认 50，最大 200")),
	), handleSearchMemory)

	s.AddTool(mcp.NewTool("search_instructions",
		mcp.WithDescription(`在 trace 所有指令中搜索关键词（大小写不敏感）。服务端将每条指令的 instrText + pcText + regText 拼接为一个字符串，然后判断是否包含关键词。
因此搜索范围覆盖汇编指令、PC地址/符号名、寄存器状态（含 => 后的写回值）。结果按行号升序排列。

警告：请使用尽可能具体、完整的关键词！
- 差: "mov x0" — 会命中成千上万条，浪费 token
- 好: "mov x0, x25 => x0=0x12345678" — 包含寄存器写回值，精准定位
- 好: "libmain.so+0x5bc04" — 搜索特定地址
- 好: "aes" — 搜索特定功能相关指令

返回字段说明:
- done: bool, 搜索是否完成
- scanned: int, 已扫描的记录数
- totalMatches: int, 总匹配数
- totalRecords: int, trace 总记录数
- matches: array, 匹配列表，每条包含:
  - index: int, 命中指令的全局行号
  - pc: string, 命中指令的 PC 地址（含符号名）
  - instrText: string, 命中指令的 ARM 汇编文本
  - regText: string, 命中指令的寄存器状态，格式 "输入寄存器=值 ... => 写回寄存器=新值"
  - depth: int, 函数调用嵌套深度（0=入口函数层级，每进入一个子函数 +1）`),
		mcp.WithString("keyword", mcp.Required(), mcp.Description("搜索关键词，大小写不敏感")),
		mcp.WithNumber("offset", mcp.Description("结果分页偏移，默认 0")),
		mcp.WithNumber("limit", mcp.Description("结果分页大小，默认 50，最大 200")),
	), handleSearchInstructions)

	s.AddTool(mcp.NewTool("set_watchpoint",
		mcp.WithDescription(`设置内存监控点，找出 trace 中所有访问指定地址范围的指令。用于追踪某个内存地址被哪些指令读写。结果按行号升序排列。
提示：拿到结果后，可将设置监控点时的 addr 和 size 传给 get_memory 的 highlight_addr/highlight_size 参数，在内存快照中高亮定位监控范围的数据。

返回字段说明:
- done: bool, 搜索是否完成
- scanned: int, 已扫描的记录数
- totalMatches: int, 总匹配数
- totalRecords: int, trace 总记录数
- matches: array, 匹配列表，每条包含:
  - index: int, 访问该地址的指令的全局行号
  - pc: string, 指令的 PC 地址（含符号名）
  - instrText: string, 指令的 ARM 汇编文本
  - chunkBase: string, 包含监控地址的内存 chunk 起始地址（hex）
  - type: string, "read" 或 "write"，表示该指令是读取还是写入了监控地址
  - dataPreview: string, 监控地址附近的数据预览`),
		mcp.WithString("addr", mcp.Required(), mcp.Description("监控地址，hex 格式如 0x40001000")),
		mcp.WithNumber("size", mcp.Required(), mcp.Description("监控字节数（如 4 表示监控 4 字节）")),
		mcp.WithNumber("offset", mcp.Description("结果分页偏移，默认 0")),
		mcp.WithNumber("limit", mcp.Description("结果分页大小，默认 50，最大 200")),
	), handleSetWatchpoint)

	s.AddTool(mcp.NewTool("watchpoint_traceback",
		mcp.WithDescription(`在当前监控点结果中，从指定行号向上回溯，找到该行之前最近的内存访问记录。结果按行号降序排列（最邻近目标行的排最前）。
必须先调用 set_watchpoint 建立监控点。

典型场景：某条 ldr 指令从地址 X 读取了数据，想知道是谁最后写入了地址 X——先 set_watchpoint 监控地址 X，再用本接口从 ldr 所在行号回溯，过滤仅写入 [W]，第一条结果大概率就是目标 str 指令。

返回字段说明:
- totalMatches: int, 满足条件的匹配总数
- beforeIndex: int, 回溯的目标行号（即传入的 before_index）
- typeFilter: string, 当前过滤类型
- matches: array, 匹配列表（按行号降序，最邻近的在前），每条包含:
  - index: int, 指令的全局行号
  - pc: string, 指令的 PC 地址（含符号名）
  - instrText: string, 指令的 ARM 汇编文本
  - chunkBase: string, 包含监控地址的内存 chunk 起始地址（hex）
  - type: string, "read" 或 "write"
  - dataPreview: string, 数据预览`),
		mcp.WithNumber("before_index", mcp.Required(), mcp.Description("目标行号，只返回行号小于此值的记录")),
		mcp.WithString("type_filter", mcp.Description("过滤类型: write / read / all，默认 write")),
		mcp.WithNumber("offset", mcp.Description("结果分页偏移，默认 0")),
		mcp.WithNumber("limit", mcp.Description("结果分页大小，默认 50，最大 200")),
	), handleWatchpointTraceback)

	s.AddTool(mcp.NewTool("trace_register",
		mcp.WithDescription(`追踪指定寄存器在指定行号范围内每条指令的值变化。用于分析寄存器数据流，如追踪某个参数在函数调用链中的传递过程。
注意：只追踪被指令写回（修改）的寄存器值，即 regText 中 => 后面出现的寄存器。如果某条指令没有修改目标寄存器，则不会出现在结果中。

返回字段说明:
- done: bool, 追踪是否完成
- scanned: int, 已扫描的记录数
- totalMatches: int, 目标寄存器被修改的总次数
- totalRecords: int, 指定范围内的总记录数
- matches: array, 匹配列表（按行号升序），每条包含:
  - index: int, 修改该寄存器的指令的全局行号
  - pc: string, 指令的 PC 地址（含符号名）
  - instrText: string, 指令的 ARM 汇编文本
  - value: string, 该指令执行后寄存器的新值（hex），如 "0x40001000"`),
		mcp.WithString("reg", mcp.Required(), mcp.Description("寄存器名（大小写不敏感），如 x0, sp, lr, w9")),
		mcp.WithNumber("from", mcp.Description("起始行号，默认 0")),
		mcp.WithNumber("to", mcp.Description("结束行号，默认 0 表示到末尾")),
		mcp.WithNumber("offset", mcp.Description("结果分页偏移，默认 0")),
		mcp.WithNumber("limit", mcp.Description("结果分页大小，默认 200，最大 10000")),
	), handleTraceRegister)

	// ==================== Resources ====================

	s.AddResource(mcp.NewResource("trace://info", "Trace 基本信息",
		mcp.WithResourceDescription("trace 文件元信息，包括总记录数、线程列表、入口上下文"),
		mcp.WithMIMEType("application/json"),
	), handleResourceInfo)

	s.AddResource(mcp.NewResource("trace://functions", "函数列表",
		mcp.WithResourceDescription("trace 中识别出的所有函数摘要"),
		mcp.WithMIMEType("application/json"),
	), handleResourceFunctions)

	httpServer := server.NewStreamableHTTPServer(s,
		server.WithStateLess(true),
	)
	return httpServer
}
