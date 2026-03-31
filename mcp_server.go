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
		mcp.WithDescription(`获取当前加载的 unidbg trace 文件的基本信息，这是分析的起点，应首先调用。
返回总指令记录数、索引构建状态、所有线程 ID 列表，以及从第一条记录推断的入口上下文（入口 PC、符号名、主线程 ID、主 SO 名称）。`),
	), handleTraceInfo)

	s.AddTool(mcp.NewTool("get_instructions",
		mcp.WithDescription(`分页获取 trace 中的 ARM 指令列表，支持按线程 ID 过滤。
每条指令包含：全局行号 index、线程 ID、PC 地址（格式 "(0x绝对地址)SO名+偏移"）、汇编文本、寄存器状态（"输入寄存器=值 => 写回寄存器=新值"）、depth（函数调用嵌套深度，0=入口层级，进入子函数+1）、memFlag（""=无内存访问, "R"=读, "W"=写, "RW"=读写）。
支持两种用法：
1. 分页模式：传 offset + limit，从指定位置顺序获取
2. 上下文模式：传 center + context_size，获取指定行号前后各 context_size 行的指令（适合查看某条指令的执行上下文）`),
		mcp.WithNumber("offset", mcp.Description("分页模式：起始位置（行号偏移），从 0 开始")),
		mcp.WithNumber("limit", mcp.Description("分页模式：返回条数，默认 100，最大 500")),
		mcp.WithNumber("center", mcp.Description("上下文模式：目标行号，会返回该行前后各 context_size 行的指令")),
		mcp.WithNumber("context_size", mcp.Description("上下文模式：前后各取多少行，默认 20")),
		mcp.WithNumber("tid", mcp.Description("线程 ID 过滤，不传则返回所有线程")),
	), handleGetInstructions)

	s.AddTool(mcp.NewTool("get_memory",
		mcp.WithDescription(`获取指定行号指令执行时的内存读写数据。返回实际访问地址前后各 32 字节的上下文窗口。
hex 字段以 4 字节为单位分组，格式为 {"0x地址": "8位hex", ...}，方便逐字段阅读。
accessRange 包含实际操作的地址范围及其原始 hex 数据。`),
		mcp.WithNumber("index", mcp.Required(), mcp.Description("指令行号")),
	), handleGetMemory)

	s.AddTool(mcp.NewTool("get_functions",
		mcp.WithDescription(`获取 trace 中识别出的所有函数摘要（入口 PC、调用次数、首次调用行号、累计指令数），按调用次数降序。需要 indexDone=true。`),
	), handleGetFunctions)

	// ==================== Search Tools ====================

	s.AddTool(mcp.NewTool("search_memory",
		mcp.WithDescription(`在 trace 所有指令的内存读写数据中搜索 hex 字节序列或字符串，用于追踪特定数据（密钥、明文、魔数）出现在哪些指令中。
搜索可能耗时较长（1.3亿条约40秒）。结果按 index 降序排列（最新的在前）。
每条结果包含：matchAddr（匹配数据的精确内存地址）、regText（寄存器状态）、dataPreview（可打印字符串预览）、dataHex（匹配字节的原始 hex 编码）。`),
		mcp.WithString("pattern", mcp.Required(), mcp.Description("搜索模式。hex 模式如 0a1b2c3d，string 模式如 hello")),
		mcp.WithString("type", mcp.Required(), mcp.Description("hex 或 string")),
		mcp.WithNumber("offset", mcp.Description("结果分页偏移，默认 0")),
		mcp.WithNumber("limit", mcp.Description("结果分页大小，默认 50，最大 200")),
	), handleSearchMemory)

	s.AddTool(mcp.NewTool("search_instructions",
		mcp.WithDescription(`在 trace 所有指令中搜索关键词（大小写不敏感）。关键词按空格拆分为多个 token，每个 token 独立在 instrText、pcText、regText 三个字段中匹配，任一字段包含该 token 即算命中，所有 token 都命中才返回该条指令。结果按 index 降序排列（最新的在前）。
支持行号跳转：传入 line 参数时，自动定位到包含该行号的结果页并返回，同时返回该行在结果中的位置 foundPosition。
示例：
- "str x0 libmain.so" — str x0 匹配 instrText，libmain.so 匹配 pcText → 命中
- "0x5bc04 => x0=" — 0x5bc04 匹配 pcText，=> x0= 匹配 regText → 命中
- "mov x0" — 单个 token，在 instrText 中匹配 → 命中（但结果可能很多）`),
		mcp.WithString("keyword", mcp.Required(), mcp.Description("搜索关键词，大小写不敏感")),
		mcp.WithNumber("line", mcp.Description("行号跳转：传入指令行号（index），自动定位到该行所在的结果页返回。与 offset 互斥，优先使用 line")),
		mcp.WithNumber("offset", mcp.Description("结果分页偏移，默认 0")),
		mcp.WithNumber("limit", mcp.Description("结果分页大小，默认 50，最大 200")),
	), handleSearchInstructions)

	s.AddTool(mcp.NewTool("set_watchpoint",
		mcp.WithDescription(`设置内存监控点，找出 trace 中所有访问指定地址范围的指令（读或写）。返回 watchpoint_id 用于后续 watchpoint_traceback 调用。
结果按 index 降序排列（最新的在前）。每条结果包含：instrText、regText（寄存器状态）、hexText（实际访问数据的 hex）、accessStart/accessEnd（指令实际操作的内存地址范围）。
重要：set_watchpoint 通常需要配合 watchpoint_traceback 使用来追踪数据来源链。
典型数据溯源流程：
1. search_memory 找到感兴趣的数据，发现某条 str x1, [addr] 写入了目标地址
2. 想知道 x1 的值从哪来 → 向上看指令，找到 ldr x1, [0x123456]
3. set_watchpoint 监控 0x123456 → 拿到 watchpoint_id → watchpoint_traceback 从 ldr 所在行号回溯，type_filter=write → 找到最后写入 0x123456 的指令
4. 重复此过程，逐步追溯整条数据来源链`),
		mcp.WithString("addr", mcp.Required(), mcp.Description("监控地址，hex 格式如 0x40001000")),
		mcp.WithNumber("size", mcp.Required(), mcp.Description("监控字节数（如 4 表示监控 4 字节）")),
		mcp.WithNumber("offset", mcp.Description("结果分页偏移，默认 0")),
		mcp.WithNumber("limit", mcp.Description("结果分页大小，默认 50，最大 200")),
	), handleSetWatchpoint)

	s.AddTool(mcp.NewTool("watchpoint_traceback",
		mcp.WithDescription(`【必须先调用 set_watchpoint 拿到 watchpoint_id】从指定行号向上回溯，在监控点结果中找到该行之前最近的写入（或读取）记录。这是追踪数据来源链的核心工具。
结果按行号降序（最邻近的在前），第一条就是离目标最近的访问。每条结果包含：instrText、regText（寄存器状态）、hexText（实际访问数据的 hex）、accessStart/accessEnd（指令实际操作的内存地址范围）。
典型用法：发现 ldr x1, [0x123456] 从某地址读取了数据，想知道谁最后写入了 0x123456 → set_watchpoint(addr=0x123456, size=8) 拿到 watchpoint_id → watchpoint_traceback(watchpoint_id=id, before_index=ldr所在行号, type_filter=write) → 第一条结果就是最后写入该地址的 str 指令。`),
		mcp.WithString("watchpoint_id", mcp.Required(), mcp.Description("set_watchpoint 返回的 watchpoint_id")),
		mcp.WithNumber("before_index", mcp.Required(), mcp.Description("目标行号，只返回行号小于此值的记录")),
		mcp.WithString("type_filter", mcp.Description("过滤类型: write / read / all，默认 write")),
		mcp.WithNumber("offset", mcp.Description("结果分页偏移，默认 0")),
		mcp.WithNumber("limit", mcp.Description("结果分页大小，默认 50，最大 200")),
	), handleWatchpointTraceback)

	s.AddTool(mcp.NewTool("trace_register",
		mcp.WithDescription(`追踪指定寄存器在指定行号范围内的值变化。只追踪被指令写回（修改）的值，即 regText 中 => 后面出现的寄存器。`),
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
