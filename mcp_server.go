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
		mcp.WithDescription("获取当前加载的 unidbg trace 文件的基本信息。这是分析的起点，应首先调用。返回值包括：总指令记录数、索引构建状态、所有线程 ID 列表，以及从第一条记录自动推断的上下文——入口函数 PC 和符号名、主线程 ID、主 SO 名称。因为 unidbg trace 是对某个函数的调用追踪，所以第一条记录就是入口函数，其线程 ID 就是主线程，其 PC 地址中的 SO 名就是被分析的主 SO。"),
	), handleTraceInfo)

	s.AddTool(mcp.NewTool("get_instructions",
		mcp.WithDescription("分页获取 trace 中的 ARM 指令列表。每条指令包含 PC 地址（可能带符号名如 libc.so+0x1234）、汇编文本、寄存器状态、调用深度、内存访问标记。支持按线程 ID 过滤。结果按执行顺序（行号升序）排列。"),
		mcp.WithNumber("offset", mcp.Required(), mcp.Description("起始位置（行号偏移），从 0 开始")),
		mcp.WithNumber("limit", mcp.Description("返回条数，默认 100，最大 500")),
		mcp.WithNumber("tid", mcp.Description("线程 ID 过滤，不传则返回所有线程。传入后 offset 是该线程内的偏移")),
	), handleGetInstructions)

	s.AddTool(mcp.NewTool("get_memory",
		mcp.WithDescription("获取指定行号的指令在执行时的内存读写数据。每个内存区域包含访问地址前后各 128 字节的上下文快照，数据为 hex 编码。返回值中标注了实际访问范围（accessRange）。可选传入 highlight 参数来标记关注的地址范围（如监控点地址或搜索命中地址），返回值会额外提取该范围的数据片段，便于快速定位关键数据而无需解析整个 hex dump。"),
		mcp.WithNumber("index", mcp.Required(), mcp.Description("指令行号")),
		mcp.WithString("highlight_addr", mcp.Description("需要关注的地址，hex 格式如 0x40001000")),
		mcp.WithNumber("highlight_size", mcp.Description("关注的字节数，配合 highlight_addr 使用")),
	), handleGetMemory)

	s.AddTool(mcp.NewTool("get_functions",
		mcp.WithDescription("获取 trace 中识别出的所有函数摘要，包括函数入口 PC 地址、调用次数、首次调用位置、总执行指令数。按调用次数降序排列。需要索引构建完成。"),
	), handleGetFunctions)

	// ==================== Search Tools ====================

	s.AddTool(mcp.NewTool("search_memory",
		mcp.WithDescription("在 trace 所有指令的内存读写数据中搜索指定的 hex 字节序列或字符串。用于追踪特定数据（如密钥、明文、魔数）在哪些指令中出现。结果按行号升序排列。搜索可能耗时较长，结果可能有成千上万条，请使用分页获取。提示：拿到结果后，可将 chunkBase 和 matchOffset 传给 get_memory 的 highlight_addr/highlight_size 参数，直接提取命中位置的数据。"),
		mcp.WithString("pattern", mcp.Required(), mcp.Description("搜索模式。hex 模式如 0a1b2c3d，string 模式如 hello")),
		mcp.WithString("type", mcp.Required(), mcp.Description("hex 或 string")),
		mcp.WithNumber("offset", mcp.Description("结果分页偏移，默认 0")),
		mcp.WithNumber("limit", mcp.Description("结果分页大小，默认 50，最大 200")),
	), handleSearchMemory)

	s.AddTool(mcp.NewTool("search_instructions",
		mcp.WithDescription("在 trace 所有指令的 PC 地址文本、汇编指令文本、寄存器状态文本中搜索关键词（大小写不敏感）。用于定位特定指令模式，如搜索 aes 找加密相关指令，搜索 bl 0x40001000 找特定函数调用。结果按行号升序排列。警告：请使用尽可能具体的关键词！模糊搜索如 mov 或 ldr 会命中成千上万条结果，严重浪费 token。建议搭配完整的操作数搜索（如 movz w9, #0xa1 而非 movz），或搜索特定地址/符号名（如 libmain.so+0x5bc04）。"),
		mcp.WithString("keyword", mcp.Required(), mcp.Description("搜索关键词")),
		mcp.WithNumber("offset", mcp.Description("结果分页偏移，默认 0")),
		mcp.WithNumber("limit", mcp.Description("结果分页大小，默认 50，最大 200")),
	), handleSearchInstructions)

	s.AddTool(mcp.NewTool("set_watchpoint",
		mcp.WithDescription("设置内存监控点，找出 trace 中所有访问指定地址范围的指令。用于追踪某个内存地址被哪些指令读写。结果按行号升序排列。提示：拿到结果后，可将监控地址传给 get_memory 的 highlight_addr/highlight_size 参数，在内存快照中直接定位监控范围的数据。"),
		mcp.WithString("addr", mcp.Required(), mcp.Description("监控地址，hex 格式如 0x40001000")),
		mcp.WithNumber("size", mcp.Required(), mcp.Description("监控字节数（如 4 表示监控 4 字节）")),
		mcp.WithNumber("offset", mcp.Description("结果分页偏移，默认 0")),
		mcp.WithNumber("limit", mcp.Description("结果分页大小，默认 50，最大 200")),
	), handleSetWatchpoint)

	s.AddTool(mcp.NewTool("watchpoint_traceback",
		mcp.WithDescription("在当前监控点结果中，从指定行号向上回溯，找到该行之前最近的内存访问记录。结果按行号降序排列（最邻近目标行的排最前）。典型场景：某条 ldr 指令从地址 X 读取了数据，想知道是谁最后写入了地址 X——先 set_watchpoint 监控地址 X，再用本接口从 ldr 所在行号回溯，过滤仅写入 [W]，第一条结果大概率就是目标 str 指令。"),
		mcp.WithNumber("before_index", mcp.Required(), mcp.Description("目标行号，只返回行号小于此值的记录")),
		mcp.WithString("type_filter", mcp.Description("过滤类型: write / read / all，默认 write")),
		mcp.WithNumber("offset", mcp.Description("结果分页偏移，默认 0")),
		mcp.WithNumber("limit", mcp.Description("结果分页大小，默认 50，最大 200")),
	), handleWatchpointTraceback)

	s.AddTool(mcp.NewTool("trace_register",
		mcp.WithDescription("追踪指定寄存器（如 x0, x1, sp, lr 等）在指定行号范围内每条指令的值变化。用于分析寄存器数据流，如追踪某个参数在函数调用链中的传递过程。"),
		mcp.WithString("reg", mcp.Required(), mcp.Description("寄存器名（大小写不敏感），如 x0, sp, lr")),
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
