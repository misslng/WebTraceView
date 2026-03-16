package com.github.unidbg;

import capstone.api.Instruction;
import com.github.unidbg.arm.Cpsr;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.ReadHook;
import com.github.unidbg.arm.backend.WriteHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.memory.MemoryMap;
import unicorn.Arm64Const;
import unicorn.ArmConst;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.Locale;

/**
 * RegAccessPrinter — 一条指令一条记录的二进制 trace
 *
 * 文件格式（小端序）：
 *
 *
 * 使用方式:
 *   RegAccessPrinter.initTraceFile(emulator, "trace_output.bin");
 *   RegAccessPrinter.shutdownTrace();
 */
public class RegAccessPrinter {

    private final long address;
    private final Instruction instruction;
    private final short[] accessRegs;
    private boolean forWriteRegs;

    // ==================== 全局共享 ====================
    private static volatile TraceWriter globalWriter;
    private static volatile Emulator<?> tracingEmulator;

    /** 分开记录读/写访问点 */
    private static final ConcurrentLinkedQueue<AccessPoint> readAccessPoints = new ConcurrentLinkedQueue<>();
    private static final ConcurrentLinkedQueue<AccessPoint> writeAccessPoints = new ConcurrentLinkedQueue<>();

    /**
     * 暂存第一次 print()（读寄存器）的信息，等第二次 print()（写寄存器）时合并写出。
     * 因为 unidbg trace 是单线程顺序执行的，用 volatile 即可。
     */
    private static volatile PendingRecord pendingRecord;

    private final boolean isWritePass;

    public RegAccessPrinter(long address, Instruction instruction, short[] accessRegs, boolean forWriteRegs) {
        this.address = address;
        this.instruction = instruction;
        this.accessRegs = accessRegs;
        this.forWriteRegs = forWriteRegs;
        this.isWritePass = forWriteRegs;  // 保存原始值，用于配对判断
    }

    // ==================== 全局 trace 控制 ====================

    public static void initTraceFile(Emulator<?> emulator, String outputPath) {
        tracingEmulator = emulator;
        readAccessPoints.clear();
        writeAccessPoints.clear();
        pendingRecord = null;
        globalWriter = new TraceWriter(outputPath);
        globalWriter.start();
        installAccessHooks(emulator);
    }

    public static void shutdownTrace() {
        // 如果有未写出的 pending，强制写出
        if (pendingRecord != null && globalWriter != null) {
            globalWriter.enqueue(new TraceRecord(
                    pendingRecord.pc, pendingRecord.instrText, pendingRecord.regText,
                    pendingRecord.readChunks, Collections.emptyList()));
            pendingRecord = null;
        }
        if (globalWriter != null) {
            globalWriter.shutdown();
            globalWriter = null;
        }
        tracingEmulator = null;
        readAccessPoints.clear();
        writeAccessPoints.clear();
    }

    private static void installAccessHooks(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();

        backend.hook_add_new(new WriteHook() {
            @Override
            public void hook(Backend backend, long address, int size, long value, Object user) {
                writeAccessPoints.offer(new AccessPoint(address, size));
            }
            @Override public void onAttach(UnHook unHook) {}
            @Override public void detach() {}
        }, 1, 0, null);

        backend.hook_add_new(new ReadHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                readAccessPoints.offer(new AccessPoint(address, size));
            }
            @Override public void onAttach(UnHook unHook) {}
            @Override public void detach() {}
        }, 1, 0, null);
    }

    // ==================== 核心 print 方法 ====================

    public void print(Emulator<?> emulator, Backend backend, StringBuilder builder, long address) {
        if (this.address != address) {
            return;
        }

        // 记录 builder 当前位置，后面只截取本次新增的寄存器文本
        int builderStart = builder.length();

        // 收集寄存器信息（原有逻辑，往 builder 追加）
        for (short reg : accessRegs) {
            int regId = instruction.mapToUnicornReg(reg);
            if (emulator.is32Bit()) {
                if ((regId >= ArmConst.UC_ARM_REG_R0 && regId <= ArmConst.UC_ARM_REG_R12) ||
                        regId == ArmConst.UC_ARM_REG_LR || regId == ArmConst.UC_ARM_REG_SP ||
                        regId == ArmConst.UC_ARM_REG_CPSR) {
                    if (forWriteRegs) {
                        builder.append(" =>");
                        forWriteRegs = false;
                    }
                    if (regId == ArmConst.UC_ARM_REG_CPSR) {
                        Cpsr cpsr = Cpsr.getArm(backend);
                        builder.append(" cpsr: ").append(String.format(Locale.US, "N=%d, Z=%d, C=%d, V=%d",
                                cpsr.isNegative() ? 1 : 0, cpsr.isZero() ? 1 : 0,
                                cpsr.hasCarry() ? 1 : 0, cpsr.isOverflow() ? 1 : 0));
                    } else {
                        int value = backend.reg_read(regId).intValue();
                        long unsigned = value & 0xffffffffL;
                        builder.append(' ').append(instruction.regName(reg)).append("=0x").append(Long.toHexString(unsigned));
                    }
                }
            } else {
                if ((regId >= Arm64Const.UC_ARM64_REG_X0 && regId <= Arm64Const.UC_ARM64_REG_X28) ||
                        (regId >= Arm64Const.UC_ARM64_REG_X29 && regId <= Arm64Const.UC_ARM64_REG_SP)) {
                    if (forWriteRegs) {
                        builder.append(" =>");
                        forWriteRegs = false;
                    }
                    if (regId == Arm64Const.UC_ARM64_REG_NZCV) {
                        Cpsr cpsr = Cpsr.getArm64(backend);
                        String label = cpsr.isA32() ? "cpsr" : "nzcv";
                        builder.append(' ').append(label).append(": ").append(String.format(Locale.US, "N=%d, Z=%d, C=%d, V=%d",
                                cpsr.isNegative() ? 1 : 0, cpsr.isZero() ? 1 : 0,
                                cpsr.hasCarry() ? 1 : 0, cpsr.isOverflow() ? 1 : 0));
                    } else {
                        long value = backend.reg_read(regId).longValue();
                        builder.append(' ').append(instruction.regName(reg)).append("=0x").append(Long.toHexString(value));
                    }
                } else if (regId >= Arm64Const.UC_ARM64_REG_W0 && regId <= Arm64Const.UC_ARM64_REG_W30) {
                    if (forWriteRegs) {
                        builder.append(" =>");
                        forWriteRegs = false;
                    }
                    int value = backend.reg_read(regId).intValue();
                    long unsigned = value & 0xffffffffL;
                    builder.append(' ').append(instruction.regName(reg)).append("=0x").append(Long.toHexString(unsigned));
                }
            }
        }

        // ===== 二进制 trace 写出逻辑 =====
        if (globalWriter == null || tracingEmulator == null) {
            return;
        }

        String instrText = instruction.getMnemonic() + " " + instruction.getOpStr();
        // 只截取本次 print() 新增的寄存器文本，避免混入外部 log
        String regSnapshot = builder.substring(builderStart);

        if (!isWritePass) {
            // ===== 第一次 print（读寄存器）=====
            // 如果有上一条未配对的 pending，先写出
            if (pendingRecord != null) {
                globalWriter.enqueue(new TraceRecord(
                        pendingRecord.pc, pendingRecord.instrText, pendingRecord.regText,
                        pendingRecord.readChunks, Collections.emptyList()));
            }
            List<MemoryChunk> readChunks = drainAccessPoints(readAccessPoints, backend);
            pendingRecord = new PendingRecord(this.address, instrText,
                    regSnapshot, readChunks);
        } else {
            // ===== 第二次 print（写寄存器）=====
            if (pendingRecord != null) {
                List<MemoryChunk> writeChunks = drainAccessPoints(writeAccessPoints, backend);
                List<MemoryChunk> extraRead = drainAccessPoints(readAccessPoints, backend);
                List<MemoryChunk> allRead = pendingRecord.readChunks;
                if (!extraRead.isEmpty()) {
                    allRead = new ArrayList<>(allRead);
                    allRead.addAll(extraRead);
                }

                String combinedRegText = pendingRecord.regText + regSnapshot;

                globalWriter.enqueue(new TraceRecord(
                        pendingRecord.pc,
                        pendingRecord.instrText,
                        combinedRegText,
                        allRead,
                        writeChunks));
                pendingRecord = null;
            } else {
                // 没有 pending 却收到写 pass，单独写出
                List<MemoryChunk> writeChunks = drainAccessPoints(writeAccessPoints, backend);
                globalWriter.enqueue(new TraceRecord(
                        this.address, instrText, regSnapshot,
                        Collections.emptyList(), writeChunks));
            }
        }
    }

    /** 从队列中取出所有访问点并采集内存窗口 */
    private static List<MemoryChunk> drainAccessPoints(ConcurrentLinkedQueue<AccessPoint> queue, Backend backend) {
        List<MemoryChunk> chunks = new ArrayList<>();
        AccessPoint p;
        while ((p = queue.poll()) != null) {
            long lo = Math.max(1, p.address - WINDOW_RADIUS);
            long hi = p.address + p.size + WINDOW_RADIUS;
            int readSize = (int) (hi - lo);
            if (lo == 0 || readSize <= 0 || readSize > 64 * 1024) continue;
            try {
                byte[] data = backend.mem_read(lo, readSize);
                if (data != null) {
                    chunks.add(new MemoryChunk(lo, data));
                }
            } catch (Exception ignored) {}
        }
        return chunks;
    }

    private static final int WINDOW_RADIUS = 128;

    // ==================== 数据结构 ====================

    static class AccessPoint {
        final long address;
        final int size;
        AccessPoint(long address, int size) {
            this.address = address;
            this.size = size;
        }
    }

    static class MemoryChunk {
        final long base;
        final byte[] data;
        MemoryChunk(long base, byte[] data) {
            this.base = base;
            this.data = data;
        }
    }

    /** 暂存第一次 print 的数据 */
    static class PendingRecord {
        final long pc;
        final String instrText;
        final String regText;
        final List<MemoryChunk> readChunks;
        PendingRecord(long pc, String instrText, String regText, List<MemoryChunk> readChunks) {
            this.pc = pc;
            this.instrText = instrText;
            this.regText = regText;
            this.readChunks = readChunks;
        }
    }

    /** 一条完整的 trace 记录（一条指令） */
    static class TraceRecord {
        final long pc;
        final String instrText;
        final String regText;
        final List<MemoryChunk> readChunks;
        final List<MemoryChunk> writeChunks;

        TraceRecord(long pc, String instrText, String regText,
                    List<MemoryChunk> readChunks, List<MemoryChunk> writeChunks) {
            this.pc = pc;
            this.instrText = instrText;
            this.regText = regText;
            this.readChunks = readChunks;
            this.writeChunks = writeChunks;
        }
    }

    // ==================== 异步写入 ====================

    /**
     * 文件格式（小端序），每条记录：
     *
     *   magic          : 4B   "UTRA"
     *   pc             : 8B
     *   instrLen       : 2B
     *   instrBytes     : instrLen B
     *   regTextLen     : 2B
     *   regTextBytes   : regTextLen B
     *   readChunkCnt   : 4B
     *   [base:8B, len:4B, data:lenB] × readChunkCnt
     *   writeChunkCnt  : 4B
     *   [base:8B, len:4B, data:lenB] × writeChunkCnt
     */
    static class TraceWriter {
        private static final byte[] MAGIC = "UTRA".getBytes(StandardCharsets.US_ASCII);

        private final String outputPath;
        private final BlockingQueue<TraceRecord> queue;
        private final Thread workerThread;
        private volatile boolean running = true;

        TraceWriter(String outputPath) {
            this.outputPath = outputPath;
            this.queue = new LinkedBlockingQueue<>(); // 无界，有多少内存吃多少
            this.workerThread = new Thread(this::processLoop, "UnidbgTraceWriter");
            // 不设为 daemon，确保 JVM 退出前能写完
            this.workerThread.setDaemon(false);
        }

        void start() { workerThread.start(); }

        void enqueue(TraceRecord record) {
            queue.offer(record);
        }

        void shutdown() {
            running = false;
            workerThread.interrupt();
            try { workerThread.join(); } catch (InterruptedException ignored) {} // 不限时，等写完
            drainRemaining();
        }

        private void processLoop() {
            try (BufferedOutputStream bos = new BufferedOutputStream(
                    Files.newOutputStream(Paths.get(outputPath),
                            StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING), 1024 * 1024)) {
                while (running || !queue.isEmpty()) {
                    TraceRecord record;
                    try {
                        record = queue.poll(100, TimeUnit.MILLISECONDS);
                    } catch (InterruptedException e) {
                        if (!running && queue.isEmpty()) break;
                        continue;
                    }
                    if (record == null) continue;
                    writeRecord(bos, record);
                }
                bos.flush();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        private void drainRemaining() {
            try (BufferedOutputStream bos = new BufferedOutputStream(
                    Files.newOutputStream(Paths.get(outputPath),
                            StandardOpenOption.CREATE, StandardOpenOption.APPEND), 1024 * 1024)) {
                TraceRecord record;
                while ((record = queue.poll()) != null) {
                    writeRecord(bos, record);
                }
                bos.flush();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        private void writeRecord(BufferedOutputStream bos, TraceRecord record) throws IOException {
            byte[] instrBytes = record.instrText.getBytes(StandardCharsets.UTF_8);
            byte[] regBytes = record.regText.getBytes(StandardCharsets.UTF_8);

            // header: magic + pc + instrLen + instr + regLen + reg + readChunkCnt
            int headerSize = 4 + 8 + 2 + instrBytes.length + 2 + regBytes.length + 4;
            ByteBuffer header = ByteBuffer.allocate(headerSize);
            header.order(ByteOrder.LITTLE_ENDIAN);
            header.put(MAGIC);
            header.putLong(record.pc);
            header.putShort((short) instrBytes.length);
            header.put(instrBytes);
            header.putShort((short) regBytes.length);
            header.put(regBytes);
            header.putInt(record.readChunks.size());
            bos.write(header.array());

            // read chunks
            for (MemoryChunk chunk : record.readChunks) {
                writeChunk(bos, chunk);
            }

            // writeChunkCnt + write chunks
            ByteBuffer wcBuf = ByteBuffer.allocate(4);
            wcBuf.order(ByteOrder.LITTLE_ENDIAN);
            wcBuf.putInt(record.writeChunks.size());
            bos.write(wcBuf.array());

            for (MemoryChunk chunk : record.writeChunks) {
                writeChunk(bos, chunk);
            }
        }

        private void writeChunk(BufferedOutputStream bos, MemoryChunk chunk) throws IOException {
            ByteBuffer chunkHeader = ByteBuffer.allocate(12);
            chunkHeader.order(ByteOrder.LITTLE_ENDIAN);
            chunkHeader.putLong(chunk.base);
            chunkHeader.putInt(chunk.data.length);
            bos.write(chunkHeader.array());
            bos.write(chunk.data);
        }
    }
}
