# Changelog

All notable changes to `stitch-wire` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-11-03

### Added

- **SMA Composable Pipeline Engine**:
  - `WireBlackboard`: 64-byte L1D cache-aligned context satisfying `align_of == 64` and `size_of == 64`.
  - SMA Layers: `FramingLayer`, `CastagnoliCrcLayer`, `MtuChunkingLayer`, `SwarResyncLayer`.
  - Terminals: `BufferTerminal` writing directly into pre-allocated memory.
  - Domain Presets: `WirePresets::game_datagram`, `WirePresets::stream_framing`.
- **Hardware-Accelerated CRC-32C Castagnoli**: 16-way slicing-by-8/16 with hardware instruction support.
- **Streaming Resynchronization**: Bit-parallel SWAR scanner for magic byte recovery.
- **Adapters**:
  - `stitch-wire-adapter-udp`: Non-blocking batched UDP datagram transmitter and receiver.
  - `stitch-wire-adapter-tokio`: Asynchronous Tokio framing integration.
  - `stitch-wire-adapter-std`: Standard library synchronous reader/writer.
  - `stitch-wire-adapter-c`: C-ABI zero-copy framing bindings.
  - `stitch-wire-adapter-wasm`: WebAssembly browser transport integration.

### Changed

- Refactored `WireFlags` to include canonical flags (`FLAG_RETAIN_LAST`, `FLAG_HIGH_PRIORITY`, `FLAG_REQUIRES_ACK`, `FLAG_HEARTBEAT`).
- Quarantined raw socket I/O from core crates into dedicated adapter crates.
