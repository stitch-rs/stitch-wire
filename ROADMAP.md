# Stitch Wire (`stitch-wire`) Roadmap

This roadmap tracks the development milestones, releases, and forward-looking capabilities for `stitch-wire`.

---

## Current Release: v0.1.0 (SMA Composable Pipeline Architecture)

- [x] **Zero Socket Leaks in Core**: Socket I/O (`std::net::UdpSocket`, Tokio) migrated to standalone adapters (`adapters/stitch-wire-adapter-udp`).
- [x] **Composable SMA Framing Pipeline**:
  - `WireBlackboard`: 64-byte L1D cache-aligned context (`#[repr(C, align(64))]`).
  - Modular SMA layers: `FramingLayer`, `CastagnoliCrcLayer`, `MtuChunkingLayer`, `SwarResyncLayer`.
  - Zero-allocation `BufferTerminal` and scatter-gather vectorization.
- [x] **Canonical `WireFlags`**: `FLAG_COMPRESSED`, `FLAG_CHUNKED`, `FLAG_SCHEMA_HASH`, `FLAG_RETAIN_LAST`, `FLAG_HIGH_PRIORITY`, `FLAG_REQUIRES_ACK`, `FLAG_HEARTBEAT`.
- [x] **Hardware CRC-32C Castagnoli**: 16-way slicing-by-8/16 and hardware acceleration.
- [x] **SWAR Prefix Resynchronization**: Bit-parallel resync over noisy streams.

---

## v0.2.0 (Zero-Copy Vectored Rings & Shared Memory)

- [ ] **Lock-free SPSC Ring Buffer Enhancements**: Cache-padded atomic pointers with batched push/pop.
- [ ] **Cross-Platform Shared Memory Adapter**: Zero-copy IPC memory mapped transport (`stitch-wire-adapter-shm`).
- [ ] **Kernel Bypass Adapters**: io_uring and AF_XDP experimental zero-copy drivers.
