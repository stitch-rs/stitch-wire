# Stitch Wire Engine (`stitch-wire`) Technical Reference

**Specification Identifier:** `ARCH-SPEC-STITCH-WIRE-001`  
**Classification:** Normative Wire Framing, Composable Pipeline & Invariant Contracts  
**Status:** Canonical (Single Source of Truth)  

---

## 1. Normative Authority & Contract Hierarchy

This document serves as the **sole normative technical specification** for the `stitch-wire` transport framing, resynchronization, and microsecond pipeline bus.

- `ARCHITECTURE.md`: The authoritative reference for 28-byte wire frame headers, 64-byte `WireBlackboard` cache alignment, SMA U-cycle framing layers, zero-copy buffer terminals, and SWAR resynchronization.
- `README.md`: Informative landing page, getting-started examples, and integration guide. In any discrepancy, `ARCHITECTURE.md` supersedes `README.md`.

---

## 2. Core Architectural Axioms

1. **Zero Socket Leaks in Core (`#![no_std]`)**:
   - `stitch-wire-core` and `stitch-wire` are pure framing and pipeline engines.
   - Operating system socket I/O (`std::net::UdpSocket`, Tokio UDP, epoll) is strictly quarantined in standalone adapters (`adapters/stitch-wire-adapter-*`).
   - Hot path packet processing emits zero-copy borrowed slices or `[IoSlice; 2]` scatter-gather descriptors.

2. **The Composable Sewing Machine Pipeline**:
   - Framing, checksum verification, MTU segmentation, and noisy stream resynchronization are monomorphic SMA layers (`stitch_core::Layer`).
   - Context is carried via `WireBlackboard`, statically asserted to 64-byte L1D cache-line alignment (`#[repr(C, align(64))]`).

3. **Mechanical Sympathy & Sub-Microsecond Budgets**:
   - Frame header parsing executes in $< 5 \text{ ns}$.
   - Hardware Castagnoli CRC-32C operates at $> 25 \text{ GiB/s}$ using hardware CRC32/PCLMULQDQ or 16-way slicing-by-8/16.
   - SWAR resynchronization scans up to 8 bytes per iteration via bit-parallel prefix matching.

---

## 3. Physical Wire Frame Format

The canonical 28-byte wire frame layout:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Magic (0x57)| Version (0x01)|  Profile Tag  |  WireFlags    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Payload Length (u32 LE)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Schema Hash Low 32-bits (u32 LE)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Schema Hash High 32-bits (u32 LE)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Sequence Number (u64 LE)                    |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|              Hardware Castagnoli CRC-32C Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Framed Payload Data                       |
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 3.1 Field Specifications

- `Magic`: 1 byte (`0x57` = `'W'`), marking frame start.
- `Version`: 1 byte (`0x01`).
- `Profile`: 1 byte optimization profile tag (`Direct`, `Realtime`, `Balanced`, `MaxDensity`).
- `WireFlags`: 1 byte bitmask:
  - Bit 0: `FLAG_COMPRESSED` (`0x01`)
  - Bit 1: `FLAG_CHUNKED` (`0x02`)
  - Bit 2: `FLAG_SCHEMA_HASH` (`0x04`)
  - Bit 3: `FLAG_RETAIN_LAST` (`0x08`)
  - Bit 4: `FLAG_HIGH_PRIORITY` (`0x10`)
  - Bit 5: `FLAG_REQUIRES_ACK` (`0x20`)
  - Bit 6: `FLAG_HEARTBEAT` (`0x40`)
  - Bit 7: Reserved (`0x80`)
- `Payload Length`: 4 bytes unsigned little-endian integer.
- `Schema Hash`: 8 bytes optional FNV-1a schema identifier (or zero).
- `Sequence Number`: 8 bytes monotonic packet sequence for loss/out-of-order tracking.
- `CRC-32C`: 4 bytes Castagnoli CRC-32C calculated across header fields and payload.

---

## 4. SMA Pipeline Architecture & Layers

Framing operations implement the Sewing Machine Architecture (`stitch_core::Layer` and `stitch_core::Terminal`):

```text
Intent (&[u8]) ──► [FramingLayer] ──► [CastagnoliCrcLayer] ──► [BufferTerminal]
                                                                      │
Outcome (usize) ◄─ [FramingLayer] ◄── [CastagnoliCrcLayer] ◄──────────┘
```

### 4.1 WireBlackboard Context

```rust
#[repr(C, align(64))]
pub struct WireBlackboard {
    pub header: WireHeader,
    pub flags: WireFlags,
    pub crc32: u32,
    pub bytes_processed: usize,
    pub chunk_index: u16,
    pub chunk_total: u16,
    pub resync_offset: usize,
    pub _pad: [u8; 12],
}
```

Statically verified to satisfy:
- `align_of::<WireBlackboard>() == 64`
- `size_of::<WireBlackboard>() == 64` (exact single L1D cache-line fit).

### 4.2 Presets & Extension Traits (`WirePresets`)

- `WirePresets::game_datagram(mtu)`: Composes `FramingLayer` + `CastagnoliCrcLayer` + `MtuChunkingLayer` + `BufferTerminal`.
- `WirePresets::stream_framing()`: Composes `SwarResyncLayer` + `FramingLayer` + `CastagnoliCrcLayer` + `BufferTerminal`.
