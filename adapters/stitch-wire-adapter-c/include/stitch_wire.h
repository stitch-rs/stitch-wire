#ifndef STITCH_WIRE_H
#define STITCH_WIRE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STITCH_WIRE_MAGIC 0x5354
#define STITCH_WIRE_VERSION_1 0x01

#define STITCH_FLAG_COMPRESSED   (1 << 0)
#define STITCH_FLAG_CHUNKED      (1 << 1)
#define STITCH_FLAG_SCHEMA_HASH  (1 << 2)

/**
 * C representation of wire frame header options.
 */
typedef struct {
    uint8_t profile;         /* 0 = Direct, 1 = Realtime, 2 = Balanced, 3 = MaxDensity */
    uint8_t flags;           /* bitmask: STITCH_FLAG_* */
    uint64_t schema_hash;    /* Schema hash or 0 if none */
} stitch_wire_options_t;

/**
 * Calculates Castagnoli CRC32 checksum with hardware acceleration (CLMUL / SSE4.2).
 */
uint32_t stitch_crc32(const uint8_t* data, size_t len);

/**
 * Packs a frame into out_buf.
 * Returns bytes written on success, or 0 on error.
 */
size_t stitch_pack_frame(
    const stitch_wire_options_t* opts,
    const uint8_t* payload,
    size_t payload_len,
    uint8_t* out_buf,
    size_t out_capacity
);

/**
 * Unpacks and verifies a frame from frame_buf.
 * Writes payload pointer and length to out parameters.
 * Returns 1 on success, 0 on checksum/format error.
 */
int stitch_unpack_frame(
    const uint8_t* frame_buf,
    size_t frame_len,
    const uint8_t** out_payload_ptr,
    size_t* out_payload_len,
    uint64_t* out_schema_hash
);

/**
 * SWAR-accelerated search for Stitch wire magic bytes (0x5354).
 * Returns offset in bytes, or SIZE_MAX if not found.
 */
size_t stitch_find_magic(const uint8_t* data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* STITCH_WIRE_H */
