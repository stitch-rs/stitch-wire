use core::hint::black_box;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use stitch_wire::crc::crc32_castagnoli;
use stitch_wire::pipeline::{WireBlackboard, WirePresets};
use stitch_wire::resync::find_magic_swar;
use stitch_wire::{
    OptimizationProfile, WIRE_MAGIC, WireFlags, WireHeader, pack_frame, unpack_frame,
};

fn bench_wire_framing(c: &mut Criterion) {
    let mut group = c.benchmark_group("wire_framing");

    let payload_64b: Vec<u8> = (0..64).map(|i| (i * 37 + 13) as u8).collect();
    let payload_1k: Vec<u8> = (0..1024).map(|i| (i * 37 + 13) as u8).collect();

    let mut out_buf = [0u8; 2048];

    let header_64b = WireHeader {
        profile: OptimizationProfile::Realtime,
        flags: WireFlags::new(true, false, false),
        payload_len: payload_64b.len(),
        schema_hash: None,
    };

    let header_1k = WireHeader {
        profile: OptimizationProfile::Balanced,
        flags: WireFlags::new(true, false, false),
        payload_len: payload_1k.len(),
        schema_hash: None,
    };

    group.throughput(Throughput::Bytes(64));
    group.bench_function("pack_frame_64b", |b| {
        b.iter(|| {
            let written = pack_frame(
                black_box(&header_64b),
                black_box(&payload_64b),
                black_box(&mut out_buf),
            )
            .unwrap();
            black_box(written);
        })
    });

    group.throughput(Throughput::Bytes(1024));
    group.bench_function("pack_frame_1k", |b| {
        b.iter(|| {
            let written = pack_frame(
                black_box(&header_1k),
                black_box(&payload_1k),
                black_box(&mut out_buf),
            )
            .unwrap();
            black_box(written);
        })
    });

    let frame_1k_len = pack_frame(&header_1k, &payload_1k, &mut out_buf).unwrap();
    let framed_1k = out_buf[..frame_1k_len].to_vec();

    group.bench_function("unpack_frame_1k_with_crc", |b| {
        b.iter(|| {
            let (hdr, payload) = unpack_frame(black_box(&framed_1k)).unwrap();
            black_box((hdr.payload_len, payload.len()));
        })
    });

    group.finish();
}

fn bench_crc_and_swar(c: &mut Criterion) {
    let mut group = c.benchmark_group("hardware_primitives");

    let data_1k: Vec<u8> = (0..1024).map(|i| (i * 37 + 13) as u8).collect();
    group.throughput(Throughput::Bytes(1024));

    group.bench_function("castagnoli_crc32_1k", |b| {
        b.iter(|| {
            let crc = crc32_castagnoli(black_box(&data_1k));
            black_box(crc);
        })
    });

    let mut noisy_stream = vec![0xFFu8; 4096];
    noisy_stream[1023] = WIRE_MAGIC;
    noisy_stream[2047] = WIRE_MAGIC;
    noisy_stream[3071] = WIRE_MAGIC;

    group.throughput(Throughput::Bytes(4096));
    group.bench_function("swar_resync_scan_4kb", |b| {
        b.iter(|| {
            let mut pos = 0;
            let mut matches = 0;
            while pos < noisy_stream.len() {
                if let Some(idx) = find_magic_swar(black_box(&noisy_stream[pos..])) {
                    matches += 1;
                    pos += idx + 1;
                } else {
                    break;
                }
            }
            black_box(matches);
        })
    });

    group.finish();
}

fn bench_sma_wire_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("sma_pipeline");

    let payload: Vec<u8> = (0..256).map(|i| (i * 17 + 5) as u8).collect();
    let header = WireHeader {
        profile: OptimizationProfile::Realtime,
        flags: WireFlags::new(true, false, false),
        payload_len: payload.len(),
        schema_hash: None,
    };

    let mut out_buf = [0u8; 1500];

    group.throughput(Throughput::Bytes(256));
    group.bench_function("game_datagram_preset_cycle", |b| {
        b.iter(|| {
            let mut pipeline = WirePresets::game_datagram(1400, &mut out_buf);
            let mut ctx = WireBlackboard::new_tx(header.clone(), payload.len());
            let outcome = pipeline
                .dispatch(black_box(&mut ctx), black_box(&payload[..]))
                .unwrap();
            black_box(outcome);
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_wire_framing,
    bench_crc_and_swar,
    bench_sma_wire_pipeline
);
criterion_main!(benches);
