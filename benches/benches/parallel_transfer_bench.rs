use criterion::{Criterion, criterion_group, criterion_main};
use rayon::prelude::*;
use std::hint::black_box;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use stitch_wire::ChunkPartitioner;

// 1. In-Memory Transfer Benchmarks (Raw Engine Throughput: CPU + Memory Bus)
fn bench_in_memory_parallel_transfer(c: &mut Criterion) {
    let mut group = c.benchmark_group("in_memory_resource_transfer");

    // Legacy GoldSrc BSP resource (e.g. de_inferno.bsp: 6.27 MB)
    let legacy_bsp_size = 6_269_880usize;
    let legacy_bsp_data = vec![0x7Fu8; legacy_bsp_size];

    // Modern FlatWorld FLW resource (e.g. de_inferno_compressed.flw: 26.5 KB)
    let flat_flw_size = 26_496usize;
    let flat_flw_data = vec![0x57u8; flat_flw_size];

    // Baseline: Legacy single-threaded sequential buffer copy (as GoldSrc download / filesystem writes)
    group.bench_function("legacy_goldsrc_bsp_sequential_copy_6mb", |b| {
        let mut target_buf = vec![0u8; legacy_bsp_size];
        b.iter(|| {
            target_buf.copy_from_slice(black_box(&legacy_bsp_data));
            black_box(&target_buf[0]);
        });
    });

    // Stitch-Wire: FlatWorld single-stream
    group.bench_function("flatworld_flw_direct_mount_26kb", |b| {
        let mut target_buf = vec![0u8; flat_flw_size];
        b.iter(|| {
            target_buf.copy_from_slice(black_box(&flat_flw_data));
            black_box(&target_buf[0]);
        });
    });

    // Stitch-Wire: Parallel 4-channel transfer for large packages (6.27 MB partitioned across 4 threads)
    group.bench_function("stitch_wire_parallel_4channel_6mb", |b| {
        let chunk_size = 64 * 1024; // 64 KB chunks
        let partitioner = ChunkPartitioner::new(legacy_bsp_size as u64, chunk_size, 4);
        let total_chunks = partitioner.total_chunks();

        let target_buf = vec![0u8; legacy_bsp_size];

        b.iter(|| {
            // Simulate 4 concurrent network worker threads writing chunks into target sink
            (0..total_chunks).into_par_iter().for_each(|chunk_idx| {
                let desc = partitioner.chunk_desc(chunk_idx, 0).unwrap();
                let start = desc.file_offset as usize;
                let end = start + desc.chunk_len as usize;
                let chunk_slice = &legacy_bsp_data[start..end];

                // In multi-threaded execution, workers write into disjoint slice regions
                // Safety: Each chunk_idx has non-overlapping [start..end] intervals
                unsafe {
                    let dest_ptr = target_buf.as_ptr() as *mut u8;
                    std::ptr::copy_nonoverlapping(
                        chunk_slice.as_ptr(),
                        dest_ptr.add(start),
                        desc.chunk_len as usize,
                    );
                }
            });
            black_box(&target_buf[0]);
        });
    });

    group.finish();
}

// 2. Real Loopback Network Socket Benchmarks (Simulated Network Stack)
fn bench_network_socket_transfer(c: &mut Criterion) {
    let mut group = c.benchmark_group("simulated_network_transfer");
    group.sample_size(20);

    let legacy_bsp_size = 6_269_880usize;
    let legacy_bsp_data = vec![0x7Fu8; legacy_bsp_size];

    let flat_flw_size = 26_496usize;
    let flat_flw_data = vec![0x57u8; flat_flw_size];

    // Legacy GoldSrc: 1 TCP Socket downloading 6.27 MB BSP
    group.bench_function("legacy_network_1_socket_bsp_6mb", |b| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        b.iter(|| {
            let mut client = TcpStream::connect(addr).unwrap();
            let (mut server_stream, _) = listener.accept().unwrap();

            let handle = std::thread::spawn(move || {
                let mut data = vec![0u8; legacy_bsp_size];
                server_stream.read_exact(&mut data).unwrap();
                data.len()
            });

            client.write_all(&legacy_bsp_data).unwrap();
            drop(client);

            handle.join().unwrap();
        });
    });

    // Stitch-Wire: 1 TCP Socket downloading 26.5 KB FlatWorld
    group.bench_function("stitch_wire_1_socket_flw_26kb", |b| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        b.iter(|| {
            let mut client = TcpStream::connect(addr).unwrap();
            let (mut server_stream, _) = listener.accept().unwrap();

            let handle = std::thread::spawn(move || {
                let mut data = vec![0u8; flat_flw_size];
                server_stream.read_exact(&mut data).unwrap();
                data.len()
            });

            client.write_all(&flat_flw_data).unwrap();
            drop(client);

            handle.join().unwrap();
        });
    });

    // Stitch-Wire: 4 Parallel TCP Sockets streaming 26.5 KB FlatWorld chunks concurrently
    group.bench_function("stitch_wire_4_parallel_sockets_flw_26kb", |b| {
        let chunk_size = 8 * 1024; // 8 KB chunks (~4 chunks for 26.5 KB)
        let partitioner = ChunkPartitioner::new(flat_flw_size as u64, chunk_size, 4);
        let total_chunks = partitioner.total_chunks();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        b.iter(|| {
            let mut streams = Vec::new();
            let mut clients = Vec::new();

            for chunk_idx in 0..total_chunks {
                let client = TcpStream::connect(addr).unwrap();
                let (server_stream, _) = listener.accept().unwrap();
                clients.push((client, chunk_idx));
                streams.push(server_stream);
            }

            let server_thread = std::thread::spawn(move || {
                let mut received = 0;
                let mut handles = Vec::new();
                for mut stream in streams {
                    handles.push(std::thread::spawn(move || {
                        let mut buf = vec![0u8; 16 * 1024];
                        stream.read(&mut buf).unwrap()
                    }));
                }
                for h in handles {
                    received += h.join().unwrap();
                }
                received
            });

            // 4 parallel client threads
            clients.into_par_iter().for_each(|(mut client, chunk_idx)| {
                let desc = partitioner.chunk_desc(chunk_idx, 0).unwrap();
                let start = desc.file_offset as usize;
                let end = start + desc.chunk_len as usize;
                client.write_all(&flat_flw_data[start..end]).unwrap();
            });

            let total_received = server_thread.join().unwrap();
            assert_eq!(total_received, flat_flw_size);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_in_memory_parallel_transfer,
    bench_network_socket_transfer
);
criterion_main!(benches);
