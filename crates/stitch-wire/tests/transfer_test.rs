use stitch_wire::{ChunkPartitioner, crc::crc32_castagnoli, transfer_sink::MemoryTransferSink};

#[test]
fn test_parallel_chunk_partition_and_memory_transfer() {
    let total_file_size = 256 * 1024; // 256 KB
    let chunk_size = 64 * 1024; // 64 KB per chunk -> exactly 4 chunks
    let channels = 4; // 4 simultaneous connections/channels

    let partitioner = ChunkPartitioner::new(total_file_size, chunk_size, channels);
    assert_eq!(partitioner.total_chunks(), 4);

    let mut mock_target_file = vec![0u8; total_file_size as usize];
    let mut sink = MemoryTransferSink::new(&mut mock_target_file, partitioner.total_chunks());

    // Generate and send chunks out of order (simulating parallel arrival across sockets)
    let arrival_order = [2, 0, 3, 1];

    for &chunk_idx in &arrival_order {
        let mut desc = partitioner
            .chunk_desc(chunk_idx, 0)
            .expect("Chunk desc missing");
        assert_eq!(desc.channel_id, chunk_idx as u8);

        // Fill chunk with deterministic payload
        let chunk_payload = vec![(chunk_idx + 1) as u8; desc.chunk_len as usize];
        desc.expected_crc32 = crc32_castagnoli(&chunk_payload);

        let completed = sink
            .write_chunk(&desc, &chunk_payload, true)
            .expect("Write chunk failed");
        if chunk_idx == arrival_order[arrival_order.len() - 1] {
            assert!(sink.is_complete());
            assert_eq!(completed, 4);
        }
    }

    // Verify buffer data integrity
    for (i, byte) in mock_target_file.iter().enumerate() {
        let expected_chunk = (i / chunk_size as usize) as u8 + 1;
        assert_eq!(*byte, expected_chunk);
    }
}
