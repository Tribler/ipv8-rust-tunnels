use std::sync::atomic::AtomicU64;

use _rust::crypto::cipher::{Direction, SessionKeys, WINDOW_SIZE};

fn dummy_keys_with_seed(seed: u8) -> SessionKeys {
    SessionKeys {
        key_forward: vec![seed; 32],
        key_backward: vec![seed.wrapping_add(1); 32],
        salt_forward: vec![seed.wrapping_add(2); 4],
        salt_backward: vec![seed.wrapping_add(3); 4],
        salt_explicit_forward: AtomicU64::new(0),
        salt_explicit_backward: AtomicU64::new(0),
        ..Default::default()
    }
}

#[test]
fn test_encrypt_decrypt_forward_and_backward() {
    let client = dummy_keys_with_seed(0x10);
    let relay = dummy_keys_with_seed(0x10);

    // Forward direction
    let msg_fwd = b"forward data".to_vec();
    let mut buf_fwd = msg_fwd.clone();
    client.encrypt_in_place(&mut buf_fwd, Direction::Forward).unwrap();
    assert_eq!(buf_fwd.len(), msg_fwd.len() + 24); // 8-byte counter + 16-byte tag

    relay.decrypt_in_place(&mut buf_fwd, Direction::Forward).unwrap();
    assert_eq!(buf_fwd, msg_fwd);

    // Backward direction
    let msg_bwd = b"backward data".to_vec();
    let mut buf_bwd = msg_bwd.clone();
    relay.encrypt_in_place(&mut buf_bwd, Direction::Backward).unwrap();
    assert_eq!(buf_bwd.len(), msg_bwd.len() + 24);

    client.decrypt_in_place(&mut buf_bwd, Direction::Backward).unwrap();
    assert_eq!(buf_bwd, msg_bwd);
}

#[test]
fn test_multi_hop_onion_routing() {
    let client_hop1 = dummy_keys_with_seed(0x10);
    let client_hop2 = dummy_keys_with_seed(0x20);
    let client_hop3 = dummy_keys_with_seed(0x30);

    let relay1 = dummy_keys_with_seed(0x10);
    let relay2 = dummy_keys_with_seed(0x20);
    let relay3 = dummy_keys_with_seed(0x30);

    let secret_payload = b"secret payload".to_vec();
    let mut packet = secret_payload.clone();

    // Add union layers
    client_hop3.encrypt_in_place(&mut packet, Direction::Forward).unwrap();
    client_hop2.encrypt_in_place(&mut packet, Direction::Forward).unwrap();
    client_hop1.encrypt_in_place(&mut packet, Direction::Forward).unwrap();
    assert_eq!(packet.len(), secret_payload.len() + (24 * 3));

    relay1.decrypt_in_place(&mut packet, Direction::Forward).unwrap();
    assert_ne!(packet, secret_payload);

    relay2.decrypt_in_place(&mut packet, Direction::Forward).unwrap();
    assert_ne!(packet, secret_payload);

    relay3.decrypt_in_place(&mut packet, Direction::Forward).unwrap();
    assert_eq!(packet, secret_payload);
}

#[test]
fn test_empty_payload() {
    let client = dummy_keys_with_seed(0x50);
    let relay = dummy_keys_with_seed(0x50);

    let mut packet = Vec::new();
    client.encrypt_in_place(&mut packet, Direction::Forward).unwrap();
    // Only 8-byte counter + 16-byte tag
    assert_eq!(packet.len(), 24);

    relay.decrypt_in_place(&mut packet, Direction::Forward).unwrap();
    assert!(packet.is_empty());
}

#[test]
fn test_invalid_and_corrupted_packets() {
    let client = dummy_keys_with_seed(0x60);
    let relay = dummy_keys_with_seed(0x60);

    // Packet too short (< 24 bytes)
    let mut short_buf = vec![0u8; 23];
    assert_eq!(relay.decrypt_in_place(&mut short_buf, Direction::Forward).unwrap_err(), "Content too short");

    // Wrong direction
    let mut wrong_dir_pkt = b"secret payload".to_vec();
    client.encrypt_in_place(&mut wrong_dir_pkt, Direction::Forward).unwrap();
    assert_eq!(
        relay.decrypt_in_place(&mut wrong_dir_pkt, Direction::Backward).unwrap_err(),
        "AEAD integrity check failed"
    );

    // Corrupted packet
    let mut corrupted_pkt = b"secret payload".to_vec();
    client.encrypt_in_place(&mut corrupted_pkt, Direction::Forward).unwrap();
    *corrupted_pkt.get_mut(10).unwrap() ^= 0xFF;
    assert_eq!(
        relay.decrypt_in_place(&mut corrupted_pkt, Direction::Forward).unwrap_err(),
        "AEAD integrity check failed"
    );
}

#[test]
fn test_replay_rejection() {
    let client = dummy_keys_with_seed(0x70);
    let relay = dummy_keys_with_seed(0x70);

    let original = b"secret payload".to_vec();
    let mut packet = original.clone();

    client.encrypt_in_place(&mut packet, Direction::Forward).unwrap();
    let mut replay = packet.clone();

    relay.decrypt_in_place(&mut packet, Direction::Forward).unwrap();
    assert_eq!(packet, original);

    // Replaying the same packet is rejected
    assert_eq!(
        relay.decrypt_in_place(&mut replay, Direction::Forward).unwrap_err(),
        "Replay/old packet detected"
    );
}

#[test]
fn test_out_of_order_packets() {
    let client = dummy_keys_with_seed(0x80);
    let relay = dummy_keys_with_seed(0x80);

    // Create 5 sequential packets
    let mut packets = Vec::new();
    for i in 1..=5u8 {
        let mut buf = vec![i; 64];
        client.encrypt_in_place(&mut buf, Direction::Forward).unwrap();
        packets.push((i, buf));
    }

    // Receive them out of order
    let order = vec![4, 1, 3, 0, 2];
    for idx in order {
        let (expected_byte, mut pkt) = packets.get(idx).unwrap().clone();
        relay.decrypt_in_place(&mut pkt, Direction::Forward).unwrap();
        assert_eq!(pkt, vec![expected_byte; 64]);
    }

    // All 5 have been processed, re-sending should fail
    for (_, mut pkt) in packets {
        assert!(relay.decrypt_in_place(&mut pkt, Direction::Forward).is_err());
    }
}

#[test]
fn test_reject_packet_outside_window() {
    let client = dummy_keys_with_seed(0x90);
    let relay = dummy_keys_with_seed(0x90);

    let mut old_packet = b"packet 1".to_vec();
    client.encrypt_in_place(&mut old_packet, Direction::Forward).unwrap();

    // Send and process WINDOW_SIZE+1 newer packets
    for _ in 2..=(WINDOW_SIZE + 1) {
        let mut buf = b"newer".to_vec();
        client.encrypt_in_place(&mut buf, Direction::Forward).unwrap();
        relay.decrypt_in_place(&mut buf, Direction::Forward).unwrap();
    }

    // First packet is outside the sliding window and should fail
    assert_eq!(
        relay.decrypt_in_place(&mut old_packet, Direction::Forward).unwrap_err(),
        "Replay/old packet detected"
    );
}

#[test]
fn test_corrupt_counter_does_not_shift_window() {
    let client = dummy_keys_with_seed(0xA0);
    let relay = dummy_keys_with_seed(0xA0);

    let mut valid_pkt = b"legit".to_vec();
    client.encrypt_in_place(&mut valid_pkt, Direction::Forward).unwrap();

    // We get a forged packet with a much larger counter
    let mut forged_pkt = valid_pkt.clone();
    forged_pkt[..8].copy_from_slice(&999_999u64.to_be_bytes());
    assert!(relay.decrypt_in_place(&mut forged_pkt, Direction::Forward).is_err());

    // Check that the sliding window isn't affected by forged packet
    relay.decrypt_in_place(&mut valid_pkt, Direction::Forward).unwrap();
    assert_eq!(valid_pkt, b"legit");
}

#[test]
fn test_clone_and_debug_traits() {
    let keys = dummy_keys_with_seed(0xB0);
    let cloned = keys.clone();

    let debug_str = format!("{:?}", cloned);
    assert!(debug_str.contains("SessionKeys"));
    assert_eq!(cloned.key_forward, keys.key_forward);
}
