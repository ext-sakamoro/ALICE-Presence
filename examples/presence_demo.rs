//! ALICE-Presence demo — 2 者間 encounter + 3 者 group proximity
//!
//! 実行: `cargo run --example presence_demo`

use alice_presence::{
    execute_presence_protocol, GroupConfig, PartyInfo, PresenceConfig, PresenceGroup, VivaldiCoord,
};

fn banner(title: &str) {
    println!("\n──── {title} ────");
}

fn main() {
    let cfg = PresenceConfig::default();
    println!(
        "PresenceConfig: threshold={}, challenge_bits={}, require_mutual={}",
        cfg.proximity_threshold, cfg.challenge_bits, cfg.require_mutual
    );

    let alice = PartyInfo::new(VivaldiCoord::new(0.0, 0.0), 0xA11CE_5EC, 1);
    let bob = PartyInfo::new(VivaldiCoord::new(3.0, 4.0), 0xB0B_5EC, 2);
    let charlie = PartyInfo::new(VivaldiCoord::new(80.0, 80.0), 0xC4A_5EC, 3);

    let ts_ns: u64 = 1_723_000_000_000_000_000;

    banner("Case 1: Alice ↔ Bob (近接 = 距離 5.0 ≤ 10.0)");
    match execute_presence_protocol(&alice, &bob, ts_ns, &cfg) {
        Some(rec) => {
            let ev_bytes = rec.event.to_bytes();
            println!(
                "distance         = {:.4}  (threshold {})",
                rec.proximity.distance, rec.proximity.threshold
            );
            println!(
                "is_proximate     = {}",
                rec.proximity.is_proximate
            );
            println!(
                "coord_hash_a     = 0x{:016x}",
                rec.proximity.coord_hash_a
            );
            println!(
                "coord_hash_b     = 0x{:016x}",
                rec.proximity.coord_hash_b
            );
            println!("proof_a.verified = {}", rec.proof_a.verified);
            println!("proof_b.verified = {}", rec.proof_b.verified);
            println!(
                "event.flags      = 0b{:08b}  (mutual={}, verified={}, proximate={})",
                rec.event.flags,
                rec.event.is_mutual(),
                rec.event.is_verified(),
                rec.event.is_proximate()
            );
            println!("18-byte wire     = {ev_bytes:02x?}");
            println!("record content_hash = 0x{:016x}", rec.content_hash);
            println!("is_fully_verified = {}", rec.is_fully_verified());
            println!("status           = {:?}", rec.status());
        }
        None => println!("(NOT proximate — 記録なし)"),
    }

    banner("Case 2: Alice ↔ Charlie (遠い = 距離 ≈113 > 10.0)");
    match execute_presence_protocol(&alice, &charlie, ts_ns, &cfg) {
        Some(_) => println!("(想定外: 近接判定通過)"),
        None => println!("proximity 未達 → CrossingRecord は None (= 出会いなし)"),
    }

    banner("Case 3: 3-party group proximity (Alice, Bob, Dora)");
    let mut group = PresenceGroup::new(GroupConfig {
        proximity_threshold: 10.0,
        min_members: 2,
    });
    group.add_member(alice.id, alice.coord, ts_ns);
    group.add_member(bob.id, bob.coord, ts_ns);
    group.add_member(4, VivaldiCoord::new(6.0, 0.0), ts_ns);

    println!("member_count  = {}", group.member_count());
    println!("member_ids    = {:?}", group.member_ids());
    println!("max_pairwise  = {:.4}", group.max_pairwise_distance());
    println!("all_proximate = {}", group.is_all_proximate());

    if let Some(gp) = group.prove_proximity() {
        println!(
            "GroupProof: group_id=0x{:016x}, members={}, max_dist={:.4}, all_proximate={}, content_hash=0x{:016x}",
            gp.group_id, gp.member_count, gp.max_distance, gp.all_proximate, gp.content_hash
        );
    }

    banner("Case 4: 群に遠い Charlie を追加 → all_proximate 崩壊");
    group.add_member(charlie.id, charlie.coord, ts_ns);
    println!("member_count  = {}", group.member_count());
    println!("max_pairwise  = {:.4}", group.max_pairwise_distance());
    println!("all_proximate = {}", group.is_all_proximate());
    if let Some(gp) = group.prove_proximity() {
        println!(
            "GroupProof: all_proximate={} (max_dist {:.4} > threshold {})",
            gp.all_proximate, gp.max_distance, gp.threshold
        );
    }
}
