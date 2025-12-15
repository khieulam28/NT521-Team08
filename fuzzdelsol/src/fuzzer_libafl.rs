use crate::evaluator::TransactionEvaluator;
use crate::oracles::{OracleContext, Oracles};
use crate::emulator::BlockchainEmulator;
use crate::txgen::TxGenerator;
use crate::types::{ExecResult, OracleSignals};
use crate::vm_rbpf::TraceVm;
use solana_sdk::pubkey::Pubkey;
use std::fs;
use std::io;
use std::path::Path;

fn mutate_bytes(seed: &[u8], iter: u64) -> Vec<u8> {
    let mut out = seed.to_vec();
    if out.is_empty() {
        out = vec![2, 3, 0, 1, 2, 3, 4, 5];
    }
    let n = (iter as usize % 8) + 1;
    for k in 0..n {
        let i = (iter as usize + k * 13) % out.len();
        out[i] ^= (iter as u8).wrapping_mul(31).wrapping_add(k as u8);
    }
    if (iter % 7) == 0 && out.len() < 256 {
        out.push((iter as u8) ^ 0xAA);
    }
    out
}

fn write_artifact(dir: &str, name_hex: &str, bytes: &[u8]) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    fs::write(format!("{}/{}", dir, name_hex), bytes)?;
    Ok(())
}

pub fn run_fuzzdelsol(iters: u64, elf_path: &str) -> io::Result<()> {
    println!("[*] Fuzzing for {iters} iterations...");
    println!("[*] ELF = {elf_path}");
    println!("[*] crashes_dir = crashes");
    println!("[*] bugs_dir    = bugs");

    let elf_bytes = fs::read(elf_path).unwrap_or_else(|_| vec![]);
    let program_id = Pubkey::new_unique();

    let mut emu = BlockchainEmulator::new();

    let seed = vec![2, 3, 0, 1, 2, 3, 0x10, 0x22, 0x80, 0xFF, 0x7F, 0x01];
    let mut best_cov_hash: u64 = 0;

    let mut executions: u64 = 0;
    let mut new_crash_inputs: u64 = 0;

    for i in 0..iters {
        // ---------- build blockchain snapshot ----------
        let pre_snapshot = emu.build_snapshot(program_id, &elf_bytes);

        // ---------- generate tx ----------
        let input = mutate_bytes(&seed, i);
        let tx = TxGenerator::from_bytes(&input, &emu, program_id);

        // ✅ USE instruction.program_id (fix warning correctly)
        debug_assert_eq!(
            tx.instruction.program_id,
            program_id,
            "Instruction targets wrong program_id"
        );

        // ---------- run VM ----------
        let vm_out = TraceVm::run(program_id, pre_snapshot.clone(), &tx);

        let mut signals = OracleSignals {
            msc: false,
            moc: false,
            acpi: false,
            mkc: false,
            ib: false,
            lamports_theft: false,
        };

        let ctx = OracleContext {
            program_id,
            attacker: emu.attacker,
            user: emu.user,
        };

        let mut oracles = Oracles::new(ctx, &pre_snapshot);

        for ev in vm_out.events.clone() {
            oracles.process_event(
                &tx,
                &vm_out.taint,
                &pre_snapshot,
                &vm_out.post_snapshot,
                ev,
                &mut signals,
            );
        }

        // finalize oracle decisions (paper-style)
        oracles.finalize(&tx, &pre_snapshot, &vm_out.post_snapshot, &mut signals);

        let exec = ExecResult {
            coverage: vm_out.coverage,
            signals: signals.clone(),
            semantics: Default::default(),
            tx: tx.clone(),
            pre_snapshot: pre_snapshot.clone(),
            post_snapshot: vm_out.post_snapshot.clone(),
            trace_summary: vm_out.trace_summary.clone(),
        };

        let out = TransactionEvaluator::evaluate(&exec, &mut best_cov_hash);

        if out.is_objective {
            new_crash_inputs += 1;
            let name = format!("{:016x}", exec.coverage.hash16());
            let dir = if signals.lamports_theft { "crashes" } else { "bugs" };
            write_artifact(dir, &name, &input)?;

            if let Some(r) = out.report {
                let rep_path = format!("{}/{}.report.txt", dir, name);
                fs::write(
                    rep_path,
                    format!(
                        "Vulnerability Class: {}\n\nTX Payload (hex): {}\n\n=== Global State BEFORE ===\n{}\n\n=== Global State AFTER ===\n{}\n\nTrace:\n{}\n",
                        r.vuln_class,
                        r.tx_payload_hex,
                        r.global_state_before,
                        r.global_state_after,
                        r.trace_summary
                    ),
                )?;
            }

            println!(
                "[Objective:new] {} cov_hash={:016x}",
                signals.class(),
                exec.coverage.hash16()
            );
        }

        // semantic feedback loop (paper-lite)
        emu.update_semantics(&out.semantics);

        executions += 1;
        if (i + 1) % 1000 == 0 || out.is_objective {
            println!(
                "[*] iter={}/{} exec={} best_cov_hash={:016x} objective={}",
                i + 1,
                iters,
                executions,
                best_cov_hash,
                out.is_objective
            );
        }
    }

    println!("\n================ SUMMARY ================");
    println!("iters requested  : {iters}");
    println!("executions       : {executions}");
    println!("new crash inputs : {new_crash_inputs}");
    if Path::new("crashes").exists() {
        println!("crashes/ written");
    }
    if Path::new("bugs").exists() {
        println!("bugs/ written");
    }
    println!("========================================");
    Ok(())
}
