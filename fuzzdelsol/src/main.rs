mod fuzzer_libafl;
mod vm_rbpf;

mod types;
mod emulator;
mod txgen;
mod oracles;
mod evaluator;

use std::io::{self, Write};

fn main() {
    println!("=== FuzzDelSol-Lite (paper-aligned, 6 oracles) ===");

    print!("Nhập đường dẫn ELF .so (vd: /home/solana/fuzz_target/target/deploy/fuzz_target.so): ");
    io::stdout().flush().unwrap();
    let mut elf_path = String::new();
    io::stdin().read_line(&mut elf_path).unwrap();
    let elf_path = elf_path.trim().to_string();

    print!("Nhập số lần fuzzing (iters, ví dụ 10000): ");
    io::stdout().flush().unwrap();
    let mut s = String::new();
    io::stdin().read_line(&mut s).unwrap();
    let iters: u64 = s.trim().parse().unwrap_or(10_000);

    if let Err(e) = fuzzer_libafl::run_fuzzdelsol(iters, &elf_path) {
        eprintln!("Error: {e:?}");
    }
}
