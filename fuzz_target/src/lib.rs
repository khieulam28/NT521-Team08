use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    program::{invoke_signed},
    pubkey::Pubkey,
    system_instruction,
    system_program,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    input: &[u8],
) -> ProgramResult {
    if input.len() < 9 {
        return Ok(());
    }

    let opcode = input[0];
    let amount = u64::from_le_bytes(input[1..9].try_into().unwrap());

    let mut it = accounts.iter();
    let vault = next_account_info(&mut it)?;
    let authority = next_account_info(&mut it)?;
    let sys = next_account_info(&mut it)?;

    if *sys.key != system_program::id() {
        return Ok(());
    }

    match opcode {
        0 => {
            // BUG: missing_signer (không check authority.is_signer)
            **vault.try_borrow_mut_lamports()? = vault.lamports().wrapping_sub(amount);
            **authority.try_borrow_mut_lamports()? = authority.lamports().wrapping_add(amount);
        }

        1 => {
            // BUG: missing_owner (không check vault.owner == program_id)
            **vault.try_borrow_mut_lamports()? = vault.lamports().wrapping_sub(amount);
            **authority.try_borrow_mut_lamports()? = authority.lamports().wrapping_add(amount);
        }

        2 => {
            // BUG: missing_key (kỳ vọng vault là PDA nhưng không verify vault.key)
            let (_expected_vault, _bump) = Pubkey::find_program_address(
                &[b"vault", authority.key.as_ref()],
                program_id,
            );

            **vault.try_borrow_mut_lamports()? = vault.lamports().wrapping_sub(amount);
            **authority.try_borrow_mut_lamports()? = authority.lamports().wrapping_add(amount);
        }

        3 => {
            // BUG: integer_bug (underflow/overflow logic)
            let v = vault.lamports().wrapping_sub(amount.wrapping_add(1));
            let a = authority.lamports().wrapping_add(amount.wrapping_add(1));
            **vault.try_borrow_mut_lamports()? = v;
            **authority.try_borrow_mut_lamports()? = a;
        }

        4 => {
            // BUG: cpi_bug (CPI misuse)
            // - invoke_signed nhưng seeds không liên quan vault/authority đúng cách
            // - gọi system_program::transfer với from=vault (thường phải signer)
            let ix = system_instruction::transfer(vault.key, authority.key, amount);

            let fake_bump = input[8];
            let seeds: &[&[u8]] = &[b"not_the_vault", authority.key.as_ref(), &[fake_bump]];

            let _ = invoke_signed(&ix, &[vault.clone(), authority.clone(), sys.clone()], &[seeds]);
        }

        5 => {
            // BUG: ebpf_crash
            panic!("fuzz crash opcode=5");
        }

        _ => {}
    }

    Ok(())
}
