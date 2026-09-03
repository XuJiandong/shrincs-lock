use ckb_hash::Blake2bBuilder;
use ckb_testtool::{
    ckb_types::{
        bytes::Bytes,
        core::{TransactionBuilder, TransactionView},
        packed::{self, *},
        prelude::*,
    },
    context::Context,
};

use shrincs::{PublicKey, SHRINCS_B, SecretKey, State, key_gen, sign_stateful, sign_stateless};

const MAX_CYCLES: u64 = 100_000_000;
// CKB_TX_MESSAGE_ALL blake2b personalization used by the shrincs-lock contract.
const MSG_PERSONALIZATION: &[u8] = b"ckb-shrincs-msg-";

/// Compute the CKB_TX_MESSAGE_ALL signing message exactly as the contract does,
/// but on the native platform. `input_cells` is the list of `(cell_output, data)`
/// for each transaction input, in input order. `witnesses` is the transaction's
/// full witness list (raw bytes).
fn ckb_tx_message_all(
    tx: &TransactionView,
    input_cells: &[(CellOutput, Bytes)],
    witnesses: &[Bytes],
) -> [u8; 32] {
    let mut hasher = Blake2bBuilder::new(32)
        .personal(MSG_PERSONALIZATION)
        .build();

    // 1. tx hash
    let tx_hash = tx.hash();
    hasher.update(&tx_hash.raw_data());

    // 2. contents of all input cells.
    for (cell_output, data) in input_cells {
        hasher.update(cell_output.as_slice());
        let len = data.len() as u32;
        hasher.update(&len.to_le_bytes());
        hasher.update(data);
    }

    // 3. first witness of the current script group: input_type + output_type.
    //    In these tests the first (and only) witness carries no input/output
    //    type, so both lengths are zero.
    let first_witness = WitnessArgsReader::from_slice(&witnesses[0]).expect("valid witness args");
    let input_type = first_witness.input_type().as_slice();
    let output_type = first_witness.output_type().as_slice();
    let len = input_type.len() as u32;
    hasher.update(&len.to_le_bytes());
    hasher.update(input_type);
    let len = output_type.len() as u32;
    hasher.update(&len.to_le_bytes());
    hasher.update(output_type);

    // 4. remaining witnesses in the current script group (skip the first).
    //    With a single input there are none.
    // 5. witnesses without matching input cells.
    for witness in witnesses.iter().skip(tx.inputs().len()) {
        let len = witness.len() as u32;
        hasher.update(&len.to_le_bytes());
        hasher.update(witness);
    }

    let mut result = [0u8; 32];
    hasher.finalize(&mut result);
    result
}

/// Compute the CKB_TX_MESSAGE_ALL signing message for `tx`, on the native side.
fn tx_message(context: &Context, tx: &TransactionView) -> ([u8; 32], Vec<Bytes>) {
    // Gather the input cells (output + data) in input order.
    let input_cells: Vec<(CellOutput, Bytes)> = tx
        .inputs()
        .into_iter()
        .map(|input| {
            context
                .get_cell(&input.previous_output())
                .expect("get input cell")
        })
        .collect();

    // The transaction currently has no witness; give it a single empty
    // WitnessArgs so the wire layout matches what the contract loads.
    let witnesses: Vec<Bytes> = tx.witnesses().into_iter().map(|w| w.raw_data()).collect();
    let witnesses = if witnesses.is_empty() {
        vec![WitnessArgs::default().as_bytes()]
    } else {
        witnesses
    };

    let message = ckb_tx_message_all(tx, &input_cells, &witnesses);
    (message, witnesses)
}

/// Insert an already-produced SHRINCS `signature` into the transaction's first
/// witness `lock` field and return the signed tx.
fn build_signed_tx(
    tx: TransactionView,
    signature: Vec<u8>,
    witnesses: Vec<Bytes>,
) -> TransactionView {
    let witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(signature)).pack())
        .build();
    let mut signed_witnesses: Vec<packed::Bytes> = vec![witness.as_bytes().pack()];
    signed_witnesses.extend(witnesses.into_iter().skip(1).map(|w| w.pack()));

    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

/// Sign a transaction with a **stateless** signature and return the signed tx.
fn sign_tx_stateless(context: &Context, tx: TransactionView, sk: &SecretKey) -> TransactionView {
    let (message, witnesses) = tx_message(context, &tx);
    let signature = sign_stateless::<SHRINCS_B>(&message, sk).expect("stateless sign");
    build_signed_tx(tx, signature, witnesses)
}

/// Sign a transaction with a **stateful** signature and return the signed tx.
///
/// `state` is advanced by one step, so callers can sign multiple transactions
/// in sequence.
fn sign_tx_stateful(
    context: &Context,
    tx: TransactionView,
    sk: &mut SecretKey,
    state: &mut State,
) -> TransactionView {
    let (message, witnesses) = tx_message(context, &tx);
    let signature = sign_stateful::<SHRINCS_B>(&message, sk, state).expect("stateful sign");
    build_signed_tx(tx, signature, witnesses)
}

/// Serialize a SHRINCS public key into the 32-byte script args layout
/// (16-byte `seed` ‖ 16-byte `root`).
fn serialize_pk(pk: &PublicKey) -> [u8; 32] {
    let mut pk_bytes = [0u8; 32];
    pk_bytes[..16].copy_from_slice(&pk.seed);
    pk_bytes[16..].copy_from_slice(&pk.root);
    pk_bytes
}

/// Deploy the contract and build a complete, unsigned one-input / one-output
/// transaction whose input cell is locked by a lock script carrying `args`.
/// Returns the context alongside the transaction (the context must outlive the
/// tx's input cells).
fn build_unlock_tx(args: Bytes) -> (Context, TransactionView) {
    let mut context = Context::default();
    let out_point = context.deploy_cell_by_name("shrincs-lock");
    let lock_script = context.build_script(&out_point, args).expect("script");

    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let output = CellOutput::new_builder()
        .capacity(1000)
        .lock(lock_script)
        .build();

    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(Bytes::new())
        .build();
    let tx = context.complete_tx(tx);

    (context, tx)
}

#[test]
fn test_shrincs_lock_unlock() {
    // Generate a SHRINCS key pair.
    let mut pk = PublicKey::default();
    let mut sk = SecretKey::default();
    let mut state = State::default();
    key_gen::<SHRINCS_B>(&mut pk, &mut sk, &mut state).expect("key gen");
    // Serialize the 32-byte public key (seed ‖ root) into script args.
    let mut pk_bytes = [0u8; 32];
    pk_bytes[..16].copy_from_slice(&pk.seed);
    pk_bytes[16..].copy_from_slice(&pk.root);

    // Deploy contract.
    let mut context = Context::default();
    let out_point = context.deploy_cell_by_name("shrincs-lock");

    // Prepare scripts.
    let lock_script = context
        .build_script(&out_point, Bytes::from(pk_bytes.to_vec()))
        .expect("script");

    // Prepare cells.
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(500)
            .lock(lock_script.clone())
            .build(),
        CellOutput::new_builder()
            .capacity(500)
            .lock(lock_script)
            .build(),
    ];
    let outputs_data = vec![Bytes::new(); 2];

    // Build transaction.
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();
    let tx = context.complete_tx(tx);

    // Sign the transaction.
    let tx = sign_tx_stateless(&context, tx, &sk);

    // Run.
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {:.1} million", cycles as f64 / 1_000_000.0);
}

/// Sign multiple transactions **statelessly** with the same key and verify each
/// unlocks. Stateless signing requires no state and always produces the same
/// fixed-size signature, which the contract dispatches to `verify_stateless`.
#[test]
fn test_shrincs_lock_stateless() {
    // Generate a SHRINCS key pair.
    let mut pk = PublicKey::default();
    let mut sk = SecretKey::default();
    let mut state = State::default();
    key_gen::<SHRINCS_B>(&mut pk, &mut sk, &mut state).expect("key gen");

    // Serialize the 32-byte public key (seed ‖ root) into script args.
    let mut pk_bytes = [0u8; 32];
    pk_bytes[..16].copy_from_slice(&pk.seed);
    pk_bytes[16..].copy_from_slice(&pk.root);

    // Deploy contract.
    let mut context = Context::default();
    let out_point = context.deploy_cell_by_name("shrincs-lock");

    let lock_script = context
        .build_script(&out_point, Bytes::from(pk_bytes.to_vec()))
        .expect("script");

    // Sign several transactions with one key; each message differs (distinct
    // tx hashes), so each signature is exercised independently.
    for _ in 0..3 {
        let input_out_point = context.create_cell(
            CellOutput::new_builder()
                .capacity(1000)
                .lock(lock_script.clone())
                .build(),
            Bytes::new(),
        );
        let input = CellInput::new_builder()
            .previous_output(input_out_point)
            .build();
        let output = CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .build();

        let tx = TransactionBuilder::default()
            .input(input)
            .output(output)
            .output_data(Bytes::new())
            .build();
        let tx = context.complete_tx(tx);

        let tx = sign_tx_stateless(&context, tx, &sk);

        // A stateless signature has exactly the fixed `SL_SIZE` length, which
        // exceeds `MAX_SF_SIZE` and thus dispatches to `verify_stateless`.
        let witness = tx.witnesses().get(0).expect("witness").raw_data();
        let witness_args = WitnessArgsReader::from_slice(&witness).expect("witness args");
        let signature = witness_args.lock().to_opt().expect("signature").raw_data();
        assert_eq!(signature.len(), <SHRINCS_B as shrincs::Params>::SL_SIZE);
        assert!(signature.len() > <SHRINCS_B as shrincs::Params>::MAX_SF_SIZE);

        let cycles = context
            .verify_tx(&tx, MAX_CYCLES)
            .expect("pass stateless verification");
        println!("consume cycles: {:.1} million", cycles as f64 / 1_000_000.0);
    }
}

/// Sign a transaction statefully and verify it unlocks. Also verifies that
/// stateful signing advances `state.q` and, because each transaction is
/// signed with a distinct message, that two sequential stateful signatures
/// over the same key both unlock their own transactions.
#[test]
fn test_shrincs_lock_stateful() {
    // Generate a SHRINCS key pair.
    let mut pk = PublicKey::default();
    let mut sk = SecretKey::default();
    let mut state = State::default();
    key_gen::<SHRINCS_B>(&mut pk, &mut sk, &mut state).expect("key gen");

    // Serialize the 32-byte public key (seed ‖ root) into script args.
    let mut pk_bytes = [0u8; 32];
    pk_bytes[..16].copy_from_slice(&pk.seed);
    pk_bytes[16..].copy_from_slice(&pk.root);

    // Deploy contract.
    let mut context = Context::default();
    let out_point = context.deploy_cell_by_name("shrincs-lock");

    // Prepare the lock script.
    let lock_script = context
        .build_script(&out_point, Bytes::from(pk_bytes.to_vec()))
        .expect("script");

    // Fresh state from key_gen has `q == 0` and `valid == true`.
    assert!(state.valid);
    assert_eq!(state.q, 0);

    // Sign three sequential transactions, advancing the stateful counter each
    // time. Each message differs (distinct tx hashes), so each signature is
    // exercised independently.
    for expected_q in 1..=3u32 {
        // Prepare the input cell spending the lock script.
        let input_out_point = context.create_cell(
            CellOutput::new_builder()
                .capacity(1000)
                .lock(lock_script.clone())
                .build(),
            Bytes::new(),
        );
        let input = CellInput::new_builder()
            .previous_output(input_out_point)
            .build();
        let output = CellOutput::new_builder()
            .capacity(1000)
            .lock(lock_script.clone())
            .build();
        let output_data = Bytes::new();

        let tx = TransactionBuilder::default()
            .input(input)
            .output(output)
            .output_data(output_data)
            .build();
        let tx = context.complete_tx(tx);

        // Stateful signing advances `state.q` by one.
        let tx = sign_tx_stateful(&context, tx, &mut sk, &mut state);
        assert_eq!(state.q, expected_q);

        // The stateful signature must be within the stateful size budget so the
        // contract's length-based dispatch routes it to `verify_stateful`.
        let witness = tx.witnesses().get(0).expect("witness").raw_data();
        let witness_args = WitnessArgsReader::from_slice(&witness).expect("witness args");
        let signature = witness_args.lock().to_opt().expect("signature").raw_data();
        assert!(signature.len() <= <SHRINCS_B as shrincs::Params>::MAX_SF_SIZE);
        assert!(!signature.is_empty());

        // Run; must pass verification.
        let cycles = context
            .verify_tx(&tx, MAX_CYCLES)
            .expect("pass stateful verification");
        println!("consume cycles: {:.1} million", cycles as f64 / 1_000_000.0);
    }
}

/// Signing with a state that has `valid == false` must fail with
/// [`shrincs::shrincs::Error::InvalidState`], and the counter must not advance.
#[test]
fn test_shrincs_lock_stateful_invalid_state() {
    let mut pk = PublicKey::default();
    let mut sk = SecretKey::default();
    let mut state = State::default();
    key_gen::<SHRINCS_B>(&mut pk, &mut sk, &mut state).expect("key gen");

    // Mark the state invalid (e.g. as after a non-atomic state write during
    // backup), which is exactly the condition `sign_stateful` guards against.
    state.valid = false;
    let q_before = state.q;

    let result = sign_stateful::<SHRINCS_B>(&[0u8; 32], &mut sk, &mut state);
    assert_eq!(result, Err(shrincs::shrincs::Error::InvalidState));
    assert_eq!(state.q, q_before);
}

#[test]
fn test_shrincs_lock_wrong_message_stateless() {
    // Generate a SHRINCS key pair.
    let mut pk = PublicKey::default();
    let mut sk = SecretKey::default();
    let mut state = State::default();
    key_gen::<SHRINCS_B>(&mut pk, &mut sk, &mut state).expect("key gen");

    let (context, tx) = build_unlock_tx(Bytes::from(serialize_pk(&pk).to_vec()));

    // Sign a DIFFERENT (wrong) message, so verification must fail.
    let wrong_message = [0xABu8; 32];
    let signature = sign_stateless::<SHRINCS_B>(&wrong_message, &sk).expect("sign");
    let (_, witnesses) = tx_message(&context, &tx);
    let tx = build_signed_tx(tx, signature, witnesses);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[test]
fn test_shrincs_lock_wrong_message_stateful() {
    let mut pk = PublicKey::default();
    let mut sk = SecretKey::default();
    let mut state = State::default();
    key_gen::<SHRINCS_B>(&mut pk, &mut sk, &mut state).expect("key gen");

    let (context, tx) = build_unlock_tx(Bytes::from(serialize_pk(&pk).to_vec()));

    // Sign a DIFFERENT (wrong) message with a stateful signature, so
    // verification must fail.
    let wrong_message = [0xABu8; 32];
    let signature = sign_stateful::<SHRINCS_B>(&wrong_message, &mut sk, &mut state).expect("sign");
    let (_, witnesses) = tx_message(&context, &tx);
    let tx = build_signed_tx(tx, signature, witnesses);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[test]
fn test_shrincs_lock_wrong_pubkey_stateless() {
    let mut pk = PublicKey::default();
    let mut sk = SecretKey::default();
    let mut state = State::default();
    key_gen::<SHRINCS_B>(&mut pk, &mut sk, &mut state).expect("key gen");

    // A different, unrelated public key placed in the script args.
    let mut other_pk = PublicKey::default();
    let mut other_sk = SecretKey::default();
    let mut other_state = State::default();
    key_gen::<SHRINCS_B>(&mut other_pk, &mut other_sk, &mut other_state).expect("key gen");

    let (context, tx) = build_unlock_tx(Bytes::from(serialize_pk(&other_pk).to_vec()));

    // Script args carry `other_pk`, but we sign with `sk` (whose pk is `pk`),
    // so verification must fail.
    let tx = sign_tx_stateless(&context, tx, &sk);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}

#[test]
fn test_shrincs_lock_wrong_pubkey_stateful() {
    let mut pk = PublicKey::default();
    let mut sk = SecretKey::default();
    let mut state = State::default();
    key_gen::<SHRINCS_B>(&mut pk, &mut sk, &mut state).expect("key gen");

    // A different, unrelated public key placed in the script args.
    let mut other_pk = PublicKey::default();
    let mut other_sk = SecretKey::default();
    let mut other_state = State::default();
    key_gen::<SHRINCS_B>(&mut other_pk, &mut other_sk, &mut other_state).expect("key gen");

    let (context, tx) = build_unlock_tx(Bytes::from(serialize_pk(&other_pk).to_vec()));

    // Sign with `sk` (whose pk is `pk`), but the script args carry `other_pk`,
    // so verification must fail.
    let tx = sign_tx_stateful(&context, tx, &mut sk, &mut state);

    assert!(context.verify_tx(&tx, MAX_CYCLES).is_err());
}
