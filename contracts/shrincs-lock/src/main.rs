#![cfg_attr(not(any(feature = "library", test)), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(any(feature = "library", test))]
extern crate alloc;

#[cfg(not(any(feature = "library", test)))]
ckb_std::entry!(program_entry);
#[cfg(not(any(feature = "library", test)))]
ckb_std::default_alloc!(16384, 1258306, 64);

use ckb_hash::{Blake2b, Blake2bBuilder};
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{packed::WitnessArgsReader, prelude::*},
    error::SysError,
    high_level::{self, QueryIter},
    syscalls,
};
use shrincs::{PublicKey, SHRINCS_B, verify as shrincs_verify};

// CKB_TX_MESSAGE_ALL uses blake2b (32-byte digest) with this personalization.
const MSG_PERSONALIZATION: &[u8] = b"ckb-shrincs-msg-";

/// Error codes returned by this lock script.
#[repr(i8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Syscall = 71,
    WitnessParse,
    SignatureMissing,
    PubkeyLength,
    CkbTxMessageAll,
    ShrincsVerify,
}

impl From<Error> for i8 {
    fn from(e: Error) -> i8 {
        e as i8
    }
}

/// A blake2b hasher for the CKB_TX_MESSAGE_ALL signing message.
pub struct MessageHasher(Blake2b);

impl MessageHasher {
    pub fn new() -> Self {
        let hasher = Blake2bBuilder::new(32)
            .personal(MSG_PERSONALIZATION)
            .build();
        MessageHasher(hasher)
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        let mut result = [0u8; 32];
        self.0.finalize(&mut result);
        result
    }
}

/// Compute the CKB_TX_MESSAGE_ALL signing message (RFC 446) using blake2b as
/// the underlying hash function. The first witness of the current script group
/// is handled specially: its `lock` field (which carries the signature) is
/// excluded from the message, but its `input_type` and `output_type` fields
/// still participate.
///
/// Algorithm (see https://github.com/nervosnetwork/rfcs/pull/446:
///   1. tx hash
///   2. for each input cell: cell output ‖ length(data) ‖ data
///   3. first witness of current group: length(input_type) ‖ input_type ‖
///      length(output_type) ‖ output_type  (lock field deliberately excluded)
///   4. remaining witnesses in current group: length ‖ witness
///   5. witnesses without matching input cells: length ‖ witness
pub fn generate_ckb_tx_message_all(
    hasher: &mut MessageHasher,
    first_witness_data: &[u8],
) -> Result<(), Error> {
    // Validates that the first witness has a valid WitnessArgs structure.
    let first_witness =
        WitnessArgsReader::from_slice(first_witness_data).map_err(|_| Error::WitnessParse)?;

    // 1. tx hash
    hasher.update(&load_tx_hash()?);

    // 2. contents of all input cells (cell output + length-prefixed data).
    let cell_output_iter = QueryIter::new(
        |index, source| load_initial(syscalls::load_cell, index, source),
        Source::Input,
    );
    let cell_data_iter = QueryIter::new(
        |index, source| load_initial(syscalls::load_cell_data, index, source),
        Source::Input,
    );
    let mut input_cell_count = 0usize;
    for (initial_cell_output, initial_cell_data) in cell_output_iter.zip(cell_data_iter) {
        input_cell_count += 1;
        load_and_hash(initial_cell_output, syscalls::load_cell, hasher)
            .map_err(|_| Error::Syscall)?;
        write_length(initial_cell_data.full_length, hasher)?;
        load_and_hash(initial_cell_data, syscalls::load_cell_data, hasher)
            .map_err(|_| Error::Syscall)?;
    }

    // 3. first witness of current script group: input_type + output_type
    //    (the `lock` field is excluded — it carries the signature).
    let input_type = first_witness.input_type().as_slice();
    let output_type = first_witness.output_type().as_slice();
    write_length(input_type.len(), hasher)?;
    hasher.update(input_type);
    write_length(output_type.len(), hasher)?;
    hasher.update(output_type);

    // 4. remaining witnesses in current script group.
    for initial_witness in QueryIter::new(
        |index, source| load_initial(syscalls::load_witness, index, source),
        Source::GroupInput,
    )
    .skip(1)
    {
        write_length(initial_witness.full_length, hasher)?;
        load_and_hash(initial_witness, syscalls::load_witness, hasher)
            .map_err(|_| Error::Syscall)?;
    }

    // 5. witnesses which do not have input cells of matching indices.
    for initial_witness in QueryIter::new(
        |index, source| load_initial(syscalls::load_witness, index, source),
        Source::Input,
    )
    .skip(input_cell_count)
    {
        write_length(initial_witness.full_length, hasher)?;
        load_and_hash(initial_witness, syscalls::load_witness, hasher)
            .map_err(|_| Error::Syscall)?;
    }

    Ok(())
}

fn load_tx_hash() -> Result<[u8; 32], Error> {
    high_level::load_tx_hash().map_err(|_| Error::Syscall)
}

#[inline]
fn write_length(length: usize, hasher: &mut MessageHasher) -> Result<(), Error> {
    let length: u32 = length.try_into().map_err(|_| Error::CkbTxMessageAll)?;
    hasher.update(&length.to_le_bytes());
    Ok(())
}

// Load a witness/cell in fixed-length batches to bound peak memory usage. A
// single witness can be as large as ~600K, while the VM only has 4M total
// memory shared by code and data.
const LOAD_BATCH_LENGTH: usize = 32 * 1024;

struct InitialLoadData {
    index: usize,
    source: Source,
    full_length: usize,
    buffer: [u8; LOAD_BATCH_LENGTH],
}

fn load_initial<F>(load_fn: F, index: usize, source: Source) -> Result<InitialLoadData, SysError>
where
    F: Fn(&mut [u8], usize, usize, Source) -> Result<usize, SysError>,
{
    let mut buffer = [0u8; LOAD_BATCH_LENGTH];
    let full_length = match load_fn(&mut buffer, 0, index, source) {
        Ok(actual_length) => actual_length,
        Err(SysError::LengthNotEnough(actual_length)) => actual_length,
        Err(e) => return Err(e),
    };
    Ok(InitialLoadData {
        index,
        source,
        full_length,
        buffer,
    })
}

fn load_and_hash<F>(
    initial: InitialLoadData,
    load_fn: F,
    hasher: &mut MessageHasher,
) -> Result<(), SysError>
where
    F: Fn(&mut [u8], usize, usize, Source) -> Result<usize, SysError>,
{
    let InitialLoadData {
        full_length,
        index,
        source,
        mut buffer,
    } = initial;
    let mut loaded = if full_length > LOAD_BATCH_LENGTH {
        LOAD_BATCH_LENGTH
    } else {
        full_length
    };
    hasher.update(&buffer[0..loaded]);

    while loaded < full_length {
        match load_fn(&mut buffer, loaded, index, source) {
            Ok(current_loaded) => {
                debug_assert_eq!(
                    loaded.checked_add(current_loaded).expect("overflow"),
                    full_length
                );
                hasher.update(&buffer[0..current_loaded]);
                loaded += current_loaded;
            }
            Err(SysError::LengthNotEnough(_)) => {
                debug_assert!(
                    loaded.checked_add(LOAD_BATCH_LENGTH).expect("overflow") < full_length
                );
                hasher.update(&buffer);
                loaded += LOAD_BATCH_LENGTH;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(())
}

pub fn program_entry() -> i8 {
    ckb_std::debug!("This is the shrincs-lock contract!");

    let first_witness_data = match high_level::load_witness(0, Source::GroupInput) {
        Ok(data) => data,
        Err(_) => return Error::Syscall.into(),
    };

    // Compute the CKB_TX_MESSAGE_ALL signing message.
    let mut message_hasher = MessageHasher::new();
    if let Err(e) = generate_ckb_tx_message_all(&mut message_hasher, &first_witness_data) {
        ckb_std::debug!("generate_ckb_tx_message_all failed: {:?}", e);
        return e.into();
    }
    let message = message_hasher.finalize();

    // Extract the SHRINCS signature from the `lock` field of the witness.
    let first_witness = match WitnessArgsReader::from_slice(&first_witness_data) {
        Ok(w) => w,
        Err(_) => return Error::WitnessParse.into(),
    };
    let signature = match first_witness.lock().to_opt() {
        Some(lock) => lock.raw_data(),
        None => return Error::SignatureMissing.into(),
    };

    // The script args carry the 32-byte SHRINCS public key: 16-byte `seed`
    // followed by 16-byte compressed `root`.
    let script = match high_level::load_script() {
        Ok(s) => s,
        Err(_) => return Error::Syscall.into(),
    };
    let args = script.args().raw_data();
    if args.len() != 32 {
        return Error::PubkeyLength.into();
    }
    let mut pk = PublicKey::default();
    pk.seed.copy_from_slice(&args[..16]);
    pk.root.copy_from_slice(&args[16..32]);

    // Verify the signature against the message and public key.
    if !shrincs_verify::<SHRINCS_B>(&message, &signature, &pk) {
        return Error::ShrincsVerify.into();
    }

    0
}
