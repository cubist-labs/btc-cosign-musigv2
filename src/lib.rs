//! helper functions for musigv2 co-signing

use bitcoin::{
    absolute::LockTime,
    blockdata::transaction::Version,
    hashes::sha256d::Hash,
    secp256k1::SECP256K1,
    sighash::{Prevouts, SighashCache, TapSighash, TapSighashType},
    taproot::TapNodeHash,
    Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, XOnlyPublicKey,
};
use rand::{rngs::OsRng, Rng};
use thiserror::Error;

/// Errors produced by the cosigner
#[derive(Debug, Error)]
pub enum CoSignerError {
    /// Transaction value minus fee would result in negative or dust output
    #[error("Transaction value minus fee would result in negative or dust output")]
    BadTestTxnValue,

    /// Error in PSBT processing
    #[error("Error in PSBT processing: {0}")]
    Psbt(#[from] bitcoin::psbt::Error),

    /// Error in Taproot sighash processing
    #[error("Error in sighash processing: {0}")]
    TapSighash(#[from] bitcoin::sighash::Error),

    #[error("Error computing muSigv2 tweak: {0}")]
    MuSigv2Tweak(#[from] musig2::errors::TweakError),

    #[error("Error computing aggregate pubkey: {0}")]
    MuSigv2KeyAgg(#[from] musig2::errors::KeyAggError),

    #[error("Signer index out of bounds: {0}")]
    SignerIndex(#[from] musig2::errors::SignerIndexError),

    #[error("Invalid round contribution: {0}")]
    RoundContribution(#[from] musig2::errors::RoundContributionError),

    #[error("Round finalization failed: {0}")]
    RoundFinalization(#[from] musig2::errors::RoundFinalizeError),
}

/// Create a test Partially-Signed Bitcoin Transaction for use with signing.
///
/// NOTE: In the actual co-signing application, the PSBT a Babylon staking transaction.
pub fn create_test_psbt(
    tap_internal_key: XOnlyPublicKey,
    tap_merkle_root: Option<TapNodeHash>,
    value: Amount,
    recipient: ScriptBuf,
    fee: Amount,
) -> Result<Psbt, CoSignerError> {
    // compute output value and check that it's not negative and
    // greater than the dust limit
    let output_value = value.checked_sub(fee).unwrap_or(Amount::ZERO);
    if output_value < recipient.dust_value() {
        Err(CoSignerError::BadTestTxnValue)?;
    }

    // sample random values for txid and vout for the UTXO
    let mut rng = OsRng;
    let txid: [u8; 32] = rng.gen();
    let vout = rng.gen::<u8>() % 16;

    // the transaction input that we will spend
    let in1 = TxIn {
        previous_output: OutPoint {
            txid: Txid::from(*Hash::from_bytes_ref(&txid)),
            vout: vout as u32,
        },
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        ..Default::default()
    };

    // the corresponding UTXO
    let in1_utxo = TxOut {
        script_pubkey: ScriptBuf::new_p2tr(SECP256K1, tap_internal_key, tap_merkle_root),
        value,
    };

    // the output spend
    let out1 = TxOut {
        script_pubkey: recipient,
        value: output_value,
    };

    // create the transaction
    let txn = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![in1],
        output: vec![out1],
    };

    // create the PSBT and add data needed for key spend
    let mut psbt = Psbt::from_unsigned_tx(txn)?;
    assert_eq!(psbt.inputs.len(), 1);
    psbt.inputs[0].witness_utxo.replace(in1_utxo);
    psbt.inputs[0].tap_internal_key.replace(tap_internal_key);
    psbt.inputs[0].tap_merkle_root = tap_merkle_root;

    Ok(psbt)
}

/// Compute the signing hash for a Taproot key spend of the PSBT's `index`th input
pub fn get_key_spend_sighash(psbt: &Psbt, index: usize) -> Result<TapSighash, CoSignerError> {
    const SIGHASH_TYPE: TapSighashType = TapSighashType::Default;

    // need all previous outputs for TapSighashType::Default
    let prevouts_vec = psbt.iter_funding_utxos().collect::<Result<Vec<_>, _>>()?;
    let prevouts = Prevouts::All(&prevouts_vec);

    // compute the sighash
    SighashCache::new(&psbt.unsigned_tx)
        .taproot_key_spend_signature_hash(index, &prevouts, SIGHASH_TYPE)
        .map_err(Into::into)
}

/// Create a hex encoding of a byte string
pub fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut ret = String::with_capacity(2 * bytes.len());
    bytes
        .iter()
        .for_each(|b| write!(&mut ret, "{b:02x}").expect("infallible"));
    ret
}
