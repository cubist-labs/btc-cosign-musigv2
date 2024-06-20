//! Demonstration of muSigv2-based co-signing of a Partially Signed Bitcoin Transaction

use bitcoin::{
    sighash::TapSighashType,
    taproot::{Signature, TapNodeHash},
    Amount, ScriptBuf,
};
use btc_cosign_musigv2::{create_test_psbt, get_key_spend_sighash, hex_encode, CoSignerError};
use musig2::{
    secp256k1::{schnorr::Signature as SchnorrSignature, Keypair, Message, PublicKey, SECP256K1},
    CompactSignature, FirstRound, KeyAggContext, PartialSignature, SecNonceSpices,
};
use rand::{rngs::OsRng, Rng};

fn main() -> Result<(), CoSignerError> {
    let mut rng = OsRng;

    // ****************************************************************
    // *** Step 0: choose a Taproot tweak for the test transaction. ***
    // ****************************************************************
    //
    // In the real application the use of a tweak (or not) is determined
    // by the UTXO that the co-signer is spending. In this example, we use
    // a random tweak to demonstrate that the co-signer is able to handle
    // all Taproot transaction types.
    let tweak: [u8; 32] = rng.gen();
    let spendable_tweak: bool = rng.gen();

    // ************************************************
    // *** Step 1: generate keys for the co-signers ***
    // ************************************************
    //
    // In the real application, this step will be done separately by each party.
    // Here we generate two test keys for demonstration purposes.
    println!("Step 1: Generating the keys for the two co-signers...");

    let party_0_key = Keypair::new(SECP256K1, &mut rng);
    let party_1_key = Keypair::new(SECP256K1, &mut rng);

    println!(
        "  {}",
        hex_encode(&party_0_key.x_only_public_key().0.serialize())
    );
    println!(
        "  {}",
        hex_encode(&party_1_key.x_only_public_key().0.serialize())
    );

    // *************************************************
    // *** Step 2: compute the aggregated public key ***
    // *************************************************
    //
    // This is the public key that will be used for all on-chain activity.
    println!("\nStep 2: Computing aggregated public key...");

    let pubkeys = vec![party_0_key.public_key(), party_1_key.public_key()];
    let untweaked_key_aggregation_context = KeyAggContext::new(pubkeys)?;
    let cosigner_public_key: PublicKey = untweaked_key_aggregation_context.aggregated_pubkey();
    let cosigner_schnorr_key = cosigner_public_key.x_only_public_key().0;

    println!("  {}", hex_encode(&cosigner_schnorr_key.serialize()));

    // ******************************************************************************
    // *** Step 3: create a transaction and sign using the aggregated public key. ***
    // ******************************************************************************
    //
    // In the real application, this PSBT would be for a Babylon staking transaction.
    // Here, we create a dummy PSBT that can be spent by the co-signer public key
    // and pays to a randomly generated Taproot address.
    println!("\nStep 3: Creating a teest transaction to sign...");

    let recipient_key = Keypair::new(SECP256K1, &mut rng).x_only_public_key().0;
    let recipient = ScriptBuf::new_p2tr(SECP256K1, recipient_key, None);
    let tap_merkle_root = spendable_tweak.then_some(TapNodeHash::assume_hidden(tweak));
    let test_psbt = create_test_psbt(
        cosigner_schnorr_key,
        tap_merkle_root,
        Amount::from_sat(1_000_000_000),
        recipient,
        Amount::from_sat(10_000),
    )?;
    let sighash = get_key_spend_sighash(&test_psbt, 0 /* input index */)?;

    println!("  {test_psbt:#?}");
    println!("  sighash: {}", hex_encode(sighash.as_ref()));

    // ********************************
    // *** Step 4: muSigv2 protocol ***
    // ********************************
    //
    // In the real application, the two signers are located on different machines
    // and they each run their respective part of the protocol. Here, we run both
    // signers locally to demonstrate how they work.
    println!("\nStep 4: running muSigv2 protocol...");

    // *
    // * Step 4a: tweak the key aggregation context
    // *
    //
    // When spending for a tweaked Taproot key, both co-signers must first tweak the
    // key aggregation context.
    let key_aggregation_context = if spendable_tweak {
        untweaked_key_aggregation_context.with_taproot_tweak(&tweak)
    } else {
        untweaked_key_aggregation_context.with_unspendable_taproot_tweak()
    }?;
    let tweaked_public_key: PublicKey = key_aggregation_context.aggregated_pubkey();
    let tweaked_public_key = tweaked_public_key.x_only_public_key().0;

    println!(
        "  Tweaked aggregate key: {}",
        hex_encode(&tweaked_public_key.serialize())
    );

    // *
    // * Step 4b: signers complete the first round
    // *
    //
    // Party 0, first round
    let party_0_nonce_seed: [u8; 32] = rng.gen();
    let mut party_0_first_round = FirstRound::new(
        key_aggregation_context.clone(),
        party_0_nonce_seed,
        0, /* signer index */
        SecNonceSpices::new()
            .with_seckey(party_0_key.secret_key())
            .with_message(&sighash),
    )?;
    let party_0_public_nonce = party_0_first_round.our_public_nonce();
    //
    // Party 1, first round
    let party_1_nonce_seed: [u8; 32] = rng.gen();
    let mut party_1_first_round = FirstRound::new(
        key_aggregation_context,
        party_1_nonce_seed,
        1, /* signer index */
        SecNonceSpices::new()
            .with_seckey(party_1_key.secret_key())
            .with_message(&sighash),
    )?;
    let party_1_public_nonce = party_1_first_round.our_public_nonce();

    // *
    // * Step 4c: each party sends the other party its public nonce
    // *
    //
    // Party 0 receives from Party 1
    party_0_first_round.receive_nonce(1, party_1_public_nonce)?;
    assert!(party_0_first_round.is_complete());
    //
    // Party 1 receives from Party 0
    party_1_first_round.receive_nonce(0, party_0_public_nonce)?;
    assert!(party_1_first_round.is_complete());

    // *
    // * Step 4d: each party starts the second round and produces their partial signature
    // *
    //
    // Party 0
    let mut party_0_second_round =
        party_0_first_round.finalize(party_0_key.secret_key(), &sighash)?;
    let party_0_partial_sig: PartialSignature = party_0_second_round.our_signature();
    //
    // Party 1
    let mut party_1_second_round =
        party_1_first_round.finalize(party_1_key.secret_key(), &sighash)?;
    let party_1_partial_sig: PartialSignature = party_1_second_round.our_signature();

    // *
    // * Step 4e: each party sends the other party its partial signature
    // *
    //
    // Party 0 receives from Party 1
    party_0_second_round.receive_signature(1, party_1_partial_sig)?;
    assert!(party_0_second_round.is_complete());
    //
    // Party 1 receives from Party 0
    party_1_second_round.receive_signature(0, party_0_partial_sig)?;
    assert!(party_1_second_round.is_complete());

    // *
    // * Step 4f: each party can now compute the signature
    // *
    //
    // Party 0
    let party_0_final_signature: CompactSignature = party_0_second_round.finalize()?;
    let party_0_final_signature = SchnorrSignature::from(party_0_final_signature);
    //
    // Party 1
    let party_1_final_signature: CompactSignature = party_1_second_round.finalize()?;
    let party_1_final_signature = SchnorrSignature::from(party_1_final_signature);

    // *********************************************************************************
    // *** FINAL CHECK: Parties end up with the same signature, and the signature is ***
    // *** valid for the sighash.
    // *********************************************************************************
    assert_eq!(party_0_final_signature, party_1_final_signature);
    let message = Message::from_digest(*sighash.as_ref());
    assert!(party_0_final_signature
        .verify(&message, &tweaked_public_key)
        .is_ok());

    // Output the signature and serialized PSBT including the signature
    println!(
        "\nSignature: {}",
        hex_encode(&party_0_final_signature.serialize())
    );

    let mut psbt = test_psbt;
    psbt.inputs[0].tap_key_sig.replace(Signature {
        sig: party_0_final_signature,
        hash_ty: TapSighashType::Default,
    });
    println!("\nPSBT: {}", psbt.serialize_hex());

    Ok(())
}
