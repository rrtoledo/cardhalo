use anyhow::{Context as _, Result, anyhow};
use ff::Field;
use midnight_curves::BlsScalar as Scalar;

use midnight_proofs::{
    plonk::{create_proof, prepare},
    poly::{commitment::Guard, kzg::params::ParamsKZG},
    transcript::{CircuitTranscript, Transcript},
};

use log::{debug, info};
use mithril_circuits::{
    JubjubBase,
    certificate::Certificate,
    merkle_tree::{MTLeaf, MerkleTree},
    unique_signature::{SigningKey, VerificationKey},
};
use plutus_halo2_verifier_gen::plutus_gen::{
    CardanoFriendlyBlake2b, export_proof, export_public_inputs, generate_aiken_verifier,
    generate_plinth_verifier, serialize_proof,
};
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use std::fs::File;

use midnight_proofs::circuit::Value;
use midnight_proofs::utils::SerdeFormat;
use midnight_zk_stdlib::MidnightCircuit;
use midnight_zk_stdlib::{self as zk, Relation};
use std::io::Cursor;

fn create_merkle_tree(n: usize) -> (Vec<SigningKey>, Vec<MTLeaf>, MerkleTree) {
    let seed = [42u8; 32]; // UNSAFE, constant seed is used for testing purposes
    let mut rng: StdRng = SeedableRng::from_seed(seed);

    let mut sks = Vec::new();
    let mut leaves = Vec::new();
    for _ in 0..n {
        let sk = SigningKey::generate(&mut rng);
        let vk = VerificationKey::from(&sk); // Replace this with actual initialization if provided
        leaves.push(MTLeaf(vk, -JubjubBase::ONE));
        sks.push(sk);
    }
    let tree = MerkleTree::create(&leaves);

    (sks, leaves, tree)
}

fn main() -> Result<()> {
    let seed = [0u8; 32]; // UNSAFE, constant seed is used for testing purposes
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    // Prepare the private and public inputs to the circuit!

    // Keep num_signers fixed for baseline comparisons.
    let k = 13;
    let quorum = 3;
    let num_signers: usize = 3000;
    let depth = num_signers.next_power_of_two().trailing_zeros();
    let num_lotteries = quorum * 10;

    let srs = ParamsKZG::unsafe_setup(k, rng.clone());
    let relation = Certificate::new(quorum, num_lotteries, depth);

    let (sks, leaves, merkle_tree) = create_merkle_tree(num_signers);

    {
        // Print circuit sizing information.
        let circuit = MidnightCircuit::from_relation(&relation);
        println!("\n=== Certificate case ===");
        println!("k (selected) {k}");
        println!("quorum {quorum}");
        println!("min_k {:?}", circuit.min_k());
        println!("{:?}", zk::cost_model(&relation));
    }

    let vk = zk::setup_vk(&srs, &relation);
    let pk = zk::setup_pk(&relation, &vk);

    {
        let mut buffer = Cursor::new(Vec::new());
        // Serialize the MidnightVK instance to the buffer in the RawBytes format
        vk.write(&mut buffer, SerdeFormat::RawBytes).unwrap();
        // Get the size of the serialized MidnightVK
        println!("vk length {:?}", buffer.get_ref().len());
    }

    let merkle_root = merkle_tree.root();
    // message to be signed
    let msg = JubjubBase::from(42);

    // take the first few signers
    let mut witness = vec![];
    for i in 0..quorum as usize {
        let ii = i % num_signers;
        let usk = sks[ii].clone();
        let uvk = leaves[ii].0;
        let sig = usk.sign(&[merkle_root, msg], &mut rng.clone());
        sig.verify(&[merkle_root, msg], &uvk).unwrap();

        let merkle_path = merkle_tree.get_path(ii);
        let computed_root = merkle_path.compute_root(leaves[ii]);
        assert_eq!(merkle_root, computed_root);

        // any index is eligible as target is set to be the maximum
        witness.push((leaves[ii], merkle_path, sig, (i + 1) as u32));
    }

    // Instantiate the circuit with the private inputs.
    let instance = (merkle_root, msg);
    let circuit = MidnightCircuit::new(
        &relation,
        Value::known(instance),
        Value::known(witness.clone()),
        None,
    );
    debug!("circuit: {:?}", circuit);

    let mut transcript: CircuitTranscript<CardanoFriendlyBlake2b> =
        CircuitTranscript::<CardanoFriendlyBlake2b>::init();
    debug!("transcript: {:?}", transcript);

    // no instances, just dummy 42 to make prover and verifier happy
    let instances: &[&[&[Scalar]]] = &[&[
        &Certificate::format_committed_instances(&witness.clone()),
        &Certificate::format_instance(&instance).unwrap(),
    ]];
    info!("Public inputs: {:?}", instances);

    let instances_file =
        "./plinth-verifier/plutus-halo2/test/Generic/serialized_public_input.hex".to_string();
    let mut output = File::create(instances_file).context("failed to create instances file")?;
    export_public_inputs(instances, &mut output).context("faield to export public inputs")?;

    let nb_committed_instances = 0;
    create_proof(
        &srs,
        &pk.pk(),
        &[circuit],
        nb_committed_instances,
        instances,
        &mut rng,
        &mut transcript,
    )
    .context("proof generation should not fail")?;

    let proof = transcript.finalize();

    let mut invalid_proof = proof.clone();
    // index points to bytes of first scalar that is part of the proof
    // this should be safe and not result in malformed encoding exception
    // which is likely for flipping Byte for compressed G1 element
    // simple mul has 8 G1 elements at the beginning of the proof each 48 bytes long
    let index = 48 * 25 + 2;
    let firs_byte = invalid_proof[index];
    let negated_firs_byte = !firs_byte;
    invalid_proof[index] = negated_firs_byte;

    info!("proof size {:?}", proof.len());

    let mut transcript_verifier: CircuitTranscript<CardanoFriendlyBlake2b> =
        CircuitTranscript::<CardanoFriendlyBlake2b>::init_from_bytes(&proof);
    let verifier = prepare::<_, _, CircuitTranscript<CardanoFriendlyBlake2b>>(
        &vk.vk(),
        &[&[]],
        instances,
        &mut transcript_verifier,
    )
    .context("prepare verification failed")?;

    verifier
        .verify(&srs.verifier_params())
        .map_err(|e| anyhow!("{e:?}"))
        .context("verify failed")?;

    serialize_proof(
        "./plinth-verifier/plutus-halo2/test/Generic/serialized_proof.json".to_string(),
        proof.clone(),
    )
    .context("json proof serialization failed")?;

    export_proof(
        "./plinth-verifier/plutus-halo2/test/Generic/serialized_proof.hex".to_string(),
        proof.clone(),
    )
    .context("hex proof serialization failed")?;

    generate_plinth_verifier(&srs, &vk.vk(), instances)
        .context("Plinth verifier generation failed")?;

    generate_aiken_verifier(
        &srs,
        &vk.vk(),
        instances,
        Some((proof.clone(), invalid_proof)),
    )
    .context("Aiken verifier generation failed")?;
    export_proof(
        "./aiken-verifier/submitter/serialized_proof.hex".to_string(),
        proof,
    )
    .context("hex proof serialization failed")?;

    let instances_file = "./aiken-verifier/submitter/serialized_public_input.hex".to_string();
    let mut output = File::create(instances_file).context("failed to create instances file")?;
    export_public_inputs(instances, &mut output).context("Failed to export the public inputs")?;

    Ok(())
}
