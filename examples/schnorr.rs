use anyhow::{Context as _, Result, anyhow};
use group::Group;
use midnight_circuits::instructions::hash::HashCPU;
use midnight_curves::{Base, Bls12, BlsScalar as Scalar, Fq, G1Projective};
use midnight_curves::{Fr as JubjubScalar, JubjubAffine, JubjubExtended as Jubjub, JubjubSubgroup};

use midnight_proofs::{
    plonk::{create_proof, k_from_circuit, keygen_pk, keygen_vk, prepare},
    poly::{
        commitment::{Guard, PolynomialCommitmentScheme},
        kzg::{
            KZGCommitmentScheme,
            params::{ParamsKZG, ParamsVerifierKZG},
        },
    },
    transcript::Transcript,
};

use midnight_circuits::hash::poseidon::PoseidonChip;
use midnight_proofs::circuit::Value;
use midnight_zk_stdlib::MidnightCircuit;

use cardhalo::{
    circuits::schnorr_circuit::{SchnorrExample, SchnorrSignature, utils::verify},
    kzg_params::get_or_create_kzg_params,
};
use log::{debug, info};
use midnight_zk_stdlib::Relation;
use rand::rngs::StdRng;
use rand_core::SeedableRng;

#[path = "./utils.rs"]
mod utils;
use utils::{CTranscript, PCS, PK, Params, VK, export_all};

fn main() -> Result<()> {
    compile_schnorr_circuit::<KZGCommitmentScheme<Bls12>>()
}

// Returns the affine coordinates of a given Jubjub point.
fn get_coords(point: &JubjubSubgroup) -> (Base, Base) {
    let point: &Jubjub = point.into();
    let point: JubjubAffine = point.into();
    (point.get_u(), point.get_v())
}

fn compile_schnorr_circuit<
    S: PolynomialCommitmentScheme<
            Scalar,
            Commitment = G1Projective,
            Parameters = ParamsKZG<Bls12>,
            VerifierParameters = ParamsVerifierKZG<Bls12>,
        >,
>() -> Result<()> {
    // Signing and public keys
    let shnorr_sk = JubjubScalar::from(7);
    let schnorr_pk = JubjubSubgroup::generator() * shnorr_sk;

    // Message
    let msg = Fq::from(42);

    // Signature
    let sig = {
        let k = JubjubScalar::from(2);
        let r = JubjubSubgroup::generator() * k;

        let (rx, ry) = get_coords(&r);
        let (pkx, pky) = get_coords(&schnorr_pk);

        let h = PoseidonChip::hash(&[pkx, pky, rx, ry, msg]);
        let e_bytes = h.to_bytes_le();

        let s = {
            let mut buff = [0u8; 64];
            buff[..32].copy_from_slice(&e_bytes);
            let e = JubjubScalar::from_bytes_wide(&buff);
            k - e * shnorr_sk
        };

        SchnorrSignature { s, e_bytes }
    };

    // Sanity check the signature verifies:
    assert!(verify(&sig, &schnorr_pk, msg));

    // Creating proof
    let seed = [0u8; 32]; // UNSAFE, constant seed is used for testing purposes
    let mut rng: StdRng = SeedableRng::from_seed(seed);

    let relation = SchnorrExample;
    let witness = sig;
    debug!(
        "circuit: {:?}",
        SchnorrExample::format_committed_instances(&witness)
    );
    let instance = (schnorr_pk, msg);

    let circuit = MidnightCircuit::new(
        &relation,
        Value::known(instance),
        Value::known(witness),
        None,
    );
    let k = k_from_circuit(&circuit);
    let params: Params = get_or_create_kzg_params(k, rng.clone())?;
    let vk: VK = keygen_vk(&params, &circuit).context("keygen_vk should not fail")?;
    let pk: PK = keygen_pk(vk.clone(), &circuit).context("keygen_pk should not fail")?;

    let mut transcript = CTranscript::init();
    debug!("transcript: {:?}", transcript);

    let formatted_instance = SchnorrExample::format_instance(&instance).unwrap();
    let instances: &[&[&[Scalar]]] = &[&[&[], &formatted_instance]];
    info!("Public inputs: {:?}", instances);
    let nb_committed_instances = 0;
    create_proof(
        &params,
        &pk,
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
    let index = 48 * 8 + 2;
    let firs_byte = invalid_proof[index];
    let negated_firs_byte = !firs_byte;
    invalid_proof[index] = negated_firs_byte;

    info!("proof size {:?}", proof.len());

    let mut transcript_verifier = CTranscript::init_from_bytes(&proof);
    let verifier = prepare::<_, PCS, CTranscript>(&vk, &[&[]], instances, &mut transcript_verifier)
        .context("prepare verification failed")?;

    verifier
        .verify(&params.verifier_params())
        .map_err(|e| anyhow!("{e:?}"))
        .context("verify failed")?;

    export_all(proof, params, vk, instances, invalid_proof)
}
