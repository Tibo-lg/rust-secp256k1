extern crate bitcoin_hashes;
extern crate secp256k1;

use bitcoin_hashes::sha256;
use secp256k1::rand::{rngs::OsRng, RngCore};
use secp256k1::{
    ecdsa_adaptor::{AdaptorProof, AdaptorSignature},
    key,
    schnorrsig::{KeyPair, PublicKey},
    Message, Secp256k1,
};

fn main() {
    let secp = Secp256k1::new();
    let mut rng = OsRng::new().expect("OsRng");

    // Set message to be signed. In practice this would be Bitcoin tx information.
    let message = "Hello World";
    let msg_hash = Message::from_hashed_data::<sha256::Hash>(message.as_bytes());

    // Outcomes: the possible outcome the oracle could sign
    let outcomes = ["Head", "Tail"];
    let outcomes_hash: Vec<Message> = outcomes
        .iter()
        .map(|m| Message::from_hashed_data::<sha256::Hash>(m.as_bytes()))
        .collect();

    // Generate oracle key pair and k and R values.
    let (oracle_sk, oracle_pk) = secp.generate_schnorrsig_keypair(&mut rng);
    let mut k_value = [0u8; 32];
    rng.fill_bytes(&mut k_value);
    let k_keypair = KeyPair::from_seckey_slice(&secp, &k_value).expect("Keypair");
    let r_value = PublicKey::from_keypair(&secp, &k_keypair);

    // Generate key pairs for Alice and Bob
    let (alice_sk, alice_pk) = secp.generate_keypair(&mut rng);
    let (bob_sk, bob_pk) = secp.generate_keypair(&mut rng);

    // Compute the signature points: SO_i = R + H(R|P|m_i)*P
    let outcomes_sig_points: Vec<::key::PublicKey> = outcomes_hash
        .iter()
        .map(|h| {
            secp.schnorrsig_compute_sig_point(&h, &r_value, &oracle_pk)
                .expect("SigPoint")
        })
        .collect();

    // Create adaptor signatures and proofs:
    // s'_i = r^-1*(H(m_i)+R'_i*sk) where R'_i = r * SO_i (= r * sO_i * G)
    // proof is DLEQ proof

    let alice_adaptor_pairs: Vec<(AdaptorSignature, AdaptorProof)> = outcomes_sig_points
        .iter()
        .map(|osg| secp.adaptor_sign(&msg_hash, &alice_sk, &osg))
        .collect();
    let bob_adaptor_pairs: Vec<(AdaptorSignature, AdaptorProof)> = outcomes_sig_points
        .iter()
        .map(|osg| secp.adaptor_sign(&msg_hash, &bob_sk, &osg))
        .collect();

    // Verify adaptor signatures
    // R'_i =? (H(m_i) * G + R'_i * Pubkey) * s'^-1
    // DLEQ proof verification
    assert!(alice_adaptor_pairs
        .iter()
        .zip(outcomes_sig_points.clone())
        .all(|(p, osg)| secp
            .adaptor_verify(&msg_hash, &p.0, &alice_pk, &osg, &p.1)
            .is_ok()));

    assert!(bob_adaptor_pairs
        .iter()
        .zip(outcomes_sig_points)
        .all(|(p, osg)| secp
            .adaptor_verify(&msg_hash, &p.0, &bob_pk, &osg, &p.1)
            .is_ok()));

    // Oracle sign
    // sO = k_value + H(R|P|m_i) * skO
    let oracle_sig = secp.schnorrsig_sign_with_nonce(&outcomes_hash[0], &oracle_sk, &k_value);

    // Extract sO
    let (_, s_value) = oracle_sig.decompose().unwrap();

    // Decrypt adaptor signature
    // s = s' * sO^-1 = (H(m)+R'*sec)(k_value*sO)^-1
    let decrypted_sig = secp.adaptor_adapt(
        &::key::SecretKey::from_slice(s_value.as_ref()).unwrap(),
        &alice_adaptor_pairs[0].0,
    );

    // Verify the decrypted ECDSA signature
    secp.verify(&msg_hash, &decrypted_sig, &alice_pk)
        .expect("Invalid signature");
}
