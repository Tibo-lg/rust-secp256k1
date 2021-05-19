//! # ECDSA Adaptor
//! Support for ECDSA based adaptor signatures.
//!

use super::{from_hex, Error};
use core::{fmt, str};
use ffi::{self, CPtr};
use {constants, PublicKey, Secp256k1, SecretKey};
use {Message, Signing};
use {Signature, Verification};

/// An adaptor signature.
pub struct AdaptorSignature([u8; constants::ADAPTOR_SIGNATURE_SIZE]);
impl_array_newtype!(AdaptorSignature, u8, constants::ADAPTOR_SIGNATURE_SIZE);
impl_pretty_debug!(AdaptorSignature);

impl fmt::LowerHex for AdaptorSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for ch in self.0.iter().enumerate() {
            write!(f, "{:02x}", ch.1)?;
        }
        Ok(())
    }
}

impl fmt::Display for AdaptorSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl str::FromStr for AdaptorSignature {
    type Err = Error;
    fn from_str(s: &str) -> Result<AdaptorSignature, Error> {
        let mut res = [0; constants::ADAPTOR_SIGNATURE_SIZE];
        match from_hex(s, &mut res) {
            Ok(constants::ADAPTOR_SIGNATURE_SIZE) => {
                AdaptorSignature::from_slice(&res[0..constants::ADAPTOR_SIGNATURE_SIZE])
            }
            _ => Err(Error::InvalidAdaptorSignature),
        }
    }
}

impl AdaptorSignature {
    /// Creates an AdaptorSignature directly from a slice
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<AdaptorSignature, Error> {
        match data.len() {
            constants::ADAPTOR_SIGNATURE_SIZE => {
                let mut ret = [0; constants::ADAPTOR_SIGNATURE_SIZE];
                ret[..].copy_from_slice(data);
                Ok(AdaptorSignature(ret))
            }
            _ => Err(Error::InvalidAdaptorSignature),
        }
    }
}

/// Proof to verify an adaptor signature.
pub struct AdaptorProof([u8; constants::ADAPTOR_PROOF_SIZE]);
impl_array_newtype!(AdaptorProof, u8, constants::ADAPTOR_PROOF_SIZE);
impl_pretty_debug!(AdaptorProof);

impl fmt::LowerHex for AdaptorProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for ch in self.0.iter().enumerate() {
            write!(f, "{:02x}", ch.1)?;
        }
        Ok(())
    }
}

impl fmt::Display for AdaptorProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl str::FromStr for AdaptorProof {
    type Err = Error;
    fn from_str(s: &str) -> Result<AdaptorProof, Error> {
        let mut res = [0; constants::ADAPTOR_PROOF_SIZE];
        match from_hex(s, &mut res) {
            Ok(constants::ADAPTOR_PROOF_SIZE) => {
                AdaptorProof::from_slice(&res[0..constants::ADAPTOR_PROOF_SIZE])
            }
            _ => Err(Error::InvalidAdaptorProof),
        }
    }
}

impl AdaptorProof {
    /// Creates an AdaptorProof directly from a slice
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<AdaptorProof, Error> {
        match data.len() {
            constants::ADAPTOR_PROOF_SIZE => {
                let mut ret = [0; constants::ADAPTOR_PROOF_SIZE];
                ret[..].copy_from_slice(data);
                Ok(AdaptorProof(ret))
            }
            _ => Err(Error::InvalidAdaptorSignature),
        }
    }
}

impl<C: Signing> Secp256k1<C> {
    /// Creates an adaptor signature along with a proof to verify the adaptor signature.
    pub fn adaptor_sign(
        &self,
        msg: &Message,
        sk: &SecretKey,
        adaptor: &PublicKey,
    ) -> (AdaptorSignature, AdaptorProof) {
        let mut adaptor_sig = [0u8; constants::ADAPTOR_SIGNATURE_SIZE];
        let mut adaptor_proof = [0u8; constants::ADAPTOR_PROOF_SIZE];

        unsafe {
            assert_eq!(
                1,
                ffi::secp256k1_ecdsa_adaptor_sign(
                    self.ctx,
                    adaptor_sig.as_mut_c_ptr(),
                    adaptor_proof.as_mut_c_ptr(),
                    sk.as_c_ptr(),
                    adaptor.as_c_ptr(),
                    msg.as_c_ptr()
                )
            );
        }

        (AdaptorSignature(adaptor_sig), AdaptorProof(adaptor_proof))
    }

    /// Creates an ECDSA signature from an adaptor signature and an adaptor secret.
    pub fn adaptor_adapt(
        &self,
        adaptor_secret: &SecretKey,
        adaptor_sig: &AdaptorSignature,
    ) -> Signature {
        unsafe {
            let mut signature = ffi::Signature::new();
            assert_eq!(
                1,
                ffi::secp256k1_ecdsa_adaptor_adapt(
                    self.ctx,
                    &mut signature,
                    adaptor_secret.as_c_ptr(),
                    adaptor_sig.as_c_ptr()
                )
            );
            Signature::from(signature)
        }
    }

    /// Extracts the adaptor secret from the complete signature and the adaptor signature.
    pub fn adaptor_extract_secret(
        &self,
        sig: &Signature,
        adaptor_sig: &AdaptorSignature,
        adaptor: &PublicKey,
    ) -> Result<SecretKey, Error> {
        let mut data: [u8; constants::SECRET_KEY_SIZE] = [0; constants::SECRET_KEY_SIZE];

        unsafe {
            assert_eq!(
                1,
                ffi::secp256k1_ecdsa_adaptor_extract_secret(
                    self.ctx,
                    data.as_mut_c_ptr(),
                    sig.as_c_ptr(),
                    adaptor_sig.as_c_ptr(),
                    adaptor.as_c_ptr()
                )
            );
        }

        SecretKey::from_slice(&data)
    }
}

impl<C: Verification> Secp256k1<C> {
    /// Verifies that the adaptor secret can be extracted from the adaptor signature and the completed ECDSA signature.
    pub fn adaptor_verify(
        &self,
        msg: &Message,
        adaptor_sig: &AdaptorSignature,
        pubkey: &PublicKey,
        adaptor: &PublicKey,
        adaptor_proof: &AdaptorProof,
    ) -> Result<(), Error> {
        unsafe {
            let res = ffi::secp256k1_ecdsa_adaptor_sig_verify(
                self.ctx,
                adaptor_sig.as_c_ptr(),
                pubkey.as_c_ptr(),
                msg.as_c_ptr(),
                adaptor.as_c_ptr(),
                adaptor_proof.as_c_ptr(),
            );
            return if res == 1 {
                Ok(())
            } else {
                Err(Error::IncorrectSignature)
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{from_hex, Message, PublicKey, Secp256k1, SecretKey, Signature};
    use super::{AdaptorProof, AdaptorSignature};
    use rand::{thread_rng, RngCore};
    use std::str::FromStr;

    macro_rules! hex {
        ($hex:expr) => {{
            let mut result = vec![0; $hex.len() / 2];
            from_hex($hex, &mut result).expect("valid hex string");
            result
        }};
    }

    #[test]
    fn test_adaptor() {
        let secp = Secp256k1::new();

        let (seckey, pubkey) = secp.generate_keypair(&mut thread_rng());
        let (adaptor_secret, adaptor) = secp.generate_keypair(&mut thread_rng());
        let msg = Message::from_slice(&[2u8; 32]).unwrap();
        let (adaptor_sig, adaptor_proof) = secp.adaptor_sign(&msg, &seckey, &adaptor);

        assert!(secp
            .adaptor_verify(&msg, &adaptor_sig, &pubkey, &adaptor, &adaptor_proof)
            .is_ok());
        assert!(!secp
            .adaptor_verify(&msg, &adaptor_sig, &adaptor, &pubkey, &adaptor_proof)
            .is_ok());
        let sig = secp.adaptor_adapt(&adaptor_secret, &adaptor_sig);
        assert!(secp.verify(&msg, &sig, &pubkey).is_ok());
    }

    #[test]
    fn test_adapt_with_schnorr_sig() {
        let secp = Secp256k1::new();
        let rng = &mut thread_rng();
        let (oracle_sk, oracle_pk) = secp.generate_schnorrsig_keypair(rng);
        let mut oracle_k = [0u8; 32];
        rng.fill_bytes(&mut oracle_k);
        let oracle_r_kp = ::schnorrsig::KeyPair::from_seckey_slice(&secp, &oracle_k).unwrap();
        let oracle_r_pk = ::schnorrsig::PublicKey::from_keypair(&secp, &oracle_r_kp);
        let (sk, pk) = secp.generate_keypair(&mut thread_rng());
        let msg = Message::from_slice(&[2u8; 32]).unwrap();

        let adaptor_point = secp
            .schnorrsig_compute_sig_point(&msg, &oracle_r_pk, &oracle_pk)
            .unwrap();
        let (adaptor_sig, _) = secp.adaptor_sign(&msg, &sk, &adaptor_point);

        let oracle_sig = secp.schnorrsig_sign_with_nonce(&msg, &oracle_sk, &oracle_k);
        let (_, adaptor_secret) = oracle_sig.decompose().unwrap();

        let adapted_sig = secp.adaptor_adapt(
            &SecretKey::from_slice(adaptor_secret.as_ref()).unwrap(),
            &adaptor_sig,
        );

        assert!(secp.verify(&msg, &adapted_sig, &pk).is_ok());
    }

    #[test]
    fn test_adaptor_sign() {
        let secp = Secp256k1::new();
        let hex_msg = hex!("024BDD11F2144E825DB05759BDD9041367A420FAD14B665FD08AF5B42056E5E2");
        let msg = Message::from_slice(&hex_msg).unwrap();
        let adaptor = PublicKey::from_str(
            "038D48057FC4CE150482114D43201B333BF3706F3CD527E8767CEB4B443AB5D349",
        )
        .unwrap();
        let sk =
            SecretKey::from_str("90AC0D5DC0A1A9AB352AFB02005A5CC6C4DF0DA61D8149D729FF50DB9B5A5215")
                .unwrap();
        let expected_adaptor_sig = AdaptorSignature::from_str("00CBE0859638C3600EA1872ED7A55B8182A251969F59D7D2DA6BD4AFEDF25F5021A49956234CBBBBEDE8CA72E0113319C84921BF1224897A6ABD89DC96B9C5B208").unwrap();
        let expected_adaptor_proof = AdaptorProof::from_str("00B02472BE1BA09F5675488E841A10878B38C798CA63EFF3650C8E311E3E2EBE2E3B6FEE5654580A91CC5149A71BF25BCBEAE63DEA3AC5AD157A0AB7373C3011D0FC2592A07F719C5FC1323F935569ECD010DB62F045E965CC1D564EB42CCE8D6D").unwrap();

        let (adaptor_sig, adaptor_proof) = secp.adaptor_sign(&msg, &sk, &adaptor);

        assert_eq!(expected_adaptor_sig, adaptor_sig);
        assert_eq!(expected_adaptor_proof, adaptor_proof);
    }

    #[test]
    fn test_adaptor_verify() {
        let secp = Secp256k1::new();
        let hex_msg = hex!("024BDD11F2144E825DB05759BDD9041367A420FAD14B665FD08AF5B42056E5E2");
        let msg = Message::from_slice(&hex_msg).unwrap();
        let adaptor = PublicKey::from_str(
            "038D48057FC4CE150482114D43201B333BF3706F3CD527E8767CEB4B443AB5D349",
        )
        .unwrap();
        let adaptor_sig = AdaptorSignature::from_str("00CBE0859638C3600EA1872ED7A55B8182A251969F59D7D2DA6BD4AFEDF25F5021A49956234CBBBBEDE8CA72E0113319C84921BF1224897A6ABD89DC96B9C5B208").unwrap();
        let adaptor_proof = AdaptorProof::from_str("00B02472BE1BA09F5675488E841A10878B38C798CA63EFF3650C8E311E3E2EBE2E3B6FEE5654580A91CC5149A71BF25BCBEAE63DEA3AC5AD157A0AB7373C3011D0FC2592A07F719C5FC1323F935569ECD010DB62F045E965CC1D564EB42CCE8D6D").unwrap();
        let pubkey = PublicKey::from_str(
            "03490CEC9A53CD8F2F664AEA61922F26EE920C42D2489778BB7C9D9ECE44D149A7",
        )
        .unwrap();

        assert!(secp
            .adaptor_verify(&msg, &adaptor_sig, &pubkey, &adaptor, &adaptor_proof)
            .is_ok());
    }

    #[test]
    fn test_adaptor_adapt() {
        let secp = Secp256k1::new();
        let secret =
            SecretKey::from_str("475697A71A74FF3F2A8F150534E9B67D4B0B6561FAB86FCAA51F8C9D6C9DB8C6")
                .unwrap();
        let adaptor_sig = AdaptorSignature::from_str("01099C91AA1FE7F25C41085C1D3C9E73FE04A9D24DAC3F9C2172D6198628E57F47BB90E2AD6630900B69F55674C8AD74A419E6CE113C10A21A79345A6E47BC74C1").unwrap();
        let expected_signature = Signature::from_str("30440220099C91AA1FE7F25C41085C1D3C9E73FE04A9D24DAC3F9C2172D6198628E57F4702204D13456E98D8989043FD4674302CE90C432E2F8BB0269F02C72AAFEC60B72DE1").unwrap();

        let signature = secp.adaptor_adapt(&secret, &adaptor_sig);

        assert_eq!(expected_signature, signature);
    }

    #[test]
    fn test_adaptor_extract_secret() {
        let secp = Secp256k1::new();

        let sig = Signature::from_str("30440220099C91AA1FE7F25C41085C1D3C9E73FE04A9D24DAC3F9C2172D6198628E57F4702204D13456E98D8989043FD4674302CE90C432E2F8BB0269F02C72AAFEC60B72DE1").unwrap();
        let adaptor_sig = AdaptorSignature::from_str("01099C91AA1FE7F25C41085C1D3C9E73FE04A9D24DAC3F9C2172D6198628E57F47BB90E2AD6630900B69F55674C8AD74A419E6CE113C10A21A79345A6E47BC74C1").unwrap();
        let adaptor = PublicKey::from_str(
            "038D48057FC4CE150482114D43201B333BF3706F3CD527E8767CEB4B443AB5D349",
        )
        .unwrap();
        let expected_secret =
            SecretKey::from_str("475697A71A74FF3F2A8F150534E9B67D4B0B6561FAB86FCAA51F8C9D6C9DB8C6")
                .unwrap();

        let secret = secp
            .adaptor_extract_secret(&sig, &adaptor_sig, &adaptor)
            .unwrap();

        assert_eq!(expected_secret, secret);
    }
}
