//! # Schnorrsig
//! Support for Schnorr signatures.
//!

use super::{from_hex, Error};
use core::{fmt, str};
use ffi::{self, CPtr};
use {constants, PublicKey, Secp256k1, SecretKey};
use {Message, Signing};

/// Represents a schnorr signature.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct SchnorrSignature(ffi::SchnorrSignature);

impl fmt::Debug for SchnorrSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::LowerHex for SchnorrSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for ch in self.0.iter().enumerate() {
            write!(f, "{:02x}", ch.1)?;
        }
        Ok(())
    }
}

impl fmt::Display for SchnorrSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl str::FromStr for SchnorrSignature {
    type Err = Error;
    fn from_str(s: &str) -> Result<SchnorrSignature, Error> {
        let mut res = [0; constants::SCHNORR_SIGNATURE_SIZE];
        match from_hex(s, &mut res) {
            Ok(constants::SCHNORR_SIGNATURE_SIZE) => {
                SchnorrSignature::from_slice(&res[0..constants::SCHNORR_SIGNATURE_SIZE])
            }
            _ => Err(Error::InvalidSchnorrSignature),
        }
    }
}

impl From<ffi::SchnorrSignature> for SchnorrSignature {
    #[inline]
    fn from(adaptor_sig: ffi::SchnorrSignature) -> SchnorrSignature {
        SchnorrSignature(adaptor_sig)
    }
}

impl CPtr for SchnorrSignature {
    type Target = ffi::SchnorrSignature;
    fn as_c_ptr(&self) -> *const Self::Target {
        self.as_ptr()
    }

    fn as_mut_c_ptr(&mut self) -> *mut Self::Target {
        self.as_mut_ptr()
    }
}

impl SchnorrSignature {
    /// Creates an SchnorrSignature directly from a slice
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<SchnorrSignature, Error> {
        match data.len() {
            constants::SCHNORR_SIGNATURE_SIZE => {
                let mut ret = [0; constants::SCHNORR_SIGNATURE_SIZE];
                ret[..].copy_from_slice(data);
                Ok(SchnorrSignature(ffi::SchnorrSignature::from_array(ret)))
            }
            _ => Err(Error::InvalidSchnorrSignature),
        }
    }

    /// Obtains a raw const pointer suitable for use with FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::SchnorrSignature {
        &self.0 as *const _
    }

    /// Obtains a raw mutable pointer suitable for use with FFI functions
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::SchnorrSignature {
        &mut self.0 as *mut _
    }
}

impl<C: Signing> Secp256k1<C> {
    /// Create a schnorr signature.
    pub fn schnorr_sign(
        &self,
        msg: &Message,
        sk: &SecretKey,
        aux_rand: &[u8; 32],
    ) -> Result<SchnorrSignature, Error> {
        unsafe {
            let mut keypair = ffi::KeyPair::new();
            let ret = ffi::secp256k1_keypair_create(self.ctx, &mut keypair, sk.as_c_ptr());
            if ret == 0 {
                return Err(Error::InvalidSecretKey);
            }

            let mut sig = ffi::SchnorrSignature::new();
            assert_eq!(
                1,
                ffi::secp256k1_schnorrsig_sign(
                    self.ctx,
                    &mut sig,
                    msg.as_c_ptr(),
                    &keypair,
                    ffi::secp256k1_nonce_function_bip340,
                    aux_rand.as_c_ptr() as *const ffi::types::c_void
                )
            );

            Ok(SchnorrSignature(sig))
        }
    }

    /// Verify a schnorr signature.
    pub fn schnorr_verify(
        &self,
        sig: &SchnorrSignature,
        msg: &Message,
        pubkey: &PublicKey,
    ) -> Result<(), Error> {
        unsafe {
            let mut xonly_pubkey = ffi::XOnlyPublicKey::new();
            let mut pk_parity: ffi::types::c_int = 0;
            let mut ret = ffi::secp256k1_xonly_pubkey_from_pubkey(
                self.ctx,
                &mut xonly_pubkey,
                &mut pk_parity,
                pubkey.as_c_ptr(),
            );

            if ret == 0 {
                return Err(Error::InvalidPublicKey);
            }

            ret = ffi::secp256k1_schnorrsig_verify(
                self.ctx,
                sig.as_c_ptr(),
                msg.as_c_ptr(),
                &xonly_pubkey,
            );

            return if ret == 1 {
                Ok(())
            } else {
                Err(Error::InvalidSchnorrSignature)
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{from_hex, Message, PublicKey, Secp256k1, SecretKey};
    use super::{SchnorrSignature};
    use std::convert::TryInto;
    use std::str::FromStr;

    macro_rules! hex {
        ($hex:expr) => {{
            let mut result = vec![0; $hex.len() / 2];
            from_hex($hex, &mut result).expect("valid hex string");
            result
        }};
    }

    #[test]
    fn test_schnorr_sign() {
        let secp = Secp256k1::new();

        let hex_msg = hex!("E48441762FB75010B2AA31A512B62B4148AA3FB08EB0765D76B252559064A614");
        let msg = Message::from_slice(&hex_msg).unwrap();
        let sk =
            SecretKey::from_str("688C77BC2D5AAFF5491CF309D4753B732135470D05B7B2CD21ADD0744FE97BEF")
                .unwrap();
        let aux_rand: Box<[u8; 32]> =
            hex!("02CCE08E913F22A36C5648D6405A2C7C50106E7AA2F1649E381C7F09D16B80AB")
                .into_boxed_slice()
                .try_into()
                .unwrap();
        let expected_sig = SchnorrSignature::from_str("6470FD1303DDA4FDA717B9837153C24A6EAB377183FC438F939E0ED2B620E9EE5077C4A8B8DCA28963D772A94F5F0DDF598E1C47C137F91933274C7C3EDADCE8").unwrap();

        let sig = secp.schnorr_sign(&msg, &sk, &*aux_rand).unwrap();

        assert_eq!(expected_sig, sig);
    }

    #[test]
    fn test_schnorr_verify() {
        let secp = Secp256k1::new();

        let hex_msg = hex!("E48441762FB75010B2AA31A512B62B4148AA3FB08EB0765D76B252559064A614");
        let msg = Message::from_slice(&hex_msg).unwrap();
        let sig = SchnorrSignature::from_str("6470FD1303DDA4FDA717B9837153C24A6EAB377183FC438F939E0ED2B620E9EE5077C4A8B8DCA28963D772A94F5F0DDF598E1C47C137F91933274C7C3EDADCE8").unwrap();
        let pubkey = PublicKey::from_str(
            "02B33CC9EDC096D0A83416964BD3C6247B8FECD256E4EFA7870D2C854BDEB33390",
        )
        .unwrap();

        assert!(secp.schnorr_verify(&sig, &msg, &pubkey).is_ok());
    }
}
