use ed25519_zebra::{SigningKey, VerificationKey};
use hex_literal::hex;
use crate::schemes::{Keypair, SchemeInfo, SizeInfo, SizeKind};
use crate::SignatureScheme;

pub struct Ed25519Zebra;

impl SignatureScheme for Ed25519Zebra {
    fn get_scheme_info(&self) -> SchemeInfo {
        return SchemeInfo {
            ct_size_info: SizeInfo {
                kind: SizeKind::FixedSized,
                fixed_size: Some(64),
                variable_size_bytelen: None,
            },
            pk_size_info: SizeInfo {
                kind: SizeKind::FixedSized,
                variable_size_bytelen: None,
                fixed_size: Some(32),
            },
        };
    }

    fn generate_keypair(&self, seed: &[u8]) -> Keypair {
        let mut hasher = blake3::Hasher::new();
        // echo -n "Salt for hashing Ed2219Zebra seeds into static-length seeds as the keygenerator requires it\!" | openssl sha384
        hasher.update(&hex!("a340634e35773aa1692f46914284363e13fc7f3d13ef302da3f008582807556ad72091d1d4b18ce80c7c0ad1e99c78ee"));
        hasher.update(seed);
        let mut seed = [0u8; 32];
        let mut output_reader = hasher.finalize_xof();
        output_reader.fill(&mut seed);

        let sk = SigningKey::from(seed);
        let vk_bytes: [u8; 32] = VerificationKey::from(&sk).into();
        let sk_bytes: [u8; 32] = sk.into();

        return Keypair {
            pk: vk_bytes.to_vec(),
            sk: sk_bytes.to_vec(),
        };
    }

    fn sign_message(&self, sk: &[u8], message: &[u8]) -> Vec<u8> {
        let sk = SigningKey::try_from(sk).unwrap();
        let sig = sk.sign(message);
        let sig_bytes: [u8; 64] = sig.into();
        return sig_bytes.to_vec();
    }

    fn verify_message(&self, message: &[u8], signature: &[u8], pk: &[u8]) -> bool {
        let signature: [u8; 64] = signature.try_into().unwrap();
        VerificationKey::try_from(pk)
            .and_then(|vk| vk.verify(&signature.into(), message))
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use log::debug;
    use test_log::test;
    use super::*;
    use crate::test_utils::{increment_bytes, test_seed};

    #[test]
    fn seed_change_test() {
        let kp = Ed25519Zebra.generate_keypair(&test_seed);
        let mut incremented_seed = test_seed.clone();
        increment_bytes(&mut incremented_seed, 1);
        debug!("test_seed: {}\nincremented_seed: {}", hex::encode(&test_seed), hex::encode(&incremented_seed));
        let kp2 = Ed25519Zebra.generate_keypair(&incremented_seed);
        assert_ne!(kp.pk, kp2.pk);
        assert_ne!(kp.sk, kp2.sk);
    }

    #[test]
    fn test_sign_verify() {
        let kp = Ed25519Zebra.generate_keypair(&test_seed);
        assert_eq!(kp.pk, hex!("4e0da33007ac2fbc7e29f9f23de059d510b5a6a1764628f4aede79c555da67ee"));
        assert_eq!(kp.sk, hex!("38b7765cf4dcbe89c61e61bb2b9c72dcc6ab8168f123790b58eaab2a068acf58"));
        let message = "Test from Peter".as_bytes();
        let signature = Ed25519Zebra.sign_message(&kp.sk, message);
        debug!("Message: {} signature: {}", hex::encode(&message), hex::encode(&signature));
        assert_eq!(signature, hex!("6e5b395b0cb4a5326d08634a70bdfecb0ff1a373a5a448f5c7afe31652854daf462eca1b730b7cfdb8c23a23eb000d193dcca10a93a0fd17ce3f80fef48da20f"));
    }
}