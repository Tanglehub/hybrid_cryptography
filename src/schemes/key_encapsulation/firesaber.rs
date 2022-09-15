use crate::schemes::key_encapsulation::KeyEncapsulationScheme;
use crate::schemes::scheme_info::*;
use crate::schemes::Keypair;
use saber::firesaber::{keygen_seed, keygen, encapsulate, decapsulate, PublicKey, SecretKey, Ciphertext};

pub struct Firesaber;

impl KeyEncapsulationScheme for Firesaber {
    fn get_scheme_info(&self) -> SchemeInfo {
        // Lengths from: https://openquantumsafe.org/liboqs/algorithms/kem/saber
        return SchemeInfo {
            pk_size_info: SizeInfo {
                kind: SizeKind::FixedSized,
                fixed_size: Some(1312),
                variable_size_bytelen: None,
            },
            ct_size_info: SizeInfo {
                kind: SizeKind::FixedSized,
                fixed_size: Some(1472),
                variable_size_bytelen: None,
            },
        };
    }
    fn generate_keypair(&self, seed: &[u8]) -> Keypair {
        let sk = keygen_seed(seed);
        let pk = sk.public_key();
        let pk_bytes: Vec<u8> = pk.to_bytes().into_bytes().to_vec();
        let sk_bytes: Vec<u8> = sk.to_bytes().into_bytes().to_vec();
        return Keypair {
            pk: pk_bytes,
            sk: sk_bytes,
        };
    }

    fn encapsulate(&self, pk_other_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let pk_other = match PublicKey::from_bytes(pk_other_bytes) {
            Ok(pk) => pk,
            Err(err) => panic!("Error decoding public key: {}", err),
        };
        let (ss, ct) = encapsulate(&pk_other);
        return (ss.as_bytes().to_vec(), ct.as_bytes().to_vec());
    }

    fn decapsulate(&self, ct_bytes: &[u8], sk_bytes: &[u8]) -> std::vec::Vec<u8> {
        let secret_key = match SecretKey::from_bytes(sk_bytes) {
            Ok(sk) => sk,
            Err(err) => panic!("Error decoding secret key: {}", err),
        };
        let ciphertext = match Ciphertext::from_bytes(ct_bytes) {
            Ok(ct) => ct,
            Err(err) => panic!("Error decoding ciphertext: {}", err),
        };
        
        let server_secret = decapsulate(&ciphertext, &secret_key);
        return ciphertext.as_bytes().to_vec();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use crate::test_utils::{increment_bytes, test_seed};
    
    fn test_seed_full() -> Vec<u8> {
        let mut seed_config = hex!("010000").to_vec();
        let mut test_seed_real = test_seed.to_vec();
        seed_config.append(&mut test_seed_real);
        return seed_config;
    }

    #[test]
    fn test_cycle() {
        // Consider a server with a key pair
        let server_secret_key = keygen();
        let server_public_key = server_secret_key.public_key();

        // Let a client encapsulate some shared secret for the server
        let (client_secret, ciphertext) = encapsulate(&server_public_key);

        // Have the server decrypt the ciphertext
        let server_secret = decapsulate(&ciphertext, &server_secret_key);

        assert_eq!(client_secret.as_slice(), server_secret.as_slice());
    }
}