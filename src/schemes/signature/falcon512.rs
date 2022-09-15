use crate::schemes::keypair::Keypair;
use crate::schemes::scheme_info::*;
use crate::schemes::signature::SignatureScheme;
use pqcrypto_falcon::falcon512::*;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
pub struct Falcon512;

impl SignatureScheme for Falcon512 {
    fn get_scheme_info(&self) -> SchemeInfo {
        return SchemeInfo {
            ct_size_info: SizeInfo {
                kind: SizeKind::VariableSized,
                fixed_size: None,
                variable_size_bytelen: Some(2),
            },
            pk_size_info: SizeInfo {
                kind: SizeKind::FixedSized,
                variable_size_bytelen: None,
                fixed_size: Some(897),
            },
        };
    }

    fn generate_keypair(&self, seed: &[u8]) -> Keypair {
        let (pk, sk) = keypair_seed(seed);

        return Keypair {
            pk: pk.as_bytes().to_vec(),
            sk: sk.as_bytes().to_vec(),
        };
    }

    fn sign_message(&self, sk: &[u8], message: &[u8]) -> Vec<u8> {
        let sk = &SecretKey::from_bytes(sk).expect("Secret key loading error");
        return detached_sign(&message, sk).as_bytes().to_vec();
    }

    fn verify_message(&self, message: &[u8], signature: &[u8], pk: &[u8]) -> bool {
        let signature =
            &DetachedSignature::from_bytes(signature).expect("Detached signature loading error");
        let pk = &PublicKey::from_bytes(pk).expect("Public key loading error");
        return verify_detached_signature(signature, message, pk).is_ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{increment_bytes, test_seed};
    
    fn test_seed_full() -> Vec<u8> {
        let mut seed_config = hex::decode("010000").expect("Seed config decode failed");
        let mut test_seed_real = test_seed.to_vec();
        seed_config.append(&mut test_seed_real);
        return seed_config;
    }

    #[test]
    fn falcon_test_seed() {
        let keypair = Falcon512.generate_keypair(&test_seed);
        println!("public key: {}", hex::encode(&keypair.pk));
        let known_pk = hex::decode("096bbda4473ad2f584714f98a7969a567e41d48e5194a1564931f8600279ec53d071e0731c9cc6398421662d6106e6be486e9fb644d28fa6600e22ce91a4c49f5a45f13031664395a5cf11ef8c479ee1a90a4fcd6335a0f9a0dc6b94450245f577e429b0c971f333e64e06a8699a1d9762493934e439943632a2d8721a253d459d0d07476869b4bea1378a69a7748ef670a20e5627b1cb8437a8a58eb089d39c97ad6d113a72252a696a4098891eeebca7450b4bdbef032056f9ca009d7296cebde1385fea30a97ee2daaaff8b2981ebb29c3b40ac6b5b25275e4952f533ace0e372fc0c12834b064f4e0650c011839cb9a2656496bb1f75e290fb49547e51fbd7a9d73120196e82189da196c41191e504e8b385639bf24841287ce782176192148211542d68e49002a2634f475d575241eb51963080cefcd0024ad6b59215542f68b433226ab591951f133586a374d29f91f6003bc5aa3db614b9337e92b13611ea37e81acba050ad61718192036dea89b1e4c849ac1f7260a75157c69e6a9489d1ac62008bb0282ea9c694bb6504a809ac0f96e8e95a67f8802bfb4eb3382a5ea1cb26445aec82143ae4bd2c8146231e999f59f2653473e24f08dcb1e160408a8be45c25ec11bfb6fdef427d18556152725814ea096b44514af510505f716223475d6f68e9a4c29811bfb566924294dcd5863af5c2ca8630a73c9f4336a8850bda47650faee59542c80083e070b03c1890511b5041be20a1caca6963eac923658acd53d86bda764ffd31ac77c5536fb347d6dbc59f4f9991d417597ecad13ec2c0787da30a90bc0c4956dd4a317e58d7344a8bb8ce7db5dfe22f64fed5b540e4492c1d4d409018f0788662955f253b817adc0350d84931b9f2e589eaf95c5e5177a806ff1e7a17a51ca8ae35c5dc1930c6b038ce647905a83e3d22fb2124dcf8641c38868eaa3e6554ba073a0ee19909e6d676876a3a764053460f336496777910511b6fb14e56a3578f4400d8d64d26bc5bb5b4311a1a4f2dac1f357f4e2e84018d99e3255f779c737424e0704b2955f67a46bd509a84a5ba0ca569e18b7071a344b8a0ab6335487a5c0410c0e242f23f192af4c788f843e0e7b7f22f011a81942a2726914c923235f09b8e45c409a092982566b90457b6d72235396567b19f81665cf8bb868969916e92254fd55c16705c570a495379b203627fdced1a74fcf7680d3b058c4be650e51318a98fb2ba04b67a2d2ab059d1e01c5a7a40bec5e0").expect("Decoding known pk failed");
        assert_eq!(keypair.pk, known_pk);
        // Lengths from https://falcon-sign.info/
        assert_eq!(keypair.pk.len(), 897);
        assert_eq!(keypair.sk.len(), 1281);
    }

    #[test]
    fn falcon_test_sign() {
        let keypair = Falcon512.generate_keypair(&test_seed);
        let test_message = "Your Spanish lullaby".as_bytes();
        let signature = Falcon512.sign_message(&keypair.sk, &test_message);
        println!("signature: {}", hex::encode(&signature));
    }

    #[test]
    fn falcon_test_verify() {
        let keypair = Falcon512.generate_keypair(&test_seed);
        let test_message = "Your Spanish lullaby".as_bytes();
        let signature = Falcon512.sign_message(&keypair.sk, &test_message);
        let verified =
            Falcon512.verify_message(&test_message, &signature, &keypair.pk);
        assert_eq!(verified, true);

        let mut modified_msg = test_message.to_vec();
        increment_bytes(&mut modified_msg, 1);
        let verified =
            Falcon512.verify_message(&modified_msg, &signature, &keypair.pk);
        assert_eq!(verified, false);
    }

    #[test]
    fn falcon_test_verify_padded() {
        // Zero padded signatures do NOT work!
        let keypair = Falcon512.generate_keypair(&test_seed);
        let test_message = "Your Spanish lullaby".as_bytes();
        let mut signature = Falcon512.sign_message(&keypair.sk, &test_message);
        signature.resize(666, 0);
        println!("sig: {}", hex::encode(&signature));
        let verified =
            Falcon512.verify_message(&test_message, &signature, &keypair.pk);
        assert_eq!(verified, false);
    }
}