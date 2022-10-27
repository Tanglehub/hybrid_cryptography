#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use crate::*;
    use log::{debug, info};
    use test_log::test;
    use crate::AlgorithmPurpose::Signature;
    use crate::schemes::signature::get_name_to_ref_mapping;
    use crate::test_utils::{increment_bytes, test_seed};

    #[test]
    #[cfg(feature = "falcon")]
    fn test_seed_generator() {
        let seed1 = generate_random_seed(&["falcon512".to_string()], &[]);
        let seed2 = generate_random_seed(&["falcon512".to_string()], &[]);
        assert_ne!(&seed1, &seed2);
        assert_eq!(&seed1[1..3], &[0, 0]);
        assert_eq!(&seed2[1..3], &[0, 0]);
    }

    #[test]
    fn test_all_signature_algorithms() {
        let mapping = get_name_to_ref_mapping();
        let test_msg = hex!("CAFEBABE");
        for (name, scheme_ref) in mapping.iter() {
            info!("Testing {}...", name);
            let seed = wrap_seed(&[name.to_string()], &[], test_seed);
            let signature = sign_message(&seed, &test_msg);
            debug!("Signature: {}", hex::encode(&signature));
            let combined_public_key = generate_combined_public_key(Signature, &seed);
            let is_valid = verify_message(&test_msg, &combined_public_key, &signature);
            assert_eq!(is_valid, true);
            let mut test_msg_increased = test_msg.clone();
            increment_bytes(&mut test_msg_increased, 1);
            let is_valid = verify_message(&test_msg_increased, &combined_public_key, &signature);
            assert_eq!(is_valid, false);
        }
    }

    #[test]
    fn test_fake_combined_public_key() {
        let mapping = get_name_to_ref_mapping();
        let test_msg = hex!("CAFEBABE");
        println!("mapping: {:?}", mapping.len());
        for (name, scheme_ref) in mapping.iter() {
            info!("Testing {}...", name);
            let seed = wrap_seed(&[name.to_string()], &[], test_seed);
            let signature = sign_message(&seed, &test_msg);
            let real_combined_public_key = generate_combined_public_key(Signature, &seed);
            debug!("real_combined_public_key: {}", hex::encode(&real_combined_public_key));
            debug!("Signature: {}", hex::encode(&signature));
            // Try a bunch of fake combined public keys
            for i in 0..100 {
                let mut combined_public_key = [0u8; 48];
                getrandom::getrandom(&mut combined_public_key).expect("Random seed could not be loaded!");
                let is_valid = verify_message(&test_msg, &combined_public_key, &signature);
                assert_eq!(is_valid, false);
            }
            // Try a bunch of fake combined public keys but real algorithm selection
            for i in 0..100 {
                let mut combined_public_key = [0u8; 6];
                getrandom::getrandom(&mut combined_public_key).expect("Random seed could not be loaded!");
                let start = hex!("0100");
                let fake_key = vec![start.to_vec(), combined_public_key.to_vec()].concat();
                debug!("fake_key: {}", hex::encode(&fake_key));
                let is_valid = verify_message(&test_msg, &fake_key, &signature);
                assert_eq!(is_valid, false);
            }
        }
    }
}
