use crate::schemes::keypair::Keypair;
use crate::schemes::SchemeInfo;

pub trait SignatureScheme {
    fn get_scheme_info(&self) -> SchemeInfo;
    fn generate_keypair(&self, seed: &[u8]) -> Keypair;
    fn sign_message(&self, sk: &[u8], message: &[u8]) -> Vec<u8>;
    fn verify_message(&self, message: &[u8], signature: &[u8], pk: &[u8]) -> bool;
}