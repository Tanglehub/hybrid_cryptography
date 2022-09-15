use crate::schemes::keypair::Keypair;
use crate::schemes::SchemeInfo;

pub trait KeyEncapsulationScheme {
    fn get_scheme_info(&self) -> SchemeInfo;
    fn generate_keypair(&self, seed: &[u8]) -> Keypair;
    fn encapsulate(&self, pk_other_bytes: &[u8]) -> (Vec<u8>, Vec<u8>);
    fn decapsulate(&self, ct_bytes: &[u8], sk_bytes: &[u8]) -> std::vec::Vec<u8>;
}
