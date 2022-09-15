pub struct ParsedSeed {
    pub seed: Vec<u8>,
    pub signature_scheme_ids: Vec<(u8, u8)>,
    pub key_encapsulation_scheme_ids: Vec<(u8, u8)>,
}

pub fn parse_seed(seed: &[u8]) -> ParsedSeed {
    let seed_len = 48; // SHA384 byte len
    let real_seed = &seed[seed.len() - seed_len..];
    let signature_scheme_bytes_len: u8 = seed[0];
    let key_encapsulation_scheme_bytes_len: u8 = (((seed.len() - seed_len) as u8) - (signature_scheme_bytes_len * 2) - 1) / 2;
    let mut signature_scheme_ids: Vec<(u8, u8)> = Vec::new();
    let mut key_encapsulation_scheme_ids: Vec<(u8, u8)> = Vec::new();
    for n in 0..signature_scheme_bytes_len {
        let offset: usize = (n * 2).into();
        let scheme_id = (seed[offset + 1], seed[offset + 2]);
        signature_scheme_ids.push(scheme_id);
    }
    for n in 0..key_encapsulation_scheme_bytes_len {
        let offset: usize = (n * 2).into();
        let scheme_id = (
            seed[offset + (((signature_scheme_bytes_len * 2) + 1) as usize)],
            seed[offset + (((signature_scheme_bytes_len * 2) + 2) as usize)],
        );
        key_encapsulation_scheme_ids.push(scheme_id);
    }
    return ParsedSeed {
        seed: real_seed.to_vec(),
        signature_scheme_ids,
        key_encapsulation_scheme_ids,
    };
}
