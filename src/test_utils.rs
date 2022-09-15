use hex_literal::hex;

pub(crate) const test_seed: [u8; 48] = hex!("fe17131c10c31ebdd26493c4b77553d1e14a826276e627a018fff1c79a7fe4ccb2184ed6b8e2fed27007aa77b4f725c4");

pub(crate) fn increment_bytes(b256: &mut [u8], mut amount: u64) -> u64 {
    let mut i = b256.len() - 1;
    while amount > 0 {
        amount += b256[i] as u64;
        b256[i] = amount as u8;
        amount /= 256;

        if i == 0 {
            break;
        }
        i -= 1;
    }
    amount
}