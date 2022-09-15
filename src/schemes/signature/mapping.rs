#[cfg(feature = "falcon")]
use crate::schemes::signature::Falcon512;
use crate::schemes::signature::SchemeInfoReference;
use crate::schemes::signature::SignatureScheme;
use std::collections::HashMap;
#[cfg(feature = "ed25519-zebra")]
use crate::schemes::signature::ed25519_zebra::Ed25519Zebra;

pub fn get_name_to_ref_mapping() -> HashMap<String, SchemeInfoReference> {
    let mut map: HashMap<String, SchemeInfoReference> = HashMap::new();
    #[cfg(feature = "falcon")]
    map.insert(
        "falcon512".to_string(),
        SchemeInfoReference {
            scheme_id: 0,
            scheme_config_id: 0,
            scheme_impl: Box::new(Falcon512),
        },
    );
    #[cfg(feature = "ed25519-zebra")]
    map.insert(
        "ed25519-zebra".to_string(),
        SchemeInfoReference {
            scheme_id: 1,
            scheme_config_id: 0,
            scheme_impl: Box::new(Ed25519Zebra),
        },
    );
    return map;
}

pub fn get_id_to_ref_mapping() -> HashMap<(u8, u8), Box<dyn SignatureScheme>> {
    let mut map: HashMap<(u8, u8), Box<dyn SignatureScheme>> = HashMap::new();
    let name_mapping = get_name_to_ref_mapping();
    for (_k, v) in name_mapping {
        map.insert((v.scheme_id, v.scheme_config_id), v.scheme_impl);
    }
    return map;
}
