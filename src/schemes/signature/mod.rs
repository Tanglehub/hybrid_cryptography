#[cfg(feature = "falcon")]
mod falcon512;
mod mapping;
mod scheme_info_reference;
mod signature_scheme;

#[cfg(feature="ed25519-zebra")]
mod ed25519_zebra;

#[cfg(feature = "falcon")]
pub use falcon512::Falcon512;
pub use mapping::{get_id_to_ref_mapping, get_name_to_ref_mapping};
pub use scheme_info_reference::SchemeInfoReference;
pub use signature_scheme::SignatureScheme;
