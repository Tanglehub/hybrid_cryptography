use crate::schemes::signature::SignatureScheme;

pub struct SchemeInfoReference {
    pub scheme_id: u8,
    pub scheme_config_id: u8,
    pub scheme_impl: Box<dyn SignatureScheme>,
}
