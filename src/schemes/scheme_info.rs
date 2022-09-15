pub enum AlgorithmPurpose {
    Signature,
    KeyEncapsulation,
}

pub enum SizeKind {
    FixedSized,
    VariableSized,
}

pub struct SizeInfo {
    pub kind: SizeKind,
    pub fixed_size: Option<u32>,
    pub variable_size_bytelen: Option<u8>,
}

pub struct SchemeInfo {
    pub ct_size_info: SizeInfo,
    pub pk_size_info: SizeInfo,
}
