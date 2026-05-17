/// Fragment: a numbered chunk of payload data.
#[derive(Clone, Debug)]
pub struct Fragment {
    pub sequence_id: u16,
    pub data: Vec<u8>,
}
