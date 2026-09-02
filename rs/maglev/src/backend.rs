#[derive(Clone, Debug)]
pub struct Backend {
    pub name: String,
    pub ip: [u8; 4],
}

impl Backend {
    pub fn new(name: &str, ip: [u8; 4]) -> Self {
        Self { name: name.to_string(), ip }
    }
}
