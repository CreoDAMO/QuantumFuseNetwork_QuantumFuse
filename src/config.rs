#[derive(Debug, Deserialize, Clone)]

pub struct Config {

    pub bind_address: String,

    pub log_level: String,

    pub qusd_mint_limit: u128,

    pub attack_probability: f64,

    pub rate_limit: u64,

    pub ddos_threshold: u64,

    pub sybil_threshold: usize,

    pub validator_rotation_interval: u64,

    pub collateral_ratio: f64,

    pub governance_quorum: f64,

}
