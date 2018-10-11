///! Configuration Structures.

/// Configuration root
///
/// Every member of this structure is deserialized from corresponding section
/// of stegos.toml file.
///
/// Don't forget to update stegos.toml.example after adding new options.
///
#[derive(Serialize, Deserialize, Debug)]
#[serde(default)]
pub struct Config {
    /// Network configuration.
    pub network: ConfigNetwork,
}

/// Default values for global configuration.
impl Default for Config {
    fn default() -> Config {
        Config {
            network: Default::default(),
        }
    }
}

/// Network configuration.
#[derive(Serialize, Deserialize, Debug)]
#[serde(default)]
pub struct ConfigNetwork {
    /// An example string configuration value.
    pub strval: String,
    /// An example u32 configuration value.
    pub u32val: u32,
}

/// Default values for network configuration.
impl Default for ConfigNetwork {
    fn default() -> ConfigNetwork {
        ConfigNetwork {
            strval: "default value".to_string(),
            u32val: 0,
        }
    }
}
