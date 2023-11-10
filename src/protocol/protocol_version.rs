//! Code for exchanging and matching a common SQRL protocol version

use crate::error::SqrlError;
use std::fmt;

/// An object representing the SQRL protocol versions supported by a client
/// and/or server
#[derive(Debug, PartialEq)]
pub struct ProtocolVersion {
    versions: u128,
    max_version: u8,
}

impl ProtocolVersion {
    /// Create a new object based on the version string
    pub fn new(versions: &str) -> Result<Self, SqrlError> {
        let mut prot = ProtocolVersion {
            versions: 0,
            max_version: 0,
        };
        for sub in versions.split(',') {
            if sub.contains('-') {
                let mut versions = sub.split('-');

                // Parse out the lower and higher end of the range
                let low: u8 = match versions.next() {
                    Some(x) => x.parse::<u8>()?,
                    None => {
                        return Err(SqrlError::new(format!("Invalid version number {}", sub)));
                    }
                };
                let high: u8 = match versions.next() {
                    Some(x) => x.parse::<u8>()?,
                    None => {
                        return Err(SqrlError::new(format!("Invalid version number {}", sub)));
                    }
                };

                // Make sure the range is valid
                if low >= high {
                    return Err(SqrlError::new(format!("Invalid version number {}", sub)));
                }

                // Set the neccesary values
                for i in low..high + 1 {
                    prot.versions |= 0b00000001 << (i - 1);
                }
                if high > prot.max_version {
                    prot.max_version = high;
                }
            } else {
                let version = sub.parse::<u8>()?;
                prot.versions |= 0b00000001 << (version - 1);
                if version > prot.max_version {
                    prot.max_version = version;
                }
            }
        }

        Ok(prot)
    }

    /// Compares two protocol version objects, returning the highest version
    /// supported by both
    pub fn get_max_matching_version(&self, other: &ProtocolVersion) -> Result<u8, SqrlError> {
        let min_max = if self.max_version > other.max_version {
            other.max_version
        } else {
            self.max_version
        };

        let matches = self.versions & other.versions;

        // Start from the highest match and work our way back
        let bit: u128 = 0b00000001 << min_max;
        for i in 0..min_max {
            if matches & (bit >> i) == bit >> i {
                return Ok(min_max - i + 1);
            }
        }

        Err(SqrlError::new(format!(
            "No matching supported version! Ours: {} Theirs: {}",
            self, other
        )))
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut versions: Vec<String> = Vec::new();
        let mut current_min: Option<u8> = None;
        let mut bit: u128 = 0b00000001;
        for i in 0..self.max_version {
            if self.versions & bit == bit {
                // If we don't have a current min set it.
                // Otherwise, keep going until the range ends
                if current_min.is_none() {
                    current_min = Some(i);
                }
            } else {
                // Did we experience a range, or just a single one?
                if let Some(min) = current_min {
                    if i == min + 1 {
                        // A streak of one
                        versions.push(format!("{}", min + 1));
                    } else {
                        versions.push(format!("{}-{}", min + 1, i));
                    }

                    current_min = None;
                }
            }

            bit <<= 1;
        }

        // If we still have a min set, we need to run that same code again
        if let Some(min) = current_min {
            if self.max_version == min + 1 {
                // A streak of one
                versions.push(format!("{}", min + 1));
            } else {
                versions.push(format!("{}-{}", min + 1, self.max_version));
            }
        }

        write!(f, "{}", versions.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_create_valid_version() {
        ProtocolVersion::new("1,2,6-7").unwrap();
    }

    #[test]
    fn protocol_version_create_invalid_version() {
        if let Ok(version) = ProtocolVersion::new("1,2,7-3") {
            panic!("Version considered valid! {}", version);
        }
    }

    #[test]
    fn protocol_version_match_highest_version() {
        let client = ProtocolVersion::new("1-7").unwrap();
        let server = ProtocolVersion::new("1,3,5").unwrap();
        assert_eq!(5, client.get_max_matching_version(&server).unwrap());
    }

    #[test]
    fn protocol_version_no_version_match() {
        let client = ProtocolVersion::new("1-3,5-7").unwrap();
        let server = ProtocolVersion::new("4,8-12").unwrap();
        if let Ok(x) = client.get_max_matching_version(&server) {
            panic!("Matching version found! {}", x);
        }
    }
}
