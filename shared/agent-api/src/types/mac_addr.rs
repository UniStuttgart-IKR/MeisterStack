// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use std::fmt;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

#[derive(Debug, thiserror::Error)]
pub enum MacAddrError {
    #[error("invalid mac address `{0}`: expected 6 colon-separated hex octets (aa:bb:cc:dd:ee:ff)")]
    Malformed(String),
    #[error("invalid mac address `{input}`: octet `{octet}` is not two hex digits")]
    BadOctet { input: String, octet: String },
}

impl FromStr for MacAddr {
    type Err = MacAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sep = if s.contains('-') { '-' } else { ':' };
        let mut bytes = [0u8; 6];
        let mut count = 0;

        for part in s.split(sep) {
            if count == 6 {
                return Err(MacAddrError::Malformed(s.to_string()));
            }
            if part.len() != 2 {
                return Err(MacAddrError::BadOctet {
                    input: s.to_string(),
                    octet: part.to_string(),
                });
            }
            bytes[count] = u8::from_str_radix(part, 16).map_err(|_| MacAddrError::BadOctet {
                input: s.to_string(),
                octet: part.to_string(),
            })?;
            count += 1;
        }

        if count != 6 {
            return Err(MacAddrError::Malformed(s.to_string()));
        }
        Ok(MacAddr(bytes))
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

impl<'de> serde::Deserialize<'de> for MacAddr {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for MacAddr {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        ser.collect_str(self)
    }
}

#[cfg(test)]
mod mac_tests {
    use super::*;

    #[test]
    fn parses_canonical() {
        let m: MacAddr = "52:54:00:ab:cd:ef".parse().unwrap();
        assert_eq!(m.0, [0x52, 0x54, 0x00, 0xab, 0xcd, 0xef]);
    }

    #[test]
    fn parses_uppercase_and_dashes_normalizes() {
        let m: MacAddr = "52-54-00-AB-CD-EF".parse().unwrap();
        assert_eq!(m.to_string(), "52:54:00:ab:cd:ef");
    }

    #[test]
    fn roundtrip() {
        let m: MacAddr = "de:ad:be:ef:00:01".parse().unwrap();
        assert_eq!(m, m.to_string().parse().unwrap());
    }

    #[test]
    fn rejects_wrong_length_and_garbage() {
        for bad in [
            "",
            "52:54:00:ab:cd",       // zu kurz
            "52:54:00:ab:cd:ef:01", // zu lang
            "52:54:00:ab:cd:zz",    // kein Hex
            "5:54:00:ab:cd:ef",     // Oktett zu kurz
            "052:54:00:ab:cd:ef",   // Oktett zu lang
            "52.54.00.ab.cd.ef",    // falscher Trenner
            "525400abcdef",         // ohne Trenner
        ] {
            assert!(bad.parse::<MacAddr>().is_err(), "accepted: {bad}");
        }
    }
}
