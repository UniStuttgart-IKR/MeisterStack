// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PciAddress {
    pub domain: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

#[derive(Debug, thiserror::Error)]
pub enum PciAddressError {
    #[error("invalid pci address `{0}`: expected [dddd:]bb:dd.f (hex)")]
    Malformed(String),
    #[error("invalid pci address `{input}`: {field} `{value}` is not valid hex")]
    BadHex {
        input: String,
        field: &'static str,
        value: String,
    },
    #[error("invalid pci address `{input}`: device {device:#x} out of range (max 0x1f)")]
    DeviceOutOfRange { input: String, device: u32 },
    #[error("invalid pci address `{input}`: function {function:#x} out of range (max 0x7)")]
    FunctionOutOfRange { input: String, function: u32 },
}

impl FromStr for PciAddress {
    type Err = PciAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let malformed = || PciAddressError::Malformed(s.to_string());

        let (front, func_str) = s.rsplit_once('.').ok_or_else(malformed)?;

        let parts: Vec<&str> = front.split(':').collect();
        let (dom_str, bus_str, dev_str) = match parts.as_slice() {
            [bus, dev] => ("0", *bus, *dev),
            [dom, bus, dev] => (*dom, *bus, *dev),
            _ => return Err(malformed()),
        };

        if dom_str.is_empty() || bus_str.is_empty() || dev_str.is_empty() || func_str.is_empty() {
            return Err(malformed());
        }

        let parse = |field: &'static str, v: &str| -> Result<u32, PciAddressError> {
            u32::from_str_radix(v, 16).map_err(|_| PciAddressError::BadHex {
                input: s.to_string(),
                field,
                value: v.to_string(),
            })
        };

        let domain = parse("domain", dom_str)?;
        let bus = parse("bus", bus_str)?;
        let device = parse("device", dev_str)?;
        let function = parse("function", func_str)?;

        if domain > u16::MAX as u32 {
            return Err(malformed());
        }
        if bus > u8::MAX as u32 {
            return Err(malformed());
        }
        if device > 0x1f {
            return Err(PciAddressError::DeviceOutOfRange {
                input: s.to_string(),
                device,
            });
        }
        if function > 0x7 {
            return Err(PciAddressError::FunctionOutOfRange {
                input: s.to_string(),
                function,
            });
        }

        Ok(Self {
            domain: domain as u16,
            bus: bus as u8,
            device: device as u8,
            function: function as u8,
        })
    }
}

impl fmt::Display for PciAddress {
    /// Always the full, normalised form — identical to the sysfs name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04x}:{:02x}:{:02x}.{}",
            self.domain, self.bus, self.device, self.function
        )
    }
}

impl PciAddress {
    pub fn sysfs_path(&self) -> PathBuf {
        PathBuf::from(format!("/sys/bus/pci/devices/{self}"))
    }
}

impl<'de> serde::Deserialize<'de> for PciAddress {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for PciAddress {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.collect_str(self)
    }
}

// TESTS

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_form() {
        let a: PciAddress = "0000:23:00.0".parse().unwrap();
        assert_eq!((a.domain, a.bus, a.device, a.function), (0, 0x23, 0, 0));
    }

    #[test]
    fn parses_short_form_with_zero_domain() {
        let a: PciAddress = "23:00.1".parse().unwrap();
        assert_eq!((a.domain, a.bus, a.device, a.function), (0, 0x23, 0, 1));
    }

    #[test]
    fn parses_uppercase_and_normalizes() {
        let a: PciAddress = "0000:AF:1F.7".parse().unwrap();
        assert_eq!(a.to_string(), "0000:af:1f.7");
    }

    #[test]
    fn roundtrip_display_parse() {
        let a: PciAddress = "0002:b3:1a.5".parse().unwrap();
        let b: PciAddress = a.to_string().parse().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn rejects_device_over_1f() {
        assert!(matches!(
            "0000:00:20.0".parse::<PciAddress>(),
            Err(PciAddressError::DeviceOutOfRange { .. })
        ));
    }

    #[test]
    fn rejects_function_over_7() {
        assert!(matches!(
            "0000:00:00.8".parse::<PciAddress>(),
            Err(PciAddressError::FunctionOutOfRange { .. })
        ));
    }

    #[test]
    fn rejects_garbage() {
        for bad in [
            "",
            "hallo",
            "23:00",
            "23.00.0",
            "0000:23:00.0.1",
            "zz:00.0",
            "23::00.0",
            ":23:00.0",
            "10000:00:00.0",
        ] {
            assert!(bad.parse::<PciAddress>().is_err(), "accepted: {bad}");
        }
    }

    #[test]
    fn sysfs_path_matches_kernel_layout() {
        let a: PciAddress = "23:00.0".parse().unwrap();
        assert_eq!(
            a.sysfs_path(),
            PathBuf::from("/sys/bus/pci/devices/0000:23:00.0")
        );
    }
}
