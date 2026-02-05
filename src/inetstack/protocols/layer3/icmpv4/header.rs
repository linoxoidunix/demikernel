// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//======================================================================================================================
// Imports
//======================================================================================================================

use crate::{
    inetstack::protocols::{compute_generic_checksum, fold16, layer3::icmpv4::protocol::Icmpv4Type2},
    runtime::{fail::Fail, memory::DemiBuffer},
};
use ::libc::EBADMSG;

//======================================================================================================================
// Constants
//======================================================================================================================

/// Size of ICMPv4 Headers (in bytes)
pub const ICMPV4_HEADER_SIZE: usize = 8;

//======================================================================================================================
// Structures
//======================================================================================================================

#[derive(Copy, Clone, Debug)]
pub struct Icmpv4Header {
    protocol: Icmpv4Type2,
    // TODO: Turn this into an enum on Icmpv4Type2 and then collapse the struct.
    code: u8,
}

//======================================================================================================================
// Associate Functions
//======================================================================================================================

impl Icmpv4Header {
    pub fn new(icmpv4_type: Icmpv4Type2, code: u8) -> Self {
        Self {
            protocol: icmpv4_type,
            code,
        }
    }

    /// Strips and parses the ICMP header from the packet in [buffer].
    pub fn parse_and_strip(buffer: &mut DemiBuffer) -> Result<Self, Fail> {
        if buffer.len() < ICMPV4_HEADER_SIZE {
            return Err(Fail::new(EBADMSG, "ICMPv4 datagram too small for header"));
        }
        let header: &[u8; ICMPV4_HEADER_SIZE] = &buffer[..ICMPV4_HEADER_SIZE].try_into().unwrap();

        let type_byte = header[0];
        let code = header[1];
        if Self::compute_checksum(header, &buffer[ICMPV4_HEADER_SIZE..]) != 0 {
            return Err(Fail::new(EBADMSG, "ICMPv4 checksum mismatch"));
        }
        let remaining_header = header[4..8].try_into().unwrap();
        let icmpv4_type = Icmpv4Type2::parse(type_byte, remaining_header)?;

        buffer.adjust(ICMPV4_HEADER_SIZE)?;
        Ok(Self {
            protocol: icmpv4_type,
            code,
        })
    }

    /// Serializes and prepends the ICMP header into the packet in [buffer]. This function assumes that the packet has
    /// sufficient headroom to fit the ICMP header.
    pub fn serialize_and_attach(&self, buffer: &mut DemiBuffer) {
        buffer.prepend(ICMPV4_HEADER_SIZE).expect("Should have headroom");

        let (type_byte, rest_of_header) = self.protocol.serialize();
        buffer[0] = type_byte;
        buffer[1] = self.code;
        // Skip the checksum for now.
        buffer[2] = 0;
        buffer[3] = 0;
        buffer[4..8].copy_from_slice(&rest_of_header[..]);
        let (header, payload) = buffer[..].split_at(ICMPV4_HEADER_SIZE);
        let checksum = Self::compute_checksum(header, payload);
        println!("compute icmpv4 checksum:{}", checksum);
        buffer[2..4].copy_from_slice(&checksum.to_be_bytes());
    }

    /// Computes the checksum of the target ICMPv4 header. We can assume that the header buffer is the right size
    /// because we just split it from the body up above.
    fn compute_checksum(buffer: &[u8], body: &[u8]) -> u16 {
        let mut checksum = compute_generic_checksum(buffer, None);
        checksum = compute_generic_checksum(body, Some(checksum));
        fold16(checksum)
    }

    pub fn get_protocol(&self) -> Icmpv4Type2 {
        self.protocol
    }
}
