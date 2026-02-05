// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//======================================================================================================================
// Imports
//======================================================================================================================

use crate::{
    inetstack::protocols::layer3::ip::IpProtocol,
    runtime::{fail::Fail, memory::DemiBuffer},
};
use ::libc::{EBADMSG, ENOTSUP};
use ::std::net::Ipv4Addr;

//======================================================================================================================
// Constants
//======================================================================================================================

/// Minimum size of IPv4 header (in bytes).
pub const IPV4_HEADER_MIN_SIZE: u16 = IPV4_DATAGRAM_MIN_SIZE;

/// Maximum size of IPv4 header (in bytes).
pub const IPV4_HEADER_MAX_SIZE: u16 = 60;

/// Minimum size for an IPv4 datagram (in bytes).
const IPV4_DATAGRAM_MIN_SIZE: u16 = 20;

/// IPv4 header length when no options are present (in 32-bit words).
const IPV4_IHL_NO_OPTIONS: u8 = (IPV4_HEADER_MIN_SIZE as u8) / 4;

/// Default time to live value.
const DEFAULT_IPV4_TTL: u8 = 255;

/// Version number for IPv4.
const IPV4_VERSION: u8 = 4;

/// IPv4 Control Flag: Datagram has evil intent (see RFC 3514).
const IPV4_CTRL_FLAG_EVIL: u8 = 0x4;

/// IPv4 Control Flag: Don't Fragment.
const IPV4_CTRL_FLAG_DF: u8 = 0x2;

/// IPv4 Control Flag: More Fragments.
const IPV4_CTRL_FLAG_MF: u8 = 0x1;

//======================================================================================================================
// Structures
//======================================================================================================================

/// IPv4 Datagram Header
#[derive(Debug, Copy, Clone)]
pub struct Ipv4Header {
    /// Internet header version (4 bits).
    version: u8,
    /// Internet Header Length. (4 bits).
    ihl: u8,
    /// Differentiated Services Code Point (6 bits).
    dscp: u8,
    /// Explicit Congestion Notification (2 bits).
    ecn: u8,
    /// Total length of the packet including header and data (16 bits).
    #[allow(unused)]
    total_length: u16,
    /// Used to identify the datagram to which a fragment belongs (16 bits).
    identification: u16,
    /// Control flags (3 bits).
    flags: u8,
    /// Fragment offset indicates where in the datagram this fragment belongs to (13 bits).
    fragment_offset: u16,
    /// Time to Live indicates the maximum remaining time the datagram is allowed to be in the network (8 bits).
    ttl: u8,
    /// Protocol used in the data portion of the datagram (8 bits).
    protocol: IpProtocol,
    /// Header-only checksum for error detection (16 bits).
    #[allow(unused)]
    header_checksum: u16,
    // Source IP address (32 bits).
    src_addr: Ipv4Addr,
    /// Destination IP address (32 bits).
    dst_addr: Ipv4Addr,
}

//======================================================================================================================
// Associated Functions
//======================================================================================================================

impl Ipv4Header {
    pub fn new(src_addr: Ipv4Addr, dst_addr: Ipv4Addr, protocol: IpProtocol) -> Self {
        Self {
            version: IPV4_VERSION,
            ihl: IPV4_IHL_NO_OPTIONS,
            dscp: 0,
            ecn: 0,
            total_length: IPV4_HEADER_MIN_SIZE,
            identification: 0,
            flags: IPV4_CTRL_FLAG_DF,
            fragment_offset: 0,
            ttl: DEFAULT_IPV4_TTL,
            protocol,
            header_checksum: 0,
            src_addr,
            dst_addr,
        }
    }

    pub fn compute_size(&self) -> usize {
        (self.ihl as usize) << 2
    }

    /// Parses and strips the IPv4 header from the packet in [buf].
    pub fn parse_and_strip(buf: &mut DemiBuffer) -> Result<Self, Fail> {
        // The datagram should be as big as the header.
        if buf.len() < (IPV4_DATAGRAM_MIN_SIZE as usize) {
            return Err(Fail::new(EBADMSG, "ipv4 datagram too small"));
        }

        let version = buf[0] >> 4;
        if version != IPV4_VERSION {
            return Err(Fail::new(ENOTSUP, "unsupported IP version"));
        }

        // Internet header length.
        let ihl = buf[0] & 0xF;
        let hdr_size = (ihl as u16) << 2;
        if hdr_size < IPV4_HEADER_MIN_SIZE {
            return Err(Fail::new(EBADMSG, "ipv4 IHL is too small"));
        }
        if buf.len() < hdr_size as usize {
            return Err(Fail::new(EBADMSG, "ipv4 datagram too small to fit in header"));
        }
        let hdr_buf = &buf[..hdr_size as usize];

        // Differentiated services code point.
        let dscp = hdr_buf[1] >> 2;
        if dscp != 0 {
            warn!("ignoring dscp field (dscp={:?})", dscp);
        }

        // Explicit congestion notification.
        let ecn = hdr_buf[1] & 3;
        if ecn != 0 {
            warn!("ignoring ecn field (ecn={:?})", ecn);
        }

        let total_length = u16::from_be_bytes([hdr_buf[2], hdr_buf[3]]);
        if total_length < hdr_size {
            return Err(Fail::new(EBADMSG, "ipv4 datagram smaller than header"));
        }
        // NOTE: there may be padding bytes in the buffer.
        if (total_length as usize) > buf.len() {
            return Err(Fail::new(EBADMSG, "ipv4 datagram size mismatch"));
        }

        // Identification (Id).
        //
        // Note: We had a (now removed) bug here in that we were _requiring_ all incoming datagrams to have an Id field
        // of zero.  This was horribly misguided.  With the exception of datagramss where the DF (don't fragment) flag
        // is set, all IPv4 datagrams are _required_ to have a (temporally) unique identification field for datagrams
        // with the same source, destination, and protocol.  Thus we should expect most datagrams to have a non-zero Id.
        let identification = u16::from_be_bytes([hdr_buf[4], hdr_buf[5]]);

        // Control flags.
        //
        // Note: We had a (now removed) bug here in that we were _requiring_ all incoming datagrams to have the DF
        // (don't fragment) bit set.  This appears to be because we don't support fragmentation (yet anyway).  But the
        // lack of a set DF bit doesn't make a datagram a fragment.  So we should accept datagrams regardless of the
        // setting of this bit.
        let flags = hdr_buf[6] >> 5;
        // Don't accept evil datagrams (see RFC 3514).
        if flags & IPV4_CTRL_FLAG_EVIL != 0 {
            return Err(Fail::new(EBADMSG, "ipv4 datagram is marked as evil"));
        }

        // TODO: drop this check once we support fragmentation.
        if flags & IPV4_CTRL_FLAG_MF != 0 {
            warn!("fragmentation is not supported flags={:?}", flags);
            return Err(Fail::new(ENOTSUP, "ipv4 fragmentation is not supported"));
        }

        let fragment_offset = u16::from_be_bytes([hdr_buf[6], hdr_buf[7]]) & 0x1fff;
        // TODO: drop this check once we support fragmentation.
        if fragment_offset != 0 {
            warn!("fragmentation is not supported offset={:?}", fragment_offset);
            return Err(Fail::new(ENOTSUP, "ipv4 fragmentation is not supported"));
        }

        let time_to_live = hdr_buf[8];
        if time_to_live == 0 {
            return Err(Fail::new(EBADMSG, "ipv4 datagram too old"));
        }

        let protocol = IpProtocol::try_from(hdr_buf[9])?;

        let header_checksum = u16::from_be_bytes([hdr_buf[10], hdr_buf[11]]);
        if header_checksum == 0xffff {
            return Err(Fail::new(EBADMSG, "ipv4 checksum invalid"));
        }
        if header_checksum != Self::compute_checksum(hdr_buf) {
            return Err(Fail::new(EBADMSG, "ipv4 checksum mismatch"));
        }

        let src_addr = Ipv4Addr::new(hdr_buf[12], hdr_buf[13], hdr_buf[14], hdr_buf[15]);
        let dst_addr = Ipv4Addr::new(hdr_buf[16], hdr_buf[17], hdr_buf[18], hdr_buf[19]);

        // Truncate datagram.
        let padding_bytes = buf.len() - (total_length as usize);
        buf.adjust(hdr_size as usize)?;
        buf.trim(padding_bytes)?;

        Ok(Self {
            version,
            ihl,
            dscp,
            ecn,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl: time_to_live,
            protocol,
            header_checksum,
            src_addr,
            dst_addr,
        })
    }

    /// Serializes the IPv4 header and prepends it to the packet in [buf]. Assumes that there is enough headroom for
    /// the header.
    pub fn serialize_and_attach(&self, buf: &mut DemiBuffer, calc_hardware_ipv4_checksum_offload: bool) {
        buf.prepend(IPV4_HEADER_MIN_SIZE as usize)
            .expect("Should be sufficient headroom");
        let pkt_size_bytes = buf.len();
        // Version + IHL.
        buf[0] = (self.version << 4) | self.ihl;

        // DSCP + ECN.
        buf[1] = (self.dscp << 2) | (self.ecn & 3);

        // Total Length.
        buf[2..4].copy_from_slice(&(pkt_size_bytes as u16).to_be_bytes());

        // Identification.
        buf[4..6].copy_from_slice(&self.identification.to_be_bytes());

        // Flags and Fragment Offset.
        buf[6..8].copy_from_slice(&((self.flags as u16) << 13 | self.fragment_offset & 0x1fff).to_be_bytes());

        // Time to Live.
        buf[8] = self.ttl;

        // Protocol.
        buf[9] = self.protocol as u8;

        // Skip the checksum (bytes 10..12) until we finish writing the header.

        // Source Address.
        buf[12..16].copy_from_slice(&self.src_addr.octets());

        // Destination Address.
        buf[16..20].copy_from_slice(&self.dst_addr.octets());
        // ВАЖНО: Обнуляем поле чексуммы в буфере.
        // 1. ПРИНУДИТЕЛЬНО обнуляем поле чексуммы в буфере перед расчетом
        // не уверен что для hardware это надо
        if buf.len() >= 12 {
            buf[10] = 0;
            buf[11] = 0;
        }
        //activate software checksum calculate
        if !calc_hardware_ipv4_checksum_offload {
            // 2. Считаем чексумму ТОЛЬКО по заголовку (20 байт)
            let checksum = Self::compute_checksum(&buf[..IPV4_HEADER_MIN_SIZE as usize]);

            // 3. Записываем результат обратно в буфер
            buf[10..12].copy_from_slice(&checksum.to_be_bytes());
            debug!(
                "L3 Checksum fixed calc by software: 0x{:04x} for total_len: {}",
                checksum,
                buf.len()
            );
        }
    }

    pub fn src_addr(&self) -> Ipv4Addr {
        self.src_addr
    }

    pub fn dst_addr(&self) -> Ipv4Addr {
        self.dst_addr
    }

    pub fn protocol(&self) -> IpProtocol {
        self.protocol
    }

    pub fn compute_checksum(buf: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        // Перебираем заголовок по 2 байта
        for i in (0..buf.len()).step_by(2) {
            // Если это байты 10 и 11 (поле чексуммы), пропускаем их (считаем как 0)
            if i == 10 {
                continue;
            }

            let word = if i + 1 < buf.len() {
                u16::from_be_bytes([buf[i], buf[i + 1]])
            } else {
                // Если заголовок нечетный (на всякий случай)
                (buf[i] as u16) << 8
            };
            sum += word as u32;
        }

        // Складываем переносы
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        // Инвертируем результат
        !(sum as u16)
    }
}
