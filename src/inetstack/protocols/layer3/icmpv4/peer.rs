// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::{
    collections::async_queue::AsyncQueue,
    demikernel::config::Config,
    inetstack::protocols::{
        layer2::{SharedLayer2Endpoint, ETHERNET2_HEADER_SIZE},
        layer3::{
            arp::SharedArpPeer,
            icmpv4::{
                header::{Icmpv4Header, ICMPV4_HEADER_SIZE},
                protocol::{Icmpv4Type2, ICMPV4_ECHO_REQUEST_MESSAGE_SIZE},
            },
            ip::IpProtocol,
            ipv4::{Ipv4Header, IPV4_HEADER_MIN_SIZE},
        },
    },
    runtime::{
        conditional_yield_with_timeout, fail::Fail, memory::DemiBuffer, SharedConditionVariable, SharedDemiRuntime,
        SharedObject,
    },
};
use ::futures::FutureExt;
use ::rand::{prelude::SmallRng, Rng, SeedableRng};
use ::std::{
    collections::HashMap,
    net::Ipv4Addr,
    num::Wrapping,
    ops::{Deref, DerefMut},
    process,
    time::Duration,
};

/// Arbitrary time out for waiting for pings.
const PING_TIMEOUT: Duration = Duration::from_secs(5);

//======================================================================================================================
// Icmpv4Peer
//======================================================================================================================

enum InflightRequest {
    Inflight(SharedConditionVariable),
    Complete,
}

pub fn is_local_address(addr: Ipv4Addr, local_addr: Ipv4Addr, mask: Option<Ipv4Addr>) -> bool {
    // Если маска не задана, мы не можем сравнить подсети.
    // Возвращаем true, чтобы стек пытался слать пакет напрямую (как раньше).
    let mask_addr = match mask {
        Some(m) => m,
        None => return true,
    };

    let dest_u32 = u32::from_be_bytes(addr.octets());
    let local_u32 = u32::from_be_bytes(local_addr.octets());
    let mask_u32 = u32::from_be_bytes(mask_addr.octets());

    (dest_u32 & mask_u32) == (local_u32 & mask_u32)
}

///
/// Internet Control Message Protocol (ICMP)
///
/// This is a supporting protocol for the Internet Protocol version 4 (IPv4)
/// suite. It is used by network devices to send error messages and operational
/// information indicating success or failure when communicating with other
/// peers.
///
/// ICMP for IPv4 is defined in RFC 792.
///
pub struct Icmpv4Peer {
    /// Shared DemiRuntime.
    runtime: SharedDemiRuntime,
    /// Underlying Network Transport
    layer2_endpoint: SharedLayer2Endpoint,
    local_ipv4_addr: Ipv4Addr,

    gateway_ipv4_addr: Option<Ipv4Addr>,
    local_netmask: Option<Ipv4Addr>,
    /// enable hardware checksum calculate for ipv4
    pub ipv4_checksum_offload: bool,
    /// Underlying ARP Peer
    arp: SharedArpPeer,

    /// Incoming packets
    recv_queue: AsyncQueue<(Ipv4Header, DemiBuffer)>,

    /// Sequence Number
    seq: Wrapping<u16>,

    /// Random number generator
    rng: SmallRng,

    /// Inflight ping requests.
    inflight: HashMap<(u16, u16), InflightRequest>,
}

#[derive(Clone)]
pub struct SharedIcmpv4Peer(SharedObject<Icmpv4Peer>);

impl SharedIcmpv4Peer {
    pub fn new(
        config: &Config,
        mut runtime: SharedDemiRuntime,
        layer2_endpoint: SharedLayer2Endpoint,
        arp: SharedArpPeer,
        rng_seed: [u8; 32],
    ) -> Result<Self, Fail> {
        let rng = SmallRng::from_seed(rng_seed);
        let peer = Self(SharedObject::new(Icmpv4Peer {
            runtime: runtime.clone(),
            layer2_endpoint: layer2_endpoint.clone(),
            local_ipv4_addr: config.local_ipv4_addr()?,
            gateway_ipv4_addr: config.gateway_ipv4_addr(),
            local_netmask: config.local_netmask(),
            ipv4_checksum_offload: config.tcp_checksum_offload()?,
            arp: arp.clone(),
            recv_queue: AsyncQueue::<(Ipv4Header, DemiBuffer)>::default(),
            seq: Wrapping(0),
            rng,
            inflight: HashMap::<(u16, u16), InflightRequest>::new(),
        }));
        runtime.schedule_coroutine("bgc::inetstack::icmp::background", Box::pin(peer.clone().poll().fuse()))?;
        Ok(peer)
    }

    /// Background task for replying to ICMP messages.
    async fn poll(mut self) {
        loop {
            // Look at incoming request.
            let (header, mut buffer) = match self.recv_queue.pop(Some(PING_TIMEOUT)).await {
                Ok(result) => result,
                Err(_) => break,
            };
            let icmpv4_hdr = match Icmpv4Header::parse_and_strip(&mut buffer) {
                Ok(header) => header,
                Err(e) => {
                    let cause = "Cannot parse ICMP header";
                    warn!("{}: {:?}", cause, e);
                    continue;
                },
            };
            debug!("ICMPv4 received {:?}", icmpv4_hdr);

            // Process incoming request and respond if necessary.
            match icmpv4_hdr.get_protocol() {
                Icmpv4Type2::EchoRequest { id, seq_num } => {
                    if let Err(e) = self
                        .send_packet(Icmpv4Type2::EchoReply { id, seq_num }, header.src_addr(), buffer)
                        .await
                    {
                        warn!("Could not send packet: {:?}", e);
                    }
                },
                Icmpv4Type2::EchoReply { id, seq_num } => {
                    if let Some(InflightRequest::Inflight(cv)) = self.inflight.get_mut(&(id, seq_num)) {
                        cv.signal();
                        self.inflight.insert((id, seq_num), InflightRequest::Complete);
                    } else {
                        warn!("No inflight request matching this reply");
                    }
                },
                _ => {
                    warn!("Unsupported ICMPv4 message: {:?}", icmpv4_hdr);
                },
            };
        }
    }

    pub fn receive(&mut self, header: Ipv4Header, buffer: DemiBuffer) {
        self.recv_queue.push((header, buffer));
    }

    /// Computes the identifier for an ICMP message.
    fn make_id(&mut self) -> u16 {
        let mut state = 0xFFFF;
        let addr_octets = self.local_ipv4_addr.octets();
        state += u16::from_be_bytes([addr_octets[0], addr_octets[1]]) as u32;
        state += u16::from_be_bytes([addr_octets[2], addr_octets[3]]) as u32;

        let mut pid_buf = [0u8; 4];
        pid_buf[0..4].copy_from_slice(&process::id().to_be_bytes());
        state += u16::from_be_bytes([pid_buf[0], pid_buf[1]]) as u32;
        state += u16::from_be_bytes([pid_buf[2], pid_buf[3]]) as u32;

        let nonce: [u8; 2] = self.rng.gen();
        state += u16::from_be_bytes([nonce[0], nonce[1]]) as u32;

        while state > 0xFFFF {
            state -= 0xFFFF;
        }
        !state as u16
    }

    /// Computes sequence number for an ICMP message.
    fn make_seq_num(&mut self) -> u16 {
        let Wrapping(seq_num) = self.seq;
        self.seq += Wrapping(1);
        seq_num
    }

    /// Sends a ping to a remote peer.
    pub async fn ping(&mut self, dst_ipv4_addr: Ipv4Addr, timeout: Option<Duration>) -> Result<Duration, Fail> {
        let id = self.make_id();
        let seq_num = self.make_seq_num();
        let echo_request = Icmpv4Type2::EchoRequest { id, seq_num };

        let t0 = self.runtime.now();
        let pkt = DemiBuffer::new_with_headroom(
            ICMPV4_ECHO_REQUEST_MESSAGE_SIZE,
            (ICMPV4_HEADER_SIZE + IPV4_HEADER_MIN_SIZE as usize + ETHERNET2_HEADER_SIZE) as u16,
        );

        if let Err(e) = self.send_packet(echo_request, dst_ipv4_addr, pkt).await {
            // Ignore for now because the other end will retry.
            // TODO: Implement a retry mechanism so we do not have to wait for the other end to time out.
            // FIXME: https://github.com/microsoft/demikernel/issues/1365
            let cause = format!("Could not send response to ping: {:?}", e);
            warn!("{}", cause);
            return Err(Fail::new(libc::EAGAIN, &cause));
        }

        let condition_variable = SharedConditionVariable::default();
        self.inflight
            .insert((id, seq_num), InflightRequest::Inflight(condition_variable));
        match conditional_yield_with_timeout(
            // Yield into the scheduler until the request completes.
            async {
                while let Some(request) = self.inflight.get(&(id, seq_num)) {
                    match request {
                        InflightRequest::Inflight(condition_variable) => condition_variable.clone().wait().await,
                        InflightRequest::Complete => return,
                    }
                }
            },
            timeout.unwrap_or(PING_TIMEOUT),
        )
        .await
        {
            Ok(_) => {
                self.inflight.remove(&(id, seq_num));
                Ok(self.runtime.now() - t0)
            },
            Err(_) => {
                let message = "timer expired";
                self.inflight.remove(&(id, seq_num));
                error!("ping(): {}", message);
                Err(Fail::new(libc::ETIMEDOUT, message))
            },
        }
    }

    async fn send_packet(
        &mut self,
        request: Icmpv4Type2,
        dst_ip: Ipv4Addr,
        mut buffer: DemiBuffer,
    ) -> Result<(), Fail> {
        debug!("initiating ARP query");

        // Определяем, нужно ли нам идти через шлюз
        let is_local = is_local_address(
            dst_ip,
            self.local_ipv4_addr,
            self.local_netmask, // Здесь возвращается Option
        );

        let next_hop = if is_local {
            dst_ip
        } else {
            // Если адрес не локальный, берем шлюз.
            // Если шлюза тоже нет (is_unspecified), откатываемся на dst_ip.
            match self.gateway_ipv4_addr {
                Some(gw) if !gw.is_unspecified() => gw,
                _ => {
                    warn!("External IP {:?} but no gateway configured, trying direct", dst_ip);
                    dst_ip
                },
            }
        };

        // 2. ARP ЗАПРОС: Мы ищем MAC-адрес соседа (либо цели, либо роутера)
        let dst_mac = self.arp.query(next_hop).await?;

        debug!("ARP query complete ({} -> {})", next_hop, dst_mac);
        debug!("ping ({}, {:?})", dst_ip, request);

        // 3. СБОРКА ICMP
        let icmp_header = Icmpv4Header::new(request, 0);
        icmp_header.serialize_and_attach(&mut buffer);

        // 4. СБОРКА IP: Здесь dst_ip ВСЕГДА оригинальный (цель)
        // Это важно: роутер должен увидеть в IP-заголовке конечный адрес!
        let ip_header = Ipv4Header::new(self.local_ipv4_addr, dst_ip, IpProtocol::ICMPv4);
        ip_header.serialize_and_attach(&mut buffer, self.ipv4_checksum_offload);

        // 5. ОТПРАВКА: Пакет уходит на MAC шлюза, но с IP цели внутри
        self.layer2_endpoint.transmit_ipv4_packet(dst_mac, buffer)
    }
}

//======================================================================================================================
// Trait Implementations
//======================================================================================================================

impl Deref for SharedIcmpv4Peer {
    type Target = Icmpv4Peer;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl DerefMut for SharedIcmpv4Peer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.deref_mut()
    }
}
