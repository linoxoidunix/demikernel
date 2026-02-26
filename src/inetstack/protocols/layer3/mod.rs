// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//======================================================================================================================
// Imports
//======================================================================================================================

pub mod arp;
pub mod icmpv4;
pub mod ip;
pub mod ipv4;
pub use self::{arp::SharedArpPeer, icmpv4::SharedIcmpv4Peer, ip::IpProtocol, ipv4::Ipv4Header};
use crate::{
    demikernel::config::Config,
    inetstack::{
        consts::MAX_BATCH_SIZE_NUM_PACKETS,
        protocols::layer2::{EtherType2, SharedLayer2Endpoint},
    },
    runtime::{
        fail::Fail,
        memory::{DemiBuffer, DemiMemoryAllocator},
        SharedDemiRuntime, SharedObject,
    },
    MacAddress,
};
use ::arrayvec::ArrayVec;
#[cfg(test)]
use ::std::{collections::HashMap, hash::RandomState, time::Duration};
use ::std::{
    net::Ipv4Addr,
    ops::{Deref, DerefMut},
};

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

//======================================================================================================================
// Structures
//======================================================================================================================

pub struct Layer3Endpoint {
    layer2_endpoint: SharedLayer2Endpoint,
    arp: SharedArpPeer,
    icmpv4: SharedIcmpv4Peer,
    local_ip: Ipv4Addr,
    gateway_ipv4_addr: Option<Ipv4Addr>,
    local_netmask: Option<Ipv4Addr>,
    send_config_mss: usize,
}

#[derive(Clone)]
pub struct SharedLayer3Endpoint(SharedObject<Layer3Endpoint>);

//======================================================================================================================
// Associated Functions
//======================================================================================================================

impl SharedLayer3Endpoint {
    pub fn new(
        config: &Config,
        runtime: SharedDemiRuntime,
        layer2_endpoint: SharedLayer2Endpoint,
        rng_seed: [u8; 32],
    ) -> Result<Self, Fail> {
        let arp = SharedArpPeer::new(config, runtime.clone(), layer2_endpoint.clone())?;
        let gateway_ipv4_addr = config.gateway_ipv4_addr();
        let local_netmask = config.local_netmask();
        let send_config_mss: usize = config.mss().map(|m| m as usize).unwrap_or(1460);
        Ok(SharedLayer3Endpoint(SharedObject::new(Layer3Endpoint {
            arp: arp.clone(),
            icmpv4: SharedIcmpv4Peer::new(config, runtime, layer2_endpoint.clone(), arp, rng_seed)?,
            local_ip: config.local_ipv4_addr()?,
            layer2_endpoint,
            gateway_ipv4_addr,
            local_netmask,
            send_config_mss,
        })))
    }

    // Вспомогательная функция для определения, кому слать ARP
    fn get_next_hop(&self, remote_ip: Ipv4Addr) -> Ipv4Addr {
        if is_local_address(remote_ip, self.local_ip, self.local_netmask) {
            debug!("get_next_hop(): {} is local, routing directly", remote_ip);
            remote_ip
        } else {
            match self.gateway_ipv4_addr {
                Some(gw) if !gw.is_unspecified() => {
                    debug!("get_next_hop(): {} is remote, routing via gateway {}", remote_ip, gw);
                    gw
                },
                _ => {
                    // Если адрес внешний, но шлюз не задан — это потенциальная проблема
                    warn!(
                        "get_next_hop(): {} is remote but no gateway configured! falling back to direct delivery",
                        remote_ip
                    );
                    remote_ip
                },
            }
        }
    }

    //return mss from config
    pub fn send_config_mss(&self) -> usize {
        self.send_config_mss
    }

    pub fn receive(
        &mut self,
    ) -> Result<ArrayVec<(Ipv4Addr, IpProtocol, DemiBuffer), MAX_BATCH_SIZE_NUM_PACKETS>, Fail> {
        let mut batch = ArrayVec::new();
        for (eth2_type, mut packet) in self.layer2_endpoint.receive()? {
            match eth2_type {
                EtherType2::Arp => {
                    self.arp.receive(packet);
                    continue;
                },
                EtherType2::Ipv4 => {
                    let header = match Ipv4Header::parse_and_strip(&mut packet) {
                        Ok(header) => header,
                        Err(e) => {
                            warn!("dropping packet: Invalid destination address: {:?}", e);
                            continue;
                        },
                    };
                    debug!("L3 INCOMING {:?}", header);

                    if !self.is_for_us(header) {
                        warn!("dropping packet: Invalid destination address");
                        continue;
                    }

                    if bad_src(header) {
                        warn!("dropping packet: Invalid source addr ({})", header.src_addr());
                        continue;
                    }

                    let protocol = header.protocol();
                    match protocol {
                        IpProtocol::ICMPv4 => {
                            self.icmpv4.receive(header, packet);
                            continue;
                        },
                        _ => batch.push((header.src_addr(), protocol, packet)),
                    }
                },
                EtherType2::Ipv6 => warn!("Ipv6 not supported yet"), // Ignore for now.
            }
        }
        Ok(batch)
    }

    fn is_for_us(&mut self, header: Ipv4Header) -> bool {
        let dst = header.dst_addr();
        dst == self.local_ip || dst.is_broadcast()
    }

    pub fn transmit_tcp_packet_nonblocking(
        &mut self,
        remote_ip: Ipv4Addr,
        l4_header_len: usize,
        pkt: DemiBuffer,
    ) -> Result<(), Fail> {
        // 1. Определяем, куда отправлять пакет (шлюз или прямой хост)
        let next_hop = self.get_next_hop(remote_ip);

        // 2. Ищем MAC-адрес в ARP-таблице
        let remote_mac = match self.arp.try_query(next_hop) {
            Some(mac) => mac,
            _ => {
                // Если адреса нет, инициируем ARP-запрос (обычно делается внутри try_query)
                return Err(Fail::new(libc::EAGAIN, "destination not in ARP cache"));
            },
        };

        // 3. Передаем пакет дальше с указанием протокола и длины заголовка L4
        // Теперь transmit_packet должен уметь обрабатывать l4_len для настройки mbuf
        self.transmit_packet(remote_ip, remote_mac, IpProtocol::TCP, l4_header_len, pkt)
    }

    pub async fn transmit_tcp_packet_blocking(
        &mut self,
        remote_ip: Ipv4Addr,
        l4_header_len: usize,
        pkt: DemiBuffer,
    ) -> Result<(), Fail> {
        let next_hop = self.get_next_hop(remote_ip);
        let remote_mac = self.arp.query(next_hop).await?;
        self.transmit_packet(remote_ip, remote_mac, IpProtocol::TCP, l4_header_len, pkt)
    }

    pub async fn transmit_udp_packet_blocking(
        &mut self,
        remote_ip: Ipv4Addr,
        l4_header_len: usize,
        pkt: DemiBuffer,
    ) -> Result<(), Fail> {
        let next_hop = self.get_next_hop(remote_ip);
        let remote_mac = self.arp.query(next_hop).await?;
        self.transmit_packet(remote_ip, remote_mac, IpProtocol::UDP, l4_header_len, pkt)
    }

    pub fn transmit_packet(
        &mut self,
        remote_ip: Ipv4Addr,    // Это IP конечного узла (идет в IP заголовок)
        remote_mac: MacAddress, // Это MAC следующего узла (идет в Ethernet заголовок)
        ip_protocol: IpProtocol,
        l4_header_len: usize,
        mut pkt: DemiBuffer,
    ) -> Result<(), Fail> {
        let header = Ipv4Header::new(self.local_ip, remote_ip, ip_protocol);

        // СТАТИКА: Вычисляем размер заголовка ДО сериализации
        // Обычно это 20 байт, но если Ipv4Header поддерживает опции,
        // метод header.compute_size() вернет точное значение.
        let ihl = header.compute_size();

        debug!("L3 OUTGOING {:?}", header);
        header.serialize_and_attach(&mut pkt, self.icmpv4.ipv4_checksum_offload);

        // Теперь передаем размер заголовка и протокол в Layer2
        // Нам нужно добавить эти аргументы в transmit_ipv4_packet
        self.layer2_endpoint.transmit_ipv4_packet_with_offload(
            remote_mac,
            pkt,
            ihl as u8,
            l4_header_len as u8,
            ip_protocol,
        )
    }

    pub fn get_local_addr(&self) -> Ipv4Addr {
        self.local_ip
    }

    #[cfg(test)]
    pub async fn ping(&mut self, addr: Ipv4Addr, timeout: Option<Duration>) -> Result<Duration, Fail> {
        self.icmpv4.ping(addr, timeout).await
    }

    #[cfg(test)]
    pub async fn arp_query(&mut self, addr: Ipv4Addr) -> Result<MacAddress, Fail> {
        self.arp.query(addr).await
    }

    #[cfg(test)]
    pub fn export_arp_cache(&self) -> HashMap<Ipv4Addr, MacAddress, RandomState> {
        self.arp.export_cache()
    }
}

fn bad_src(hdr: Ipv4Header) -> bool {
    let src = hdr.src_addr();
    src.is_broadcast() || src.is_multicast() || src.is_unspecified()
}

//======================================================================================================================
// Trait Implementations
//======================================================================================================================

impl Deref for SharedLayer3Endpoint {
    type Target = Layer3Endpoint;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl DerefMut for SharedLayer3Endpoint {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.deref_mut()
    }
}

/// Memory Runtime Trait Implementation for Layer 3.
impl DemiMemoryAllocator for SharedLayer3Endpoint {
    fn max_buffer_size_bytes(&self) -> usize {
        self.layer2_endpoint.max_buffer_size_bytes()
    }

    fn allocate_demi_buffer(&self, size: usize) -> Result<DemiBuffer, Fail> {
        self.layer2_endpoint.allocate_demi_buffer(size)
    }
}
