// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//======================================================================================================================
// Exports
//======================================================================================================================

mod consts;
mod mempool;

//======================================================================================================================
// Imports
//======================================================================================================================
use crate::inetstack::protocols::layer3::IpProtocol;
use crate::runtime::libdpdk::rte_pktmbuf_free;
use crate::{
    catnip::runtime::{
        consts::{DEFAULT_BODY_POOL_SIZE, DEFAULT_CACHE_SIZE, DEFAULT_MAX_BODY_SIZE},
        mempool::MemoryPool,
    },
    demikernel::config::Config,
    inetstack::{consts::MAX_BATCH_SIZE_NUM_PACKETS, protocols::layer1::PhysicalLayer},
    runtime::{
        fail::Fail,
        libdpdk::{
            rte_delay_us_block, rte_eal_init, rte_errno, rte_eth_conf, rte_eth_dev_configure, rte_eth_dev_count_avail,
            rte_eth_dev_get_mtu, rte_eth_dev_info_get, rte_eth_dev_is_valid_port, rte_eth_dev_set_mtu,
            rte_eth_dev_start, rte_eth_find_next_owned_by, rte_eth_link_get_nowait, rte_eth_promiscuous_enable,
            rte_eth_rss_ip, rte_eth_rx_burst, rte_eth_rx_mq_mode_RTE_ETH_MQ_RX_RSS as RTE_ETH_MQ_RX_RSS,
            rte_eth_rx_offload_tcp_cksum, rte_eth_rx_offload_udp_cksum, rte_eth_rx_queue_setup, rte_eth_rxconf,
            rte_eth_tx_burst, rte_eth_tx_mq_mode_RTE_ETH_MQ_TX_NONE as RTE_ETH_MQ_TX_NONE,
            rte_eth_tx_offload_multi_segs, rte_eth_tx_offload_tcp_cksum, rte_eth_tx_offload_udp_cksum,
            rte_eth_tx_queue_setup, rte_eth_txconf, rte_mbuf, RTE_ETHER_MAX_JUMBO_FRAME_LEN, RTE_ETHER_MAX_LEN,
            RTE_ETH_DEV_NO_OWNER, RTE_ETH_LINK_FULL_DUPLEX, RTE_ETH_LINK_UP, RTE_PKTMBUF_HEADROOM,
        },
        memory::{DemiBuffer, DemiMemoryAllocator},
        SharedObject,
    },
    timer,
};
// RX Offload IPv4 Checksum (бит 1, т.е. значение 2)
const RTE_ETH_RX_OFFLOAD_IPV4_CKSUM: u64 = 1 << 1;

// TX Offload IPv4 Checksum (бит 0, т.е. значение 1)
const RTE_ETH_TX_OFFLOAD_IPV4_CKSUM: u64 = 1 << 1;

use ::arrayvec::ArrayVec;
use ::std::{
    ffi::CString,
    mem,
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
    time::Duration,
};

//======================================================================================================================
// Structures
//======================================================================================================================

pub struct DPDKRuntime {
    max_body_size: usize,
    mem_pool: MemoryPool,
    port_id: u16,
    tcp_checksum_offload: bool,
    udp_checksum_offload: bool,
}

#[derive(Clone)]
pub struct SharedDPDKRuntime(SharedObject<DPDKRuntime>);

//======================================================================================================================
// Associate Functions
//======================================================================================================================

impl SharedDPDKRuntime {
    pub fn new(config: &Config) -> Result<Self, Fail> {
        Self::set_environment_variables();
        Self::dpdk_eal_init(&config.eal_init_args()?)?;

        let port_id = Self::dpdk_eal_find_port()?;

        let jumbo = config.enable_jumbo_frames()?;
        let max_body_size = if jumbo {
            (RTE_ETHER_MAX_JUMBO_FRAME_LEN + RTE_PKTMBUF_HEADROOM) as usize
        } else {
            DEFAULT_MAX_BODY_SIZE
        };

        let mem_pool = Self::initialize_mempool(max_body_size)?;

        let tcp_offload = config.tcp_checksum_offload().is_ok_and(|x| x);
        let udp_offload = config.udp_checksum_offload().is_ok_and(|x| x);

        Self::dpdk_initialize_port(&mem_pool, port_id, jumbo, config.mtu()?, tcp_offload, udp_offload)?;

        Ok(Self(SharedObject::<DPDKRuntime>::new(DPDKRuntime {
            max_body_size,
            mem_pool,
            port_id,
            tcp_checksum_offload: tcp_offload,
            udp_checksum_offload: udp_offload,
        })))
    }

    fn set_environment_variables() {
        std::env::set_var("MLX5_SHUT_UP_BF", "1");
        std::env::set_var("MLX5_SINGLE_THREADED", "1");
        std::env::set_var("MLX4_SINGLE_THREADED", "1");
    }

    fn dpdk_eal_init(eal_init_args: &[CString]) -> Result<(), Fail> {
        let argv = eal_init_args.iter().map(|s| s.as_ptr() as *mut u8).collect::<Vec<_>>();
        let ret = unsafe { rte_eal_init(argv.len() as i32, argv.as_ptr() as *mut _) };

        if ret < 0 {
            let err = unsafe { rte_errno() };
            let msg = format!("EAL init failed (rte_errno={:?})", err);
            error!("{}", msg);
            return Err(Fail::new(libc::EIO, &msg));
        }

        Ok(())
    }

    fn dpdk_eal_find_port() -> Result<u16, Fail> {
        let n = unsafe { rte_eth_dev_count_avail() };
        if n == 0 {
            return Err(Fail::new(libc::EIO, "no ethernet ports available"));
        }

        trace!("{} DPDK ports are available.", n);

        let port = unsafe { rte_eth_find_next_owned_by(0, RTE_ETH_DEV_NO_OWNER as u64) };
        Ok(port as u16)
    }

    fn initialize_mempool(max_body_size: usize) -> Result<MemoryPool, Fail> {
        MemoryPool::new(
            CString::new("body_pool").unwrap(),
            max_body_size,
            DEFAULT_BODY_POOL_SIZE,
            DEFAULT_CACHE_SIZE,
        )
    }

    fn dpdk_initialize_port(
        mem_pool: &MemoryPool,
        port: u16,
        jumbo: bool,
        mtu: u16,
        tcp_checksum_offload: bool,
        udp_checksum_offload: bool,
    ) -> Result<(), Fail> {
        let (rx_rings, tx_rings) = (1, 1);
        let (rx_ring_size, tx_ring_size) = (2048, 2048);
        let (nb_rxd, nb_txd) = (rx_ring_size, tx_ring_size);

        // RX thresholds
        let (rx_pthresh, rx_hthresh, rx_wthresh) = (8, 8, 0);

        // TX thresholds
        let (tx_pthresh, tx_hthresh, tx_wthresh) = (0, 0, 0);

        // Get device info
        let dev_info = unsafe {
            let mut info = MaybeUninit::zeroed();
            rte_eth_dev_info_get(port, info.as_mut_ptr());
            info.assume_init()
        };

        println!("dev_info: {:?}", dev_info);

        // Port config
        let mut port_conf: rte_eth_conf = unsafe { MaybeUninit::zeroed().assume_init() };
        port_conf.rxmode.max_lro_pkt_size = if jumbo {
            RTE_ETHER_MAX_JUMBO_FRAME_LEN
        } else {
            RTE_ETHER_MAX_LEN
        };

        if tcp_checksum_offload {
            port_conf.rxmode.offloads |= unsafe { rte_eth_rx_offload_tcp_cksum() as u64 };
        }
        if udp_checksum_offload {
            port_conf.rxmode.offloads |= unsafe { rte_eth_rx_offload_udp_cksum() as u64 };
        }
        if tcp_checksum_offload || udp_checksum_offload {
            port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_IPV4_CKSUM as u64;
        }
        port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
        port_conf.rx_adv_conf.rss_conf.rss_hf = unsafe { rte_eth_rss_ip() as u64 } | dev_info.flow_type_rss_offloads;

        port_conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;
        if tcp_checksum_offload {
            port_conf.txmode.offloads |= unsafe { rte_eth_tx_offload_tcp_cksum() as u64 };
        }
        if udp_checksum_offload {
            port_conf.txmode.offloads |= unsafe { rte_eth_tx_offload_udp_cksum() as u64 };
        }
        port_conf.txmode.offloads |= unsafe { rte_eth_tx_offload_multi_segs() as u64 };
        if tcp_checksum_offload || udp_checksum_offload {
            port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM as u64;
        }
        // RX config
        println!("DEBUG TX Offloads: {:b}", port_conf.txmode.offloads);
        println!("DEBUG RX Offloads: {:b}", port_conf.rxmode.offloads);
        let mut rx_conf: rte_eth_rxconf = unsafe { MaybeUninit::zeroed().assume_init() };
        rx_conf.rx_thresh.pthresh = rx_pthresh;
        rx_conf.rx_thresh.hthresh = rx_hthresh;
        rx_conf.rx_thresh.wthresh = rx_wthresh;
        rx_conf.rx_free_thresh = 32;

        // TX config
        let mut tx_conf: rte_eth_txconf = unsafe { MaybeUninit::zeroed().assume_init() };
        tx_conf.tx_thresh.pthresh = tx_pthresh;
        tx_conf.tx_thresh.hthresh = tx_hthresh;
        tx_conf.tx_thresh.wthresh = tx_wthresh;
        tx_conf.tx_free_thresh = 32;

        if unsafe { rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf as *const _) } != 0 {
            let msg = format!("failed to configure ethernet device");
            error!("initialize_dpdk_port(): {}", msg);
            return Err(Fail::new(libc::EIO, &msg));
        }

        unsafe {
            if rte_eth_dev_set_mtu(port, mtu) != 0 {
                let msg = format!("failed to set mtu {:?}", mtu);
                error!("initialize_dpdk_port(): {}", msg);
                return Err(Fail::new(libc::EIO, &msg));
            }

            let mut dpdk_mtu = 0u16;
            if (rte_eth_dev_get_mtu(port, &mut dpdk_mtu)) != 0 {
                let msg = format!("failed to get mtu");
                error!("initialize_dpdk_port(): {}", msg);
                return Err(Fail::new(libc::EIO, &msg));
            }

            if dpdk_mtu != mtu {
                let msg = format!("failed to set MTU to {}, got back {}", mtu, dpdk_mtu);
                error!("initialize_dpdk_port(): {}", msg);
                return Err(Fail::new(libc::EIO, &msg));
            }
        }

        let socket_id = 0;

        unsafe {
            for i in 0..rx_rings {
                if rte_eth_rx_queue_setup(port, i, nb_rxd, socket_id, &rx_conf as *const _, mem_pool.into_raw()) != 0 {
                    let msg = format!("failed to set up rx queue");
                    error!("initialize_dpdk_port(): {}", msg);
                    return Err(Fail::new(libc::EIO, &msg));
                }
            }
            for i in 0..tx_rings {
                if rte_eth_tx_queue_setup(port, i, nb_txd, socket_id, &tx_conf as *const _) != 0 {
                    let msg = format!("failed to set up tx ring {:?}", i);
                    error!("initialize_dpdk_port(): {}", msg);
                    return Err(Fail::new(libc::EIO, &msg));
                }
            }
            if rte_eth_dev_start(port) != 0 {
                let msg = "failed to set up ethernet device";
                error!("initialize_dpdk_port(): {}", msg);
                return Err(Fail::new(libc::EIO, msg));
            }
            rte_eth_promiscuous_enable(port);
        }

        if unsafe { rte_eth_dev_is_valid_port(port) } == 0 {
            let msg = "invalid port id";
            error!("initialize_dpdk_port(): {}", msg);
            return Err(Fail::new(libc::EIO, msg));
        }

        let delay = Duration::from_millis(100);
        let mut retries = 90;

        loop {
            unsafe {
                let mut link = MaybeUninit::zeroed();
                rte_eth_link_get_nowait(port, link.as_mut_ptr());
                let link = link.assume_init();

                if link.__bindgen_anon_1.__bindgen_anon_1.link_status() as u32 == RTE_ETH_LINK_UP {
                    let duplex =
                        if link.__bindgen_anon_1.__bindgen_anon_1.link_duplex() as u32 == RTE_ETH_LINK_FULL_DUPLEX {
                            "full"
                        } else {
                            "half"
                        };
                    eprintln!(
                        "Port {} Link Up - speed {} Mbps - {} duplex",
                        port, link.__bindgen_anon_1.__bindgen_anon_1.link_speed, duplex
                    );
                    break;
                }
                rte_delay_us_block(delay.as_micros() as u32);
            }

            if retries == 0 {
                let msg = "link never came up";
                error!("initialize_dpdk_port(): {}", msg);
                return Err(Fail::new(libc::EIO, msg));
            }
            retries -= 1;
        }

        Ok(())
    }

    fn dpdk_allocate_mbuf(&self, size: usize) -> Result<DemiBuffer, Fail> {
        let ptr = self.mem_pool.alloc_mbuf(Some(size))?;
        // Safety: ptr is a valid rte_mbuf from mem_pool
        Ok(unsafe { DemiBuffer::from_mbuf(ptr) })
    }
}

impl Deref for SharedDPDKRuntime {
    type Target = DPDKRuntime;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl DerefMut for SharedDPDKRuntime {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.deref_mut()
    }
}

impl PhysicalLayer for SharedDPDKRuntime {
    fn transmit(&mut self, packets: ArrayVec<DemiBuffer, MAX_BATCH_SIZE_NUM_PACKETS>) -> Result<(), Fail> {
        timer!("catnip::runtime::transmit");

        // In general, this copy will happen for small packets without payloads because we allocate actual
        // data-carrying application buffers from the DPDK pool.
        let count = packets.len();
        let mut mbufs: [*mut rte_mbuf; MAX_BATCH_SIZE_NUM_PACKETS] = unsafe { mem::zeroed() };
        debug!("invoke bad transmit");
        for (i, packet) in packets.into_iter().enumerate() {
            let mbuf_ptr = if packet.is_dpdk_allocated() {
                packet
                    .into_mbuf()
                    .ok_or(Fail::new(libc::EINVAL, "failed to extract DPDK mbuf"))?
            } else if packet.len() <= self.max_body_size {
                let mut mbuf = self.dpdk_allocate_mbuf(packet.len())?;
                debug_assert_eq!(packet.len(), mbuf.len());
                mbuf.copy_from_slice(&packet);
                mbuf.into_mbuf()
                    .ok_or(Fail::new(libc::EINVAL, "failed to convert copied buffer to mbuf"))?
            } else {
                return Err(Fail::new(libc::EINVAL, "packet too large for DPDK buffer"));
            };

            // // --- НАСТРОЙКА OFFLOAD ДЛЯ КАРТЫ ---
            // unsafe {
            //     let m = &mut *mbuf_ptr;
            //     let mut ol_flags: u64 = 0;

            //     // Базовые длины для IPv4
            //     let l2_len: u64 = 14; // Ethernet
            //     let l3_len: u64 = 20; // IPv4 (без опций)

            //     // Проверяем, нужно ли считать чексуму (флаги берем из self)
            //     if self.tcp_checksum_offload {
            //         ol_flags |= (1 << 2) | (1 << 3) | (1 << 52); // IPV4 | IP_CSUM | TCP_CSUM
            //     } else if self.udp_checksum_offload {
            //         ol_flags |= (1 << 2) | (1 << 3) | (1 << 53); // IPV4 | IP_CSUM | UDP_CSUM
            //     }

            //     if ol_flags != 0 {
            //         m.ol_flags |= ol_flags;
            //         // Записываем смещения в tx_offload
            //         // Бит 0-6: L2_len, Бит 7-14: L3_len
            //         m.__bindgen_anon_3.tx_offload = l2_len | (l3_len << 7);
            //     }
            // }

            mbufs[i] = mbuf_ptr;
        }
        // === ВСТАВЛЯЙ СЮДА ===
        // if count > 0 {
        //     unsafe {
        //         let m = &*mbufs[0];

        //         // Пробираемся через дебри bindgen
        //         let ol_flags = m.ol_flags;

        //         // pkt_len и data_len лежат внутри первой анонимной структуры
        //         let pkt_len = m.__bindgen_anon_2.__bindgen_anon_1.pkt_len;
        //         let data_len = m.__bindgen_anon_2.__bindgen_anon_1.data_len;

        //         // tx_offload обычно находится в третьем анонимном блоке (в начале второй кэш-линии)
        //         // Если компилятор ругается на tx_offload, попробуем вытащить его через анонимное поле
        //         let tx_offload = m.__bindgen_anon_3.tx_offload;

        //         println!("--- [DPDK TX Packet 0 Debug] ---");
        //         println!("Data Len: {}, Pkt Len: {}", data_len, pkt_len);
        //         println!("ol_flags: {:#018x}", ol_flags);
        //         println!("tx_offload raw: {:#018x}", tx_offload);

        //         // Декодируем смещения
        //         println!(
        //             "Decoded: L2_len={}, L3_len={}",
        //             tx_offload & 0x7F,
        //             (tx_offload >> 7) & 0x1FF
        //         );
        //         println!("---------------------------------");
        //     }
        // }
        let sent = unsafe { rte_eth_tx_burst(self.port_id, 0, mbufs.as_mut_ptr(), count as u16) };
        debug_assert_eq!(sent, 1);
        Ok(())
    }

    /// Transmit a single packet with hardware offload configuration
    fn transmit_with_offload(
        &mut self,
        packet: DemiBuffer,
        l2_header_len: u8,
        l3_header_len: u8,
        l4_header_len: u8,
        protocol: IpProtocol,
    ) -> Result<(), Fail> {
        timer!("catnip::runtime::transmit_with_offload");

        // 1. Get or allocate mbuf
        let mbuf_ptr = if packet.is_dpdk_allocated() {
            packet
                .into_mbuf()
                .ok_or(Fail::new(libc::EINVAL, "failed to extract DPDK mbuf"))?
        } else if packet.len() <= self.max_body_size {
            let mut mbuf = self.dpdk_allocate_mbuf(packet.len())?;
            mbuf.copy_from_slice(&packet);
            mbuf.into_mbuf()
                .ok_or(Fail::new(libc::EINVAL, "failed to convert copied buffer to mbuf"))?
        } else {
            return Err(Fail::new(libc::EINVAL, "packet too large for DPDK buffer"));
        };

        unsafe {
            let m = &mut *mbuf_ptr;
            let mut ol_flags: u64 = 0;

            // 1. Сначала определяем флаги в зависимости от ваших настроек
            if self.tcp_checksum_offload && protocol == IpProtocol::TCP {
                // RTE_MBUF_F_TX_IPV4 (55) | RTE_MBUF_F_TX_IP_CKSUM (54) | RTE_MBUF_F_TX_TCP_CKSUM (52)
                ol_flags |= (1 << 55) | (1 << 54) | (1 << 52);
            } else if self.udp_checksum_offload && protocol == IpProtocol::UDP {
                // RTE_MBUF_F_TX_IPV4 (55) | RTE_MBUF_F_TX_IP_CKSUM (54) | RTE_MBUF_F_TX_UDP_CKSUM (3 << 52)
                ol_flags |= (1 << 55) | (1 << 54) | (3 << 52);
            } else {
                // Если оффлоад выключен, чексуммы не считаем,
                // но флаг IPV4 (55) лучше оставить, если это IP-пакет.
                ol_flags |= 1 << 55;
            }

            m.ol_flags = ol_flags;

            // 2. Заполняем длины в tx_offload
            // l2_len: 0-6 биты, l3_len: 7-15 биты, l4_len: 16-23 биты
            let l2 = l2_header_len as u64 & 0x7F;
            let l3 = (l3_header_len as u64 & 0x1FF) << 7;
            let l4 = (l4_header_len as u64 & 0xFF) << 16;

            m.__bindgen_anon_3.tx_offload = l2 | l3 | l4;
        }

        // 3. Transmit
        let mut mbufs: [*mut rte_mbuf; 1] = [mbuf_ptr];
        // unsafe {
        //     let m = &*mbuf_ptr;
        //     debug!(
        //         "TX Packet: ol_flags=0x{:x}, l2_len={}, l3_len={}",
        //         m.ol_flags,
        //         m.__bindgen_anon_3.tx_offload & 0x7f,
        //         (m.__bindgen_anon_3.tx_offload >> 7) & 0x1ff
        //     );
        // }
        let sent = unsafe { rte_eth_tx_burst(self.port_id, 0, mbufs.as_mut_ptr(), 1) };

        if sent == 1 {
            //TODO make stats
            //self.stats.tx_packets += 1;
            //self.stats.tx_bytes += packet_len as u64;
            Ok(())
        } else {
            unsafe { rte_pktmbuf_free(mbuf_ptr) };
            //self.stats.tx_dropped_queue_full += 1;
            //TODO make stats
            Err(Fail::new(libc::EAGAIN, "TX queue full"))
        }
    }

    fn receive(&mut self) -> Result<ArrayVec<DemiBuffer, MAX_BATCH_SIZE_NUM_PACKETS>, Fail> {
        timer!("catnip::runtime::receive");

        let mut buffers = ArrayVec::new();
        let mut raw_mbufs: [*mut rte_mbuf; MAX_BATCH_SIZE_NUM_PACKETS] = unsafe { mem::zeroed() };

        let count = unsafe {
            rte_eth_rx_burst(
                self.port_id,
                0,
                raw_mbufs.as_mut_ptr(),
                MAX_BATCH_SIZE_NUM_PACKETS as u16,
            )
        };

        assert!(count as usize <= MAX_BATCH_SIZE_NUM_PACKETS);

        for &mbuf in &raw_mbufs[..count as usize] {
            // Safety: `packet` is a valid pointer to a properly initialized `rte_mbuf` struct.
            let buffer = unsafe { DemiBuffer::from_mbuf(mbuf) };
            buffers.push(buffer);
        }

        Ok(buffers)
    }
}

impl DemiMemoryAllocator for SharedDPDKRuntime {
    fn max_buffer_size_bytes(&self) -> usize {
        self.max_body_size
    }

    fn allocate_demi_buffer(&self, size: usize) -> Result<DemiBuffer, Fail> {
        debug_assert!(size < self.max_body_size);
        self.dpdk_allocate_mbuf(size)
    }
}
