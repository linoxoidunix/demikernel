// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// TODO: Move this component to the `network-simulator` crate.

//======================================================================================================================
// Imports
//======================================================================================================================

use crate::{
    ensure_eq,
    inetstack::{
        consts::MAX_HEADER_SIZE,
        protocols::{
            layer2::{EtherType2, Ethernet2Header},
            layer3::{ip::IpProtocol, ipv4::Ipv4Header},
            layer4::{
                tcp::header::{TcpHeader, TcpOptions2, MAX_TCP_OPTIONS},
                udp::header::UdpHeader,
            },
        },
        test_helpers::{self, engine::SharedEngine, physical_layer::SharedTestPhysicalLayer},
    },
    runtime::{memory::DemiBuffer, OperationResult},
    MacAddress, QDesc, QToken,
};
use ::anyhow::Result;
use ::std::{
    collections::VecDeque,
    env,
    fs::File,
    io::{BufRead, BufReader},
    net::{Ipv4Addr, SocketAddrV4},
    path::{self},
    time::Instant,
};
use network_simulator::glue::{
    AcceptArgs, Action, BindArgs, CloseArgs, ConnectArgs, DemikernelSyscall, Event, ListenArgs, PacketDirection,
    PacketEvent, PopArgs, PushArgs, PushToArgs, SocketArgs, SocketDomain, SocketProtocol, SocketType, SyscallEvent,
    TcpOption, TcpPacket, UdpPacket, WaitArgs,
};

//======================================================================================================================
// Tests
//======================================================================================================================

#[test]
fn test_run_simulation() -> Result<()> {
    let verbose = false;
    let local_mac = test_helpers::ALICE_MAC;
    let remote_mac = test_helpers::BOB_MAC;
    let local_port = 12345;
    let local_ephemeral_port = 65535;
    let local_ipv4 = test_helpers::ALICE_IPV4;
    let remote_port = 23456;
    let remote_ephemeral_port = 65535;
    let remote_ipv4 = test_helpers::BOB_IPV4;

    let path = match env::var("INPUT") {
        Ok(p) => p,
        Err(e) => {
            let cause = format!("missing INPUT environment variable (err={:?})", e);
            warn!("test_simulation(): {:?}", cause);
            anyhow::bail!(cause);
        },
    };

    let tests = collect_tests(&path)?;

    if tests.is_empty() {
        let cause = format!("no tests found under {:?}", path);
        warn!("test_simulation(): {:?}", cause);
        return Ok(());
    }

    for test in &tests {
        eprintln!("running test case: {:?}", test);

        let mut simulation = Simulation::new(
            test,
            &local_mac,
            local_port,
            local_ephemeral_port,
            &local_ipv4,
            &remote_mac,
            remote_port,
            remote_ephemeral_port,
            &remote_ipv4,
        )?;
        simulation.run(verbose)?;
    }

    Ok(())
}

fn collect_tests(test_path: &str) -> Result<Vec<String>> {
    let mut files = Vec::new();
    let path = path::Path::new(test_path);

    if path.is_dir() {
        let mut directories = vec![test_path.to_string()];

        // Recurse through all directories.
        while let Some(directory) = directories.pop() {
            for entry in std::fs::read_dir(&directory)? {
                let p = entry?.path();
                let s = p.to_str().unwrap().to_string();

                if p.is_file() && p.extension().is_some_and(|ext| ext == "pkt") {
                    files.push(s);
                } else if p.is_dir() {
                    directories.push(s);
                }
            }
        }
        files.sort();
    } else {
        // It is not a directory, so just add the file.
        let fname = path.to_str().unwrap().to_string();
        files.push(fname);
    }
    Ok(files)
}

//======================================================================================================================
// Standalone Functions
//======================================================================================================================

struct Simulation {
    protocol: Option<IpProtocol>,
    local_mac: MacAddress,
    local_sockaddr: SocketAddrV4,
    local_port: u16,
    remote_mac: MacAddress,
    remote_sockaddr: SocketAddrV4,
    remote_port: u16,
    local_qd: Option<(u32, QDesc)>,
    remote_qd: Option<(u32, Option<QDesc>)>,
    engine: SharedEngine,
    now: Instant,
    inflight: VecDeque<QToken>,
    lines: Vec<String>,
}

impl Simulation {
    pub fn new(
        filename: &str,
        local_mac: &MacAddress,
        local_port: u16,
        local_ephemeral_port: u16,
        local_ipv4: &Ipv4Addr,
        remote_mac: &MacAddress,
        remote_port: u16,
        remote_ephemeral_port: u16,
        remote_ipv4: &Ipv4Addr,
    ) -> Result<Simulation> {
        let now = Instant::now();

        let test_rig = SharedTestPhysicalLayer::new(now);
        let local = SharedEngine::new(test_helpers::ALICE_CONFIG_PATH, test_rig, now)?;

        info!("Local: sockaddr={:?}, macaddr={:?}", local_ipv4, local_mac);
        info!("Remote: sockaddr={:?}, macaddr={:?}", remote_ipv4, remote_mac);

        let lines = Self::read_input_file(filename)?;

        Ok(Simulation {
            protocol: None,
            local_mac: *local_mac,
            remote_mac: *remote_mac,
            engine: local,
            now,
            local_qd: None,
            remote_qd: None,
            inflight: VecDeque::with_capacity(4),
            local_sockaddr: SocketAddrV4::new(*local_ipv4, local_ephemeral_port),
            local_port,
            remote_sockaddr: SocketAddrV4::new(*remote_ipv4, remote_ephemeral_port),
            remote_port,
            lines,
        })
    }

    fn read_input_file(filename: &str) -> Result<Vec<String>> {
        let reader = BufReader::new(File::open(filename)?);
        let mut lines = Vec::new();

        for line in reader.lines().map_while(Result::ok) {
            lines.push(line);
        }

        Ok(lines)
    }

    pub fn run(&mut self, verbose: bool) -> Result<()> {
        for line in &self.lines.clone() {
            if verbose {
                info!("Line: {:?}", line);
            }

            if let Some(event) = network_simulator::run_parser(line, verbose)? {
                self.run_event(&event)?;
            }
        }

        // Ensure that there are no more events to be processed.
        let frames = self.engine.pop_expected_frames(0);
        if !frames.is_empty() {
            for f in &frames {
                info!("run(): {:?}", f);
            }
            anyhow::bail!("run(): unexpected outgoing frames");
        }

        Ok(())
    }

    fn run_event(&mut self, event: &Event) -> Result<()> {
        self.now += event.time;
        self.engine.advance_clock(self.now);

        match &event.action {
            Action::SyscallEvent(syscall) => self.run_syscall(syscall)?,
            Action::PacketEvent(packet) => self.run_packet(packet)?,
        }

        Ok(())
    }

    #[allow(unused_variables)]
    fn run_syscall(&mut self, syscall: &SyscallEvent) -> Result<()> {
        info!("{:?}: {:?}", self.now, syscall);
        match &syscall.syscall {
            DemikernelSyscall::Socket(args, ret) => self.run_socket_syscall(args, *ret)?,
            DemikernelSyscall::Bind(args, ret) => self.run_bind_syscall(args, *ret)?,
            DemikernelSyscall::Listen(args, ret) => self.run_listen_syscall(args, *ret)?,
            DemikernelSyscall::Accept(args, fd) => self.run_accept_syscall(args, *fd)?,
            DemikernelSyscall::Connect(args, ret) => self.run_connect_syscall(args, *ret)?,
            DemikernelSyscall::Push(args, ret) => self.run_push_syscall(args, *ret)?,
            DemikernelSyscall::PushTo(args, ret) => self.run_pushto_syscall(args, *ret)?,
            DemikernelSyscall::Pop(args, ret) => self.run_pop_syscall(args, *ret)?,
            DemikernelSyscall::Wait(args, ret) => self.run_wait_syscall(args, *ret)?,
            DemikernelSyscall::Close(args, ret) => self.run_close_syscall(args, *ret)?,
            DemikernelSyscall::Unsupported => {
                error!("Unsupported syscall");
            },
        }

        Ok(())
    }

    fn run_packet(&mut self, packet: &PacketEvent) -> Result<()> {
        info!("{:?}: {:?}", self.now, packet);
        match packet {
            PacketEvent::Tcp(direction, tcp_packet) => match direction {
                PacketDirection::Incoming => self.run_incoming_packet(tcp_packet)?,
                PacketDirection::Outgoing => self.run_outgoing_packet(tcp_packet)?,
            },
            PacketEvent::Udp(direction, udp_packet) => match direction {
                PacketDirection::Incoming => self.run_incoming_udp_packet(udp_packet)?,
                PacketDirection::Outgoing => self.run_outgoing_udp_packet(udp_packet)?,
            },
        }

        Ok(())
    }

    fn run_socket_syscall(&mut self, args: &SocketArgs, ret: i32) -> Result<()> {
        if args.domain != SocketDomain::AF_INET {
            let cause = format!("unsupported domain socket domain (domain={:?})", args.domain);
            info!("run_socket_syscall(): {:?}", cause);
            anyhow::bail!(cause);
        }

        match args.typ {
            SocketType::SOCK_STREAM => {
                if args.protocol != SocketProtocol::IPPROTO_TCP {
                    let cause = format!("unsupported socket protocol (protocol={:?})", args.protocol);
                    info!("run_socket_syscall(): {:?}", cause);
                    anyhow::bail!(cause);
                }

                match self.engine.tcp_socket() {
                    Ok(qd) => {
                        self.local_qd = Some((ret as u32, qd));
                        self.protocol = Some(IpProtocol::TCP);
                        Ok(())
                    },
                    Err(err) if ret == err.errno => Ok(()),
                    _ => {
                        info!("run_socket_syscall(): ret={:?}", ret);
                        anyhow::bail!("unexpected return for socket syscall");
                    },
                }
            },
            SocketType::SOCK_DGRAM => {
                if args.protocol != SocketProtocol::IPPROTO_UDP {
                    let cause = format!("unsupported socket protocol (protocol={:?})", args.protocol);
                    info!("run_socket_syscall(): {:?}", cause);
                    anyhow::bail!(cause);
                }

                match self.engine.udp_socket() {
                    Ok(qd) => {
                        self.local_qd = Some((ret as u32, qd));
                        self.remote_qd = Some((ret as u32, None));
                        self.protocol = Some(IpProtocol::UDP);
                        Ok(())
                    },
                    Err(err) if ret == err.errno => Ok(()),
                    _ => {
                        info!("run_socket_syscall(): ret={:?}", ret);
                        anyhow::bail!("unexpected return for socket syscall");
                    },
                }
            },
        }
    }

    fn run_bind_syscall(&mut self, args: &BindArgs, ret: i32) -> Result<()> {
        let local_bind_addr = match args.addr {
            None => {
                self.local_sockaddr.set_port(self.local_port);
                self.local_sockaddr
            },

            // Custom bind address is not supported.
            Some(addr) => {
                let cause = format!("unsupported bind address (addr={:?})", addr);
                info!("run_bind_syscall(): {:?}", cause);
                anyhow::bail!(cause);
            },
        };

        let local_qd = match args.qd {
            Some(local_fd) => match self.local_qd {
                Some((fd, qd)) if fd == local_fd => qd,
                _ => {
                    let cause = "local queue descriptor mismatch";
                    info!("run_bind_syscall(): {:?}", cause);
                    anyhow::bail!(cause);
                },
            },
            None => {
                let cause = "local queue descriptor must have been previously assigned";
                info!("run_bind_syscall(): {:?}", cause);
                anyhow::bail!(cause);
            },
        };

        match self.engine.tcp_bind(local_qd, local_bind_addr) {
            Ok(()) if ret == 0 => Ok(()),
            Err(err) if ret == err.errno => Ok(()),
            _ => {
                info!("run_bind_syscall(): ret={:?}", ret);
                anyhow::bail!("unexpected return for bind syscall");
            },
        }
    }

    fn run_listen_syscall(&mut self, args: &ListenArgs, ret: i32) -> Result<()> {
        let backlog = match args.backlog {
            Some(b) => b,
            None => {
                let cause = "backlog length must be informed";
                info!("run_listen_syscall(): {:?}", cause);
                anyhow::bail!(cause);
            },
        };

        let local_qd = match args.qd {
            Some(local_fd) => match self.local_qd {
                Some((fd, qd)) if fd == local_fd => qd,
                _ => {
                    let cause = "local queue descriptor mismatch";
                    info!("run_listen_syscall(): {:?}", cause);
                    anyhow::bail!(cause);
                },
            },
            None => {
                let cause = "local queue descriptor must have been previously assigned";
                info!("run_listen_syscall(): {:?}", cause);
                anyhow::bail!(cause);
            },
        };

        match self.engine.tcp_listen(local_qd, backlog) {
            Ok(()) if ret == 0 => Ok(()),
            Err(err) if ret == err.errno => Ok(()),
            _ => {
                info!("run_listen_syscall(): ret={:?}", ret);
                anyhow::bail!("unexpected return for listen syscall");
            },
        }
    }

    fn run_accept_syscall(&mut self, args: &AcceptArgs, ret: i32) -> Result<()> {
        let local_qd = match args.qd {
            Some(local_fd) => match self.local_qd {
                Some((fd, qd)) if fd == local_fd => qd,
                _ => {
                    let cause = "local queue descriptor mismatch";
                    info!("run_accept_syscall(): {:?}", cause);
                    anyhow::bail!(cause);
                },
            },
            None => {
                let cause = "local queue descriptor must have been previously assigned";
                info!("run_accept_syscall(): {:?}", cause);
                anyhow::bail!(cause);
            },
        };

        match self.engine.tcp_accept(local_qd) {
            Ok(accept_qt) => {
                self.remote_qd = Some((ret as u32, None));
                self.inflight.push_back(accept_qt);
                Ok(())
            },
            Err(err) if ret == err.errno => Ok(()),
            _ => {
                info!("run_accept_syscall(): ret={:?}", ret);
                anyhow::bail!("unexpected return for accept syscall");
            },
        }
    }

    fn run_connect_syscall(&mut self, args: &ConnectArgs, ret: i32) -> Result<()> {
        let local_qd = match self.local_qd {
            Some((_, qd)) => qd,
            None => {
                let cause = "local queue descriptor must have been previously assigned";
                info!("run_connect_syscall(): {:?}", cause);
                anyhow::bail!(cause);
            },
        };

        let remote_addr = match args.addr {
            None => {
                self.remote_sockaddr = SocketAddrV4::new(*self.remote_sockaddr.ip(), self.remote_port);
                self.remote_sockaddr
            },
            Some(addr) => {
                // Unsupported remote address.
                let cause = format!("unsupported remote address (addr={:?})", addr);
                info!("run_connect_syscall(): {:?}", cause);
                anyhow::bail!(cause);
            },
        };

        match self.engine.tcp_connect(local_qd, remote_addr) {
            Ok(connect_qt) => {
                self.inflight.push_back(connect_qt);
                Ok(())
            },
            Err(err) if ret == err.errno => Ok(()),
            _ => {
                info!("run_accept_syscall(): ret={:?}", ret);
                anyhow::bail!("unexpected return for connect syscall");
            },
        }
    }

    fn run_push_syscall(&mut self, args: &PushArgs, ret: i32) -> Result<()> {
        let buffer_length = match args.len {
            Some(l) => l.try_into()?,
            None => {
                let cause = "buffer length must be informed";
                info!("run_push_syscall(): {:?}", cause);
                anyhow::bail!(cause);
            },
        };

        let syscall_qd = match args.qd {
            // 500 in the annotation will represent the local queue descriptor number because they are allocated
            // starting at 500.
            Some(500) => match self.local_qd {
                Some((_, qd)) => qd,
                None => {
                    info!("run_push_syscall(): ret={:?}", ret);
                    anyhow::bail!("unexpected return for push syscall");
                },
            },
            _ => match self.remote_qd {
                Some((_, Some(qd))) => qd,
                _ => {
                    info!("run_push_syscall(): ret={:?}", ret);
                    anyhow::bail!("unexpected return for push syscall");
                },
            },
        };

        let buffer = Self::prepare_dummy_buffer(buffer_length, None);
        match self.engine.tcp_push(syscall_qd, buffer) {
            Ok(push_qt) => {
                self.inflight.push_back(push_qt);
                Ok(())
            },
            Err(err) if ret == err.errno => Ok(()),
            _ => {
                info!("run_push_syscall(): ret={:?}", ret);
                anyhow::bail!("unexpected return for push syscall");
            },
        }
    }

    fn run_pop_syscall(&mut self, args: &PopArgs, ret: i32) -> Result<()> {
        let remote_qd = match args.qd {
            500 => match self.local_qd {
                Some((_, qd)) => qd,
                None => {
                    info!("run_pop_syscall(): ret={:?}", ret);
                    anyhow::bail!("unexpected return for pushto syscall");
                },
            },
            _ => match self.remote_qd {
                Some((_, Some(qd))) => qd,
                _ => {
                    info!("run_pop_syscall(): ret={:?}", ret);
                    anyhow::bail!("unexpected return for pop syscall");
                },
            },
        };

        match self.protocol {
            Some(IpProtocol::TCP) => match self.engine.tcp_pop(remote_qd) {
                Ok(pop_qt) => {
                    self.inflight.push_back(pop_qt);
                    Ok(())
                },
                Err(err) if ret == err.errno => Ok(()),
                _ => {
                    info!("run_pop_syscall(): ret={:?}", ret);
                    anyhow::bail!("unexpected return for pop syscall");
                },
            },
            Some(IpProtocol::UDP) => match self.engine.udp_pop(remote_qd) {
                Ok(pop_qt) => {
                    self.inflight.push_back(pop_qt);
                    Ok(())
                },
                Err(err) if ret == err.errno => Ok(()),
                _ => {
                    info!("run_pop_syscall(): ret={:?}", ret);
                    anyhow::bail!("unexpected return for pop syscall");
                },
            },
            _ => {
                let cause = "protocol must have been previously assigned";
                info!("run_pop_syscall(): {:?}", cause);
                anyhow::bail!(cause);
            },
        }
    }

    fn run_wait_syscall(&mut self, _: &WaitArgs, ret: i32) -> Result<()> {
        match self.has_operation_completed() {
            Ok((qd, qr)) => match qr {
                OperationResult::Accept((remote_qd, remote_addr)) if ret == 0 => {
                    info!("connection accepted (qd={:?}, addr={:?})", qd, remote_addr);
                    self.remote_qd = Some((self.remote_qd.unwrap().0, Some(remote_qd)));
                    Ok(())
                },
                OperationResult::Connect => {
                    info!("connection established as expected (qd={:?})", qd);
                    Ok(())
                },
                OperationResult::Pop(_sockaddr, _data) => {
                    info!("pop completed as expected (qd={:?})", qd);
                    Ok(())
                },
                OperationResult::Push => {
                    info!("push completed as expected (qd={:?})", qd);
                    Ok(())
                },
                OperationResult::Close => {
                    info!("close completed as expected (qd={:?})", qd);
                    Ok(())
                },
                OperationResult::Failed(e) if e.errno == ret => {
                    info!("operation failed as expected (qd={:?}, errno={:?})", qd, e.errno);
                    Ok(())
                },
                OperationResult::Failed(e) => {
                    unreachable!("operation failed unexpectedly (qd={:?}, errno={:?})", qd, e.errno);
                },
                _ => unreachable!("unexpected operation has completed"),
            },
            _ => unreachable!("no operation has completed, but it should"),
        }
    }

    fn run_pushto_syscall(&mut self, args: &PushToArgs, ret: i32) -> Result<()> {
        let buffer_length = match args.len {
            Some(len) => len.try_into()?,
            None => {
                let cause = "buffer length must be informed";
                info!("run_pushto_syscall(): {:?}", cause);
                anyhow::bail!(cause);
            },
        };

        let remote_addr = match args.addr {
            None => {
                self.remote_sockaddr = SocketAddrV4::new(*self.remote_sockaddr.ip(), self.remote_port);
                self.remote_sockaddr
            },
            Some(addr) => {
                // Unsupported remote address.
                let cause = format!("unsupported remote address (addr={:?})", addr);
                info!("run_pushto_syscall(): {:?}", cause);
                anyhow::bail!(cause);
            },
        };

        let remote_qd = match args.qd {
            Some(500) => match self.local_qd {
                Some((_, qd)) => qd,
                None => {
                    info!("run_pushto_syscall(): ret={:?}", ret);
                    anyhow::bail!("unexpected return for pushto syscall");
                },
            },
            _ => match self.remote_qd {
                Some((_, Some(qd))) => qd,
                _ => {
                    info!("run_pushto_syscall(): ret={:?}", ret);
                    anyhow::bail!("unexpected return for pushto syscall");
                },
            },
        };

        let buffer = Self::prepare_dummy_buffer(buffer_length, None);
        match self.engine.udp_pushto(remote_qd, buffer, remote_addr) {
            Ok(push_qt) => {
                self.inflight.push_back(push_qt);
                Ok(())
            },
            _ => {
                info!("run_pushto_syscall(): ret={:?}", ret);
                anyhow::bail!("unexpected return for pushto syscall");
            },
        }
    }

    fn run_close_syscall(&mut self, args: &CloseArgs, ret: i32) -> Result<()> {
        let qd = match args.qd {
            500 => match self.local_qd {
                Some((_, qd)) => qd,
                None => {
                    info!("run_close_syscall(): ret={:?}", ret);
                    anyhow::bail!("unexpected return for close syscall");
                },
            },
            _ => match self.remote_qd {
                Some((_, Some(qd))) => qd,
                _ => {
                    info!("run_close_syscall(): ret={:?}", ret);
                    anyhow::bail!("unexpected return for close syscall");
                },
            },
        };

        match self.engine.tcp_async_close(qd) {
            Ok(close_qt) => {
                self.inflight.push_back(close_qt);
                Ok(())
            },
            Err(err) if ret == err.errno => Ok(()),
            _ => {
                error!("run_close_syscall(): ret={:?}", ret);
                anyhow::bail!("unexpected return for close syscall");
            },
        }
    }

    fn build_tcp_options(&self, options: &Vec<TcpOption>) -> ([TcpOptions2; MAX_TCP_OPTIONS], usize) {
        let mut new_options = Vec::new();

        for o in options {
            match o {
                TcpOption::Noop => new_options.push(TcpOptions2::NoOperation),
                TcpOption::Mss(mss) => new_options.push(TcpOptions2::MaximumSegmentSize(*mss)),
                TcpOption::WindowScale(wscale) => new_options.push(TcpOptions2::WindowScale(*wscale)),
                TcpOption::SackOk => new_options.push(TcpOptions2::SelectiveAcknowlegementPermitted),
                TcpOption::Timestamp(sender, echo) => new_options.push(TcpOptions2::Timestamp {
                    sender_timestamp: *sender,
                    echo_timestamp: *echo,
                }),
                TcpOption::EndOfOptions => new_options.push(TcpOptions2::EndOfOptionsList),
            }
        }

        let num_options = new_options.len();

        // Pad options list.
        while new_options.len() < MAX_TCP_OPTIONS {
            new_options.push(TcpOptions2::NoOperation);
        }

        (new_options.try_into().unwrap(), num_options)
    }

    fn build_ethernet2_header(&self) -> Ethernet2Header {
        let (src_addr, dst_addr) = { (self.remote_mac, self.local_mac) };
        Ethernet2Header::new(dst_addr, src_addr, EtherType2::Ipv4)
    }

    fn build_ipv4_header(&self, protocol: IpProtocol) -> Ipv4Header {
        let (src_addr, dst_addr) = {
            (
                self.remote_sockaddr.ip().to_owned(),
                self.local_sockaddr.ip().to_owned(),
            )
        };

        Ipv4Header::new(src_addr, dst_addr, protocol)
    }

    fn build_tcp_header(&self, packet: &TcpPacket) -> TcpHeader {
        let (tcp_options, num_options) = self.build_tcp_options(&packet.options);
        let (src_port, dst_port) = { (self.remote_port, self.local_sockaddr.port()) };
        let ack_num = packet.ack.unwrap_or(0);

        TcpHeader {
            src_port,
            dst_port,
            seq_num: packet.seqnum.seq.into(),
            ack_num: ack_num.into(),
            ns: false,
            cwr: packet.flags.cwr,
            ece: packet.flags.ece,
            urg: packet.flags.urg,
            ack: packet.flags.ack,
            psh: packet.flags.psh,
            rst: packet.flags.rst,
            syn: packet.flags.syn,
            fin: packet.flags.fin,
            window_size: packet.win.unwrap() as u16,
            urgent_pointer: 0,
            num_options,
            option_list: tcp_options,
        }
    }

    fn build_udp_header(&self, _udp_packet: &UdpPacket) -> UdpHeader {
        let (src_port, dest_port) = { (self.remote_port, self.local_sockaddr.port()) };
        UdpHeader::new(src_port, dest_port)
    }

    fn build_tcp_segment(&self, tcp_packet: &TcpPacket) -> DemiBuffer {
        let header = self.build_tcp_header(tcp_packet);
        let mut buffer = if tcp_packet.seqnum.win > 0 {
            Self::prepare_dummy_buffer(tcp_packet.seqnum.win as usize, None)
        } else {
            DemiBuffer::new_with_headroom(0, MAX_HEADER_SIZE as u16)
        };

        header.serialize_and_attach(&mut buffer, self.remote_sockaddr.ip(), self.local_sockaddr.ip(), false);
        self.prepend_ipv4_header(IpProtocol::TCP, &mut buffer);
        self.prepend_ethernet_header(&mut buffer);
        buffer
    }

    fn build_udp_datagram(&self, udp_packet: &UdpPacket) -> DemiBuffer {
        let header = self.build_udp_header(udp_packet);
        let mut buffer = Self::prepare_dummy_buffer(udp_packet.len as usize, None);

        // This is an incoming packet, so the source is the remote address and the destination is the local address.
        header.serialize_and_attach(&mut buffer, self.remote_sockaddr.ip(), self.local_sockaddr.ip(), false);
        self.prepend_ipv4_header(IpProtocol::UDP, &mut buffer);
        self.prepend_ethernet_header(&mut buffer);
        buffer
    }

    fn prepend_ethernet_header(&self, buffer: &mut DemiBuffer) {
        let header = self.build_ethernet2_header();
        header.serialize_and_attach(buffer);
    }

    fn prepend_ipv4_header(&self, ip_protocol: IpProtocol, pkt: &mut DemiBuffer) {
        let header = self.build_ipv4_header(ip_protocol);
        header.serialize_and_attach(pkt, true);
    }

    fn run_incoming_packet(&mut self, tcp_packet: &TcpPacket) -> Result<()> {
        let buffer = self.build_tcp_segment(tcp_packet);
        self.engine.push_frame(buffer);
        Ok(())
    }

    fn run_incoming_udp_packet(&mut self, udp_packet: &UdpPacket) -> Result<()> {
        let buffer = self.build_udp_datagram(udp_packet);
        self.engine.push_frame(buffer);
        Ok(())
    }

    fn check_ethernet2_header(&self, header: &Ethernet2Header) -> Result<()> {
        ensure_eq!(header.src_addr(), self.local_mac);
        ensure_eq!(header.dst_addr(), self.remote_mac);
        ensure_eq!(header.ether_type(), EtherType2::Ipv4);
        Ok(())
    }

    fn check_ipv4_header(&self, header: &Ipv4Header, protocol: IpProtocol) -> Result<()> {
        ensure_eq!(header.src_addr(), self.local_sockaddr.ip().to_owned());
        ensure_eq!(header.dst_addr(), self.remote_sockaddr.ip().to_owned());
        ensure_eq!(header.protocol(), protocol);
        Ok(())
    }

    fn check_tcp_header(&self, tcp_header: &TcpHeader, tcp_packet: &TcpPacket) -> Result<()> {
        ensure_eq!(tcp_header.src_port, self.local_sockaddr.port());
        ensure_eq!(tcp_header.dst_port, self.remote_port);
        ensure_eq!(tcp_header.seq_num, tcp_packet.seqnum.seq.into());

        if let Some(ack_num) = tcp_packet.ack {
            ensure_eq!(tcp_header.ack, true);
            ensure_eq!(tcp_header.ack_num, ack_num.into());
        }

        if let Some(winsize) = tcp_packet.win {
            ensure_eq!(tcp_header.window_size, winsize as u16);
        }

        ensure_eq!(tcp_header.cwr, tcp_packet.flags.cwr);
        ensure_eq!(tcp_header.ece, tcp_packet.flags.ece);
        ensure_eq!(tcp_header.urg, tcp_packet.flags.urg);
        ensure_eq!(tcp_header.ack, tcp_packet.flags.ack);
        ensure_eq!(tcp_header.psh, tcp_packet.flags.psh);
        ensure_eq!(tcp_header.rst, tcp_packet.flags.rst);
        ensure_eq!(tcp_header.syn, tcp_packet.flags.syn);
        ensure_eq!(tcp_header.fin, tcp_packet.flags.fin);
        ensure_eq!(tcp_header.urgent_pointer, 0);

        // Check if options match what we expect.
        for i in 0..tcp_packet.options.len() {
            match tcp_packet.options[i] {
                TcpOption::Noop => {
                    ensure_eq!(tcp_header.option_list[i], TcpOptions2::NoOperation);
                },
                TcpOption::Mss(mss) => {
                    ensure_eq!(tcp_header.option_list[i], TcpOptions2::MaximumSegmentSize(mss));
                },
                TcpOption::WindowScale(wscale) => {
                    ensure_eq!(tcp_header.option_list[i], TcpOptions2::WindowScale(wscale));
                },
                TcpOption::SackOk => {
                    ensure_eq!(tcp_header.option_list[i], TcpOptions2::SelectiveAcknowlegementPermitted);
                },
                TcpOption::Timestamp(sender, echo) => {
                    ensure_eq!(
                        tcp_header.option_list[i],
                        TcpOptions2::Timestamp {
                            sender_timestamp: sender,
                            echo_timestamp: echo,
                        }
                    );
                },
                TcpOption::EndOfOptions => {
                    ensure_eq!(tcp_header.option_list[i], TcpOptions2::EndOfOptionsList);
                },
            }
        }

        Ok(())
    }

    fn check_udp_header(&self, header: &UdpHeader, _packet: &UdpPacket) -> Result<()> {
        ensure_eq!(header.src_port(), self.local_sockaddr.port());
        ensure_eq!(header.dest_port(), self.remote_port);
        Ok(())
    }

    fn has_operation_completed(&mut self) -> Result<(QDesc, OperationResult)> {
        match self.inflight.pop_front() {
            Some(qt) => Ok(self.engine.wait(qt)?),
            None => anyhow::bail!("should have an inflight queue token"),
        }
    }

    fn run_outgoing_packet(&mut self, tcp_packet: &TcpPacket) -> Result<()> {
        let mut frames = self.engine.pop_expected_frames(1);
        ensure_eq!(frames.len(), 1);

        let buffer = &mut frames[0];

        let header = Ethernet2Header::parse_and_strip(buffer)?;
        self.check_ethernet2_header(&header)?;

        let header = Ipv4Header::parse_and_strip(buffer)?;
        self.check_ipv4_header(&header, IpProtocol::TCP)?;

        let header = TcpHeader::parse_and_strip(&header.src_addr(), &header.dst_addr(), buffer, true)?;
        ensure_eq!(tcp_packet.seqnum.win as usize, buffer.len());
        self.check_tcp_header(&header, tcp_packet)?;

        Ok(())
    }

    fn run_outgoing_udp_packet(&mut self, packet: &UdpPacket) -> Result<()> {
        let mut frames = self.engine.pop_expected_frames(1);

        // FIXME: We currently do not support multi-frame segments.
        ensure_eq!(frames.len(), 1);

        let buffer = &mut frames[0];
        let header = Ethernet2Header::parse_and_strip(buffer)?;
        self.check_ethernet2_header(&header)?;

        let header = Ipv4Header::parse_and_strip(buffer)?;
        self.check_ipv4_header(&header, IpProtocol::UDP)?;

        let udp_header = UdpHeader::parse_and_strip(self.local_sockaddr.ip(), self.remote_sockaddr.ip(), buffer, true)?;
        ensure_eq!(packet.len as usize, buffer.len());
        self.check_udp_header(&udp_header, packet)?;

        Ok(())
    }

    fn prepare_dummy_buffer(size: usize, stamp: Option<u8>) -> DemiBuffer {
        assert!(size < u16::MAX as usize);
        let mut buffer = DemiBuffer::new_with_headroom(size as u16, MAX_HEADER_SIZE as u16);

        for i in 0..size {
            buffer[i] = stamp.unwrap_or(i as u8);
        }

        buffer
    }
}
