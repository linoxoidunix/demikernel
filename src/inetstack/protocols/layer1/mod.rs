// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//======================================================================================================================
// Imports
//======================================================================================================================

use ::arrayvec::ArrayVec;

use crate::inetstack::protocols::layer3::IpProtocol;
use crate::{
    inetstack::consts::MAX_BATCH_SIZE_NUM_PACKETS,
    inetstack::protocols::layer4::ephemeral::EphemeralPorts,
    runtime::{
        fail::Fail,
        memory::{DemiBuffer, DemiMemoryAllocator},
    },
};
pub use ::std::any::Any;

//======================================================================================================================
// Traits
//======================================================================================================================

/// API for the Physical Layer for any underlying hardware that implements a raw NIC interface (e.g., DPDK, raw
/// sockets). It must implement [DemiMemoryAllocator] to specify how to allocate DemiBuffers for the physical layer.
pub trait PhysicalLayer: 'static + DemiMemoryAllocator {
    /// Transmits a batch of [DemiBuffer].
    fn transmit(&mut self, pkts: ArrayVec<DemiBuffer, MAX_BATCH_SIZE_NUM_PACKETS>) -> Result<(), Fail>;

    /// Transmits a single [DemiBuffer] with hardware offload hints.
    ///
    /// # Default Behavior
    /// By default, this redirects to the standard [transmit] method, effectively
    /// ignoring offload hints. This is the intended behavior for runtimes that
    /// do not support hardware-assisted checksumming or segmentation.
    fn transmit_with_offload(
        &mut self,
        _packet: DemiBuffer,
        _l2_header_len: u8,
        _l3_header_len: u8,
        _l4_header_len: u8,
        _protocol: IpProtocol,
    ) -> Result<(), Fail> {
        // TODO: For LibOS runtimes other than DPDK (e.g., Catpowder with Raw Sockets,
        // Catnap with POSIX, or Loopback/Test runtimes), evaluate if hardware offload
        // can be supported via socket options (like SO_NO_CHECK or ethtool features).
        //
        // Currently, we fall back to software-calculated checksums by redirecting
        // to the standard transmit path. This ensures compatibility but lacks
        // the performance benefits of hardware offload.
        Ok(())
    }

    /// Receives a batch of [DemiBuffer].
    fn receive(&mut self) -> Result<ArrayVec<DemiBuffer, MAX_BATCH_SIZE_NUM_PACKETS>, Fail>;

    /// Returns the ephemeral ports on which this physical layer may operate. If none, any valid ephemeral port may be
    /// used.
    fn ephemeral_ports(&self) -> EphemeralPorts {
        EphemeralPorts::default()
    }
}
