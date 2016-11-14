/* Copyright (c) 2015 The Robigalia Project Developers
 * Licensed under the Apache License, Version 2.0
 * <LICENSE-APACHE or
 * http://www.apache.org/licenses/LICENSE-2.0> or the MIT
 * license <LICENSE-MIT or http://opensource.org/licenses/MIT>,
 * at your option. All files in the project carrying such
 * notice may not be copied, modified, or distributed except
 * according to those terms.
 */
#![no_std]
#![feature(asm)]

#![allow(bad_style, unused_parens, unused_assignments)]
#![doc(html_root_url = "https://doc.robigalia.org/")]

#[cfg(not(any(
    all(target_arch = "arm", target_pointer_width = "32"),
    all(target_arch = "x86", target_pointer_width = "32")
 )))]
use architecture_not_supported_sorry;


extern crate rlibc;
#[macro_use] extern crate bitflags;

pub use seL4_Error::*;
pub use seL4_FaultType::*;
pub use seL4_LookupFailureType::*;
pub use seL4_ObjectType::*;

// XXX: These can't be repr(C), but it needs to "match an int" according to the comments on
// SEL4_FORCE_LONG_ENUM. There's no single type that matches in Rust, so it needs to be
// per-architecture. We use a macro to define them all in one whack, with the invoker providing
// only what the size of the enums ought to be. Each arch then invokes it.
macro_rules! error_types {
    ($int_width:ident) => {
        bitflags! {
            pub flags seL4_CapRights: $int_width {
                const seL4_CanWrite = 0x1,
                const seL4_CanRead = 0x2,
                const seL4_CanGrant = 0x4
            }
        }

        #[repr($int_width)]
        #[derive(Debug, Copy, Clone, PartialEq, Eq)]
        pub enum seL4_Error {
            seL4_NoError = 0,
            seL4_InvalidArgument,
            seL4_InvalidCapability,
            seL4_IllegalOperation,
            seL4_RangeError,
            seL4_AlignmentError,
            seL4_FailedLookup,
            seL4_TruncatedMessage,
            seL4_DeleteFirst,
            seL4_RevokeFirst,
            seL4_NotEnoughMemory,
            // XXX: Code depends on this being the last variant
        }

        #[repr($int_width)]
        #[derive(Debug, Copy, Clone, PartialEq, Eq)]
        pub enum seL4_FaultType {
            seL4_NoFault = 0,
            seL4_CapFault,
            seL4_VMFault,
            seL4_UnknownSyscall,
            seL4_UserException,
        }

        #[repr($int_width)]
        #[derive(Debug, Copy, Clone, PartialEq, Eq)]
        pub enum seL4_LookupFailureType {
            seL4_NoFailure = 0,
            seL4_InvalidRoot,
            seL4_MissingCapability,
            seL4_DepthMismatch,
            seL4_GuardMismatch,
            // XXX: Code depends on this being the last variant
        }
    }
}


#[cfg(all(target_arch = "x86", target_pointer_width = "32"))]
include!("arch/x86.rs");

#[cfg(all(target_arch = "arm", target_pointer_width = "32"))]
include!("arch/arm.rs");

#[cfg(all(target_arch = "x86", target_pointer_width = "32"))]
include!(concat!(env!("OUT_DIR"), "/ia32_invocation.rs"));

#[cfg(all(target_arch = "arm", target_pointer_width = "32"))]
include!(concat!(env!("OUT_DIR"), "/aarch32_invocation.rs"));

#[cfg(all(target_arch = "x86", target_pointer_width = "32"))]
include!(concat!(env!("OUT_DIR"), "/ia32_syscall_stub.rs"));

#[cfg(all(target_arch = "arm", target_pointer_width = "32"))]
include!(concat!(env!("OUT_DIR"), "/aarch32_syscall_stub.rs"));

include!(concat!(env!("OUT_DIR"), "/types.rs"));
include!(concat!(env!("OUT_DIR"), "/syscalls.rs"));

pub type seL4_CNode = seL4_CPtr;
pub type seL4_IRQHandler = seL4_CPtr;
pub type seL4_IRQControl = seL4_CPtr;
pub type seL4_TCB = seL4_CPtr;
pub type seL4_Untyped = seL4_CPtr;
pub type seL4_DomainSet = seL4_CPtr;

pub const seL4_MsgLengthBits: usize = 7;
pub const seL4_MsgMaxLength: usize = 120;
pub const seL4_MsgExtraCapBits: usize = 2;
pub const seL4_MsgMaxExtraCaps: usize = (1usize << seL4_MsgExtraCapBits) - 1;

#[repr(C)]
#[derive(Copy)]
/// Buffer used to store received IPC messages
pub struct seL4_IPCBuffer {
    /// Message tag
    ///
    /// The kernel does not initialize this.
    pub tag: seL4_MessageInfo,
    /// Message contents
    ///
    /// The kernel only initializes the bytes which were not able to fit into physical registers.
    pub msg: [seL4_Word; seL4_MsgMaxLength],
    /// Arbitrary user data.
    ///
    /// The seL4 C libraries expect this to be a pointer to the IPC buffer in the thread's VSpace.,
    /// but this doesn't really matter.
    pub userData: seL4_Word,
    /// Capabilities to transfer (if sending) or unwrapped badges
    pub caps_or_badges: [seL4_Word; seL4_MsgMaxExtraCaps],
    /// CPtr to a CNode in the thread's CSpace from which to find the receive slot
    pub receiveCNode: seL4_CPtr,
    /// CPtr to the receive slot, relative to receiveCNode
    pub receiveIndex: seL4_CPtr,
    /// Number of bits of receiveIndex to use
    pub receiveDepth: seL4_CPtr,
}

impl ::core::clone::Clone for seL4_IPCBuffer {
    fn clone(&self) -> Self {
        *self
    }
}

/* bootinfo */

pub static seL4_CapNull: seL4_Word          = 0; /* null cap */
pub static seL4_CapInitThreadTCB: seL4_Word = 1; /* initial thread's TCB cap */
pub static seL4_CapInitThreadCNode: seL4_Word     = 2; /* initial thread's root CNode cap */
pub static seL4_CapInitThreadVSpace: seL4_Word    = 3; /* initial thread's VSpace cap */
pub static seL4_CapIRQControl: seL4_Word    = 4; /* global IRQ controller cap */
pub static seL4_CapASIDControl: seL4_Word   = 5; /* global ASID controller cap */
pub static seL4_CapInitThreadASIDPool: seL4_Word  = 6; /* initial thread's ASID pool cap */
pub static seL4_CapIOPort: seL4_Word        = 7; /* global IO port cap (null cap if not supported) */
pub static seL4_CapIOSpace: seL4_Word       = 8; /* global IO space cap (null cap if no IOMMU support) */
pub static seL4_CapBootInfoFrame: seL4_Word = 9; /* bootinfo frame cap */
pub static seL4_CapInitThreadIPCBuffer: seL4_Word = 10; /* initial thread's IPC buffer frame cap */
pub static seL4_CapDomain: seL4_Word        = 11;  /* global domain controller cap */

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// A half-open [start..end) range of slots
pub struct seL4_SlotRegion {
    /// First CNode slot position of the region
    pub start: seL4_Word, 
    /// First CNode slot position after the region
    pub end: seL4_Word,   /* first CNode slot position AFTER region */
}

// next release
//
//#[repr(C)]
//#[derive(Debug, Clone, Copy, PartialEq, Eq)]
//pub struct seL4_UntypedDesc {
//    /// Physical address corresponding of the untyped object's backing memory
//    pub paddr: seL4_Word,
//    pub padding1: u8,
//    pub padding2: u8,
//    /// log2 size of the region of memory backing the untyped object
//    pub size_bits: u8,
//    /// Whether the backing memory corresponds to some device memory
//    pub is_device: u8,
//}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Region of device memory
pub struct seL4_DeviceRegion {
    /// Base physical address of the device region
    pub basePaddr: seL4_Word,     /* base physical address of device region */
    /// log2 size of a device region frame
    pub frameSizeBits: seL4_Word,
    /// Frame caps for the pages in the device region
    pub frames: seL4_SlotRegion,
}

/* XXX: These MUST match the kernel config at build-time. */
pub const CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS: usize = 166;
pub const CONFIG_MAX_NUM_BOOTINFO_DEVICE_REGIONS: usize = 199;

#[repr(C)]
#[derive(Copy)]
pub struct seL4_BootInfo {           
    /// ID [0..numNodes-1] of the current node (0 if uniprocessor)
    pub nodeID: seL4_Word,          
    /// Number of seL4 nodes (1 if uniprocessor)
    pub numNodes: seL4_Word,
    /// Number of IOMMU PT levels (0 if no IOMMU support)
    pub numIOPTLevels: seL4_Word,   
    /// pointer to root task's IPC buffer */
    pub ipcBuffer: *mut seL4_IPCBuffer,      
    /// Empty slots (null caps)
    pub empty: seL4_SlotRegion,
    /// Frames shared between nodes
    pub sharedFrames: seL4_SlotRegion,
    /// Frame caps used for the loaded ELF image of the root task
    pub userImageFrames: seL4_SlotRegion,
    /// PD caps used for the loaded ELF image of the root task
    pub userImagePaging: seL4_SlotRegion,
    /// Untyped object caps
    pub untyped: seL4_SlotRegion,
    /// IOSpace caps for ARM SMMU
    pub ioSpaceCaps: seL4_SlotRegion,
    /// Physical addresses of caps in untyped
    pub untypedPaddrList:   [seL4_Word; CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS],
    /// log2 size of caps in untyped
    pub untypedSizeBitsList: [u8; CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS],
    /// log2 size of root task's CNode
    pub initThreadCNodeSizeBits: u8,
    /// Number of populated device regions
    pub numDeviceRegions: seL4_Word,
    /// Untyped caps corresponding to devices the kernel found
    pub deviceRegions: [seL4_DeviceRegion; CONFIG_MAX_NUM_BOOTINFO_DEVICE_REGIONS],
    /// Root task's domain ID
    pub initThreadDomain: u32,
}

impl ::core::clone::Clone for seL4_BootInfo {
    fn clone(&self) -> Self {
        // yay [T; n]
        *self
    }
}
