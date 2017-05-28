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
    all(target_arch = "x86"),
    all(target_arch = "x86_64"),
 )))]
use architecture_not_supported_sorry;


extern crate rlibc;
extern crate bitflags;

pub use seL4_Error::*;
pub use seL4_LookupFailureType::*;
pub use seL4_ObjectType::*;
pub use seL4_BreakpointType::*;
pub use seL4_BreakpointAccess::*;

use core::mem::size_of;
use core::mem::transmute;

// XXX: These can't be repr(C), but it needs to "match an int" according to the comments on
// SEL4_FORCE_LONG_ENUM. There's no single type that matches in Rust, so it needs to be
// per-architecture. We use a macro to define them all in one whack, with the invoker providing
// only what the size of the enums ought to be. Each arch then invokes it.
macro_rules! error_types {
    ($int_width:ident) => {
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
        pub enum seL4_LookupFailureType {
            seL4_NoFailure = 0,
            seL4_InvalidRoot,
            seL4_MissingCapability,
            seL4_DepthMismatch,
            seL4_GuardMismatch,
            // XXX: Code depends on this being the last variant
        }

        #[repr($int_width)]
        #[derive(Debug, Copy, Clone, PartialEq, Eq)]
        pub enum seL4_BreakpointType {
            seL4_DataBreakpoint = 0,
            seL4_InstructionBreakpoint,
            seL4_SingleStep,
            seL4_SoftwareBreakRequest,
        }
        
        #[repr($int_width)]
        #[derive(Debug, Copy, Clone, PartialEq, Eq)]
        pub enum seL4_BreakpointAccess {
            seL4_BreakOnRead = 0,
            seL4_BreakOnWrite,
            seL4_BreakOnReadWrite,
        }
    }
}


pub type seL4_Word = usize;
pub type seL4_CPtr = usize;

#[cfg(target_arch = "x86")]
include!("arch/x86.rs");

#[cfg(target_arch = "x86_64")]
include!("arch/x86_64.rs");

#[cfg(all(target_arch = "arm", target_pointer_width = "32"))]
include!("arch/arm.rs");

#[cfg(all(target_arch = "x86"))]
include!(concat!(env!("OUT_DIR"), "/ia32_invocation.rs"));

#[cfg(all(target_arch = "x86_64"))]
include!(concat!(env!("OUT_DIR"), "/x86_64_invocation.rs"));

#[cfg(all(target_arch = "arm", target_pointer_width = "32"))]
include!(concat!(env!("OUT_DIR"), "/aarch32_invocation.rs"));

#[cfg(all(target_arch = "x86"))]
include!(concat!(env!("OUT_DIR"), "/ia32_syscall_stub.rs"));

#[cfg(all(target_arch = "x86_64"))]
include!(concat!(env!("OUT_DIR"), "/x86_64_syscall_stub.rs"));

#[cfg(all(target_arch = "arm", target_pointer_width = "32"))]
include!(concat!(env!("OUT_DIR"), "/aarch32_syscall_stub.rs"));

#[cfg(target_pointer_width = "32")]
include!(concat!(env!("OUT_DIR"), "/types32.rs"));

#[cfg(target_pointer_width = "64")]
include!(concat!(env!("OUT_DIR"), "/types64.rs"));

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

pub const SEL4_BOOTINFO_HEADER_PADDING:  seL4_Word = 0;
pub const SEL4_BOOTINFO_HEADER_X86_VBE:  seL4_Word = 1;

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
    pub receiveDepth: seL4_Word,
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

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// A half-open [start..end) range of slots
pub struct seL4_SlotRegion {
    /// First CNode slot position of the region
    pub start: seL4_Word, 
    /// First CNode slot position after the region
    pub end: seL4_Word,   /* first CNode slot position AFTER region */
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct seL4_UntypedDesc {
    /// Physical address corresponding of the untyped object's backing memory
    pub paddr: seL4_Word,
    pub padding1: u8,
    pub padding2: u8,
    /// log2 size of the region of memory backing the untyped object
    pub sizeBits: u8,
    /// Whether the backing memory corresponds to some device memory
    pub isDevice: u8,
}

// explicitly *not* Copy. the array at the end is tricky to handle.

#[repr(C, packed)]
#[derive(Debug, PartialEq, Eq)]
pub struct seL4_BootInfo {           
    /// Length of any additional bootinfo information
    pub extraLen: seL4_Word,
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
    /// IOSpace caps for ARM SMMU
    pub ioSpaceCaps: seL4_SlotRegion,
    /// Caps fr anypages used to back the additional bootinfo information
    pub extraBIPages: seL4_SlotRegion,
    /// log2 size of root task's CNode
    pub initThreadCNodeSizeBits: u8,
    /// Root task's domain ID
    pub initThreadDomain: seL4_Word,
    /// TSC frequency on x86, unused on ARM.
    pub archInfo: seL4_Word,
    /// Untyped object caps
    pub untyped: seL4_SlotRegion,
    /// Information about each untyped cap
    /// 
    /// *Note*! This is actually an array! The actual length depends on kernel configuration which
    /// we have no way of knowing at this point. Use the `untyped_descs` method.
    pub untypedList: seL4_UntypedDesc,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct seL4_BootInfoHeader {
    /// Identifier of the following chunk
    pub id: seL4_Word,
    /// Length of the chunk
    pub len: seL4_Word,
}

impl seL4_BootInfo {
    /// This is safe if you don't mutate the `untyped` field and corrupt its length.
    pub unsafe fn untyped_descs(&self) -> &[seL4_UntypedDesc] {
        let len = self.untyped.end - self.untyped.start;
        // sanity check that the number of untypeds doesn't extend past the end of the page
        debug_assert!(len <= (4096 - size_of::<seL4_BootInfo>() + size_of::<seL4_UntypedDesc>()) /  size_of::<seL4_UntypedDesc>()) ;
        core::slice::from_raw_parts(&self.untypedList, len)
    }

    /// This is safe if you don't unmap the extraBIPages
    pub unsafe fn extras(&self) -> BootInfoExtraIter {
        BootInfoExtraIter { first_ptr: (self as *const _ as usize + 4096) as *mut seL4_BootInfoHeader, num_bytes: self.extraLen }
    }
}

#[repr(C, packed)]
pub struct seL4_VBEInfoBlock {
    pub signature: [u8; 4],
    pub version: u16,
    pub oemStringPtr: u32,
    pub capabilities: u32,
    pub modeListPtr: u32,
    pub totalMemory: u16,
    pub oemSoftwareRev: u16,
    pub oemVendorNamePtr: u32,
    pub oemProductNamePtr: u32,
    pub reserved: [u8; 222],
    pub oemData: [u8; 256],
}

#[repr(C, packed)]
pub struct seL4_VBEModeInfoBlock {
    // all revisions
    pub modeAttr: u16,
    pub winAAttr: u8,
    pub winBAttr: u8,
    pub winGranularity: u16,
    pub winSize: u16,
    pub winASeg: u16,
    pub winBSeg: u16,
    pub winFuncPtr: u32,
    pub bytesPerScanLine: u16,

    // 1.2+
    pub xRes: u16,
    pub yRes: u16,
    pub xCharSize: u8,
    pub yCharSize: u8,
    pub planes: u8,
    pub bitsPerPixel: u8,
    pub banks: u8,
    pub memoryMmodel: u8,
    pub bankSize: u8,
    pub imagePages: u8,
    pub reserved1: u8,

    pub redLen: u8,
    pub redOff: u8,
    pub greenLen: u8,
    pub greenOff: u8,
    pub blueLen: u8,
    pub blueOff: u8,
    pub rsvdLen: u8,
    pub rsvdOff: u8,
    pub directColorInfo: u8,

    // 2.0+
    pub physBasePtr: u32,
    pub reserved2: [u8; 6],

    // 3.0+
    pub linBytesPerScanLine: u16,
    pub bnkImagePages: u8,
    pub linImagePages: u8,
    pub linRedLen: u8,
    pub linRedOff: u8,
    pub linGreenLen: u8,
    pub linGreenOff: u8,
    pub linBlueLen: u8,
    pub linBlueOff: u8,
    pub linRsvdLen: u8,
    pub linRsvdOff: u8,
    pub maxPixelClock: u32,
    pub modeId: u16,
    pub depth: u8,

    pub reserved3: [u8; 187],
}

#[repr(C, packed)]
pub struct seL4_X86_BootInfo_VBE {
    pub header: seL4_BootInfoHeader,
    pub vbeInfoBlock: seL4_VBEInfoBlock,
    pub vbeModeInfoBlock: seL4_VBEModeInfoBlock,
    pub vbeMode: u32,
    pub vbeInterfaceSeg: u32,
    pub vbeInterfaceOff: u32,
    pub vbeInterfaceLen: u32,
}

/// Extra blocks of information passed from the kernel
pub enum BootInfoExtra {
    X86_VBE(&'static seL4_X86_BootInfo_VBE)
}

/// Iterator over extra bootinfo blocks
pub struct BootInfoExtraIter {
    first_ptr: *mut seL4_BootInfoHeader,
    num_bytes: seL4_Word,
}

impl core::iter::Iterator for BootInfoExtraIter {
    type Item = BootInfoExtra;

    fn next(&mut self) -> Option<BootInfoExtra> {
        while self.num_bytes > 0 {
            let (id, len) = unsafe {
                ((*self.first_ptr).id, (*self.first_ptr).len)
            };
            self.num_bytes -= len;
            let ptr = self.first_ptr;
            self.first_ptr = ((self.first_ptr as usize) + len) as *mut seL4_BootInfoHeader;
            match id {
                0 => { },
                SEL4_BOOTINFO_HEADER_X86_VBE => return Some(BootInfoExtra::X86_VBE(unsafe { transmute(ptr) })),
                _ => { debug_assert!(false, "unknown bootinfo header!") },
            }
        }
        None
    }
}

