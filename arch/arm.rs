/*
 * Copyright 2015, Killian Coddington 
 * Copyright 2014, NICTA
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(NICTA_BSD)
 */

pub const seL4_WordBits: usize = 32;
pub const seL4_PageBits: usize = 12;
pub const seL4_SlotBits: usize = 4;
pub const seL4_TCBBits: usize = 9;
pub const seL4_EndpointBits: usize = 4;
pub const seL4_PageTableBits: usize = 10;
pub const seL4_PageDirBits: usize = 14;
pub const seL4_ASIDPoolBits: usize = 12;

pub const seL4_Frame_Args: usize = 4;
pub const seL4_Frame_MRs: usize = 7;
pub const seL4_Frame_HasNPC: usize = 0;
pub const seL4_ASIDPoolBits: usize = 12;
pub const seL4_ASIDPoolBits: usize = 12;
pub const seL4_ASIDPoolBits: usize = 12;

pub type seL4_Word = u32;
pub type seL4_CPtr = seL4_Word;

pub type seL4_ARM_Page = seL4_CPtr;
pub type seL4_ARM_PageTable = seL4_CPtr;
pub type seL4_ARM_PageDirectory = seL4_CPtr;
pub type seL4_ARM_ASIDControl = seL4_CPtr;
pub type seL4_ARM_ASIDPool = seL4_CPtr;

pub struct seL4_UserContext {
    pub pc: seL4_Word,
    pub sp: seL4_Word,
    pub cpsr: seL4_Word,
    pub r0: seL4_Word,
    pub r1: seL4_Word,
    pub r8: seL4_Word,
    pub r9: seL4_Word,
    pub r10: seL4_Word,
    pub r11: seL4_Word,
    pub r12: seL4_Word,
    pub r2: seL4_Word,
    pub r3: seL4_Word,
    pub r4: seL4_Word,
    pub r5: seL4_Word,
    pub r6: seL4_Word,
    pub r7: seL4_Word,
    pub r14: seL4_Word,
}

#[repr(u32)]
pub enum seL4_ARM_VMAttributes {
    PageCacheable = 1,
    ParityEnabled = 2,
    Default_VMAttributes = 3,
    ExecuteNever = 4,
}

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

pub struct seL4_IPCBuffer {
    pub tag: seL4_MessageInfo,
    pub msg: [seL4_Word; seL4_MsgMaxLength],
    pub userData: seL4_Word,
    pub caps_or_badges: [seL4_Word; seL4_MsgMaxExtraCaps],
    pub receiveCNode: seL4_CPtr,
    pub receiveIndex: seL4_CPtr,
    pub receiveDepth: seL4_CPtr,
}

pub enum seL4_CapRights {
    CanWrite = 0x01,
    CanRead = 0x02,
    CanGrant = 0x04,
    AllRights = 0x07,
}

#[inline(always)]
pub unsafe fn seL4_GetIPCBuffer() -> *mut seL4_IPCBuffer {
	*(0xffffc000 as *mut *mut seL4_IPCBuffer)
}

#[inline(always)]
pub unsafe fn seL4_GetTag() -> seL4_MessageInfo {
	(*seL4_GetIPCBuffer()).tag
}

#[inline(always)]
pub unsafe fn seL4_SetTag(tag: seL4_MessageInfo) {
	(*seL4_GetIPCBuffer()).tag = tag;
}

#[inline(always)]
pub unsafe fn seL4_GetMR(regnum: isize) -> seL4_Word {
	(*seL4_GetIPCBuffer()).msg[regnum]	
}

#[inline(always)]
pub unsafe fn seL4_SetMR(regnum: isize, value: seL4_Word) {
	(*seL4_GetIPCBuffer()).msg[regnum] = value;
}

#[inline(always)]
pub unsafe fn seL4_GetUserData() -> seL4_Word {
	(*seL4_GetIPCBuffer()).userData	
}

#[inline(always)]
pub unsafe fn seL4_SetUserData(data: seL4_Word) {
	(*seL4_GetIPCBuffer()).userData = data;	
}

#[inline(always)]
pub unsafe fn seL4_GetBadge(index: isize) -> seL4_CapData {
	(*seL4_GetIPCBuffer()).caps_or_badges[index] as seL4_CapData
}

#[inline(always)]
pub unsafe fn seL4_GetCap(index: isize) -> seL4_CPtr {
	(*seL4_GetIPCBuffer()).caps_or_badges[index] as seL4_CPtr
}

#[inline(always)]
pub unsafe fn seL4_SetCap(index: isize, cptr: seL4_CPtr) {
	(*seL4_GetIPCBuffer()).caps_or_badges[index] = cptr as seL4_Word;
}

#[inline(always)]
pub unsafe fn seL4_GetCapReceivePath(receiveCNode: *mut seL4_CPtr,
                                     receiveIndex: *mut seL4_CPtr,
                                     receiveDepth: *mut seL4_Word) {
    let ipcbuffer = seL4_GetIPCBuffer();
    if !receiveCNode.is_null() {
	*receiveCNode = (*ipcbuffer).receiveCNode;
    }

    if !receiveIndex.is_null() {
	*receiveIndex = (*ipcbuffer).receiveIndex;
    }

    if !receiveDepth.is_null() {
	*receiveDepth = (*ipcbuffer).receiveDepth;
    }
}

#[inline(always)]
pub unsafe fn seL4_SetCapReceivePath(receiveCNode: seL4_CPtr,
                                     receiveIndex: seL4_CPtr,
                                     receiveDepth: seL4_Word) {
	let ipcbuffer = seL4_GetIPCBuffer();
	(*ipcbuffer).receiveCNode = receiveCNode;
	(*ipcbuffer).receiveIndex = receiveIndex;
	(*ipcbuffer).receiveDepth = receiveDepth;
}

macro_rules! swinum {
	($val:expr) => {
		$val as seL4_Word & 0x00ffffff
	}
}

#[inline(always)]
pub unsafe fn seL4_Send(dest: seL4_CPtr, msgInfo: seL4_MessageInfo) {
	let info  = msgInfo.words[0];
	let msg0 = seL4_GetMR(0);
	let msg1 = seL4_GetMR(1);
	let msg2 = seL4_GetMR(2);
	let msg3 = seL4_GetMR(3);
	let scno = SyscallId::Send as seL4_Word;
    asm!("swi $0"
	:
	: "i" (swinum!(SyscallId::Send)),
	  "{r0}" (dest), 
	  "{r1}" (msgInfo.words[0]),
	  "{r2}" (msg0), "{r3}" (msg1),
	  "{r4}" (msg2), "{r5}" (msg3),
	  "{r7}" (scno)
	: "memory", "r0", "r1", "r2", "r3", "r4", "r5", "r7"
        : "volatile");
}

macro_rules! opt_deref {
    ($name:expr) => {
        if !$name.is_null() {
            *$name
        } else {
            0
        }
    }
}

macro_rules! opt_assign {
    ($loc:expr, $val:expr) => {
        if !$loc.is_null() {
            *$loc = $val;
        }
    }
}

#[inline(always)]
pub unsafe fn seL4_SendWithMRs(dest: seL4_CPtr, msgInfo: seL4_MessageInfo,
                               mr0: *mut seL4_Word, mr1: *mut seL4_Word) {
	let info  = msgInfo.words[0];
	let mut msg0 = ::core::mem::uninitialized();
	let mut msg1 = ::core::mem::uninitialized();
	let mut msg2 = ::core::mem::uninitialized();
	let mut msg3 = ::core::mem::uninitialized();

	if !mr.is_null() && seL4_MessageInfo.get_length(msgInfo) > 0 {
		msg0 = *mr0;
	}
	if !mr.is_null() && seL4_MessageInfo.get_length(msgInfo) > 1 {
		msg1 = *mr1;
	}
	if !mr.is_null() && seL4_MessageInfo.get_length(msgInfo) > 2 {
		msg2 = *mr2;
	}
	if !mr.is_null() && seL4_MessageInfo.get_length(msgInfo) > 3 {
		msg3 = *mr3;
	}
	let scno = SyscallId::Send as seL4_Word;
    asm!("swi $0"
	:
	: "i" (swinum!(SyscallId::Send)),
	  "{r0}" (dest), 
	  "{r1}" (msgInfo.words[0]),
	  "{r2}" (msg0), "{r3}" (msg1),
	  "{r4}" (msg2), "{r5}" (msg3),
	  "{r7}" (scno)
	: "memory", "r0", "r1", "r2", "r3", "r4", "r5", "r7"
        : "volatile");
}

#[inline(always)]
pub unsafe fn seL4_NBSend(dest: seL4_CPtr, msgInfo: seL4_MessageInfo) {
	let info  = msgInfo.words[0];
	let msg0 = seL4_GetMR(0);
	let msg1 = seL4_GetMR(1);
	let msg2 = seL4_GetMR(2);
	let msg3 = seL4_GetMR(3);
	let scno = SyscallId::NBSend as seL4_Word;
    asm!("swi $0"
	:
	: "i" (swinum!(SyscallId::NBSend)),
	  "{r0}" (dest), 
	  "{r1}" (msgInfo.words[0]),
	  "{r2}" (msg0), "{r3}" (msg1),
	  "{r4}" (msg2), "{r5}" (msg3),
	  "{r7}" (scno)
	: "memory", "r0", "r1", "r2", "r3", "r4", "r5", "r7"
        : "volatile");
}
#[inline(always)]
pub unsafe fn seL4_NBSendWithMRs(dest: seL4_CPtr, msgInfo: seL4_MessageInfo,
                                 mr0: *mut seL4_Word, mr1: *mut seL4_Word) {
	let info  = msgInfo.words[0];
	let mut msg0 = ::core::mem::uninitialized();
	let mut msg1 = ::core::mem::uninitialized();
	let mut msg2 = ::core::mem::uninitialized();
	let mut msg3 = ::core::mem::uninitialized();

	if !mr.is_null() && seL4_MessageInfo.get_length(msgInfo) > 0 {
		msg0 = *mr0;
	}
	if !mr.is_null() && seL4_MessageInfo.get_length(msgInfo) > 1 {
		msg1 = *mr1;
	}
	if !mr.is_null() && seL4_MessageInfo.get_length(msgInfo) > 2 {
		msg2 = *mr2;
	}
	if !mr.is_null() && seL4_MessageInfo.get_length(msgInfo) > 3 {
		msg3 = *mr3;
	}
	let scno = SyscallId::NBSend as seL4_Word;
    asm!("swi $0"
	:
	: "i" (swinum!(SyscallId::NBSend)),
	  "{r0}" (dest), 
	  "{r1}" (msgInfo.words[0]),
	  "{r2}" (msg0), "{r3}" (msg1),
	  "{r4}" (msg2), "{r5}" (msg3),
	  "{r7}" (scno)
	: "memory", "r0", "r1", "r2", "r3", "r4", "r5", "r7"
        : "volatile");
}

#[inline(always)]
pub unsafe fn seL4_Reply(msgInfo: seL4_MessageInfo) {
	let info  = msgInfo.words[0];
	let msg0 = seL4_GetMR(0);
	let msg1 = seL4_GetMR(1);
	let msg2 = seL4_GetMR(2);
	let msg3 = seL4_GetMR(3);
	let scno = SyscallId::Reply as seL4_Word;
    asm!("swi $0"
	:
	: "i" (swinum!(SyscallId::Reply)),
	  "{r1}" (msgInfo.words[0]),
	  "{r2}" (msg0), "{r3}" (msg1),
	  "{r4}" (msg2), "{r5}" (msg3),
	  "{r7}" (scno)
	: "memory", "r0", "r1", "r2", "r3", "r4", "r5", "r7"
        : "volatile");
}
#[inline(always)]
pub unsafe fn seL4_ReplyWithMRs(msgInfo: seL4_MessageInfo,
                                mr0: *mut seL4_Word, mr1: *mut seL4_Word) {
	let info  = msgInfo.words[0];
	let mut msg0 = ::core::mem::uninitialized();
	let mut msg1 = ::core::mem::uninitialized();
	let mut msg2 = ::core::mem::uninitialized();
	let mut msg3 = ::core::mem::uninitialized();

	if !mr.is_null() && seL4_MessageInfo.get_length(msgInfo) > 0 {
		msg0 = *mr0;
	}
	if !mr.is_null() && seL4_MessageInfo.get_length(msgInfo) > 1 {
		msg1 = *mr1;
	}
	if !mr.is_null() && seL4_MessageInfo.get_length(msgInfo) > 2 {
		msg2 = *mr2;
	}
	if !mr.is_null() && seL4_MessageInfo.get_length(msgInfo) > 3 {
		msg3 = *mr3;
	}
	let scno = SyscallId::Reply as seL4_Word;
    asm!("swi $0"
	:
	: "i" (swinum!(SyscallId::Reply)),
	  "{r1}" (msgInfo.words[0]),
	  "{r2}" (msg0), "{r3}" (msg1),
	  "{r4}" (msg2), "{r5}" (msg3),
	  "{r7}" (scno)
	: "memory", "r0", "r1", "r2", "r3", "r4", "r5", "r7"
        : "volatile");
}


#[inline(always)]
pub unsafe fn seL4_Notify(dest: seL4_CPtr, msg: seL4_Word) {
	let info  = seL4_MessageInfo::new(0, 0, 0, 1).words[0];
	let scno = SyscallId::Send as seL4_Word;
    asm!("swi $0"
	:
	: "i" (swinum!(SyscallId::Send)),
	  "{r0}" (dest),
	  "{r1}" (info),
	  "{r2}" (msg)
	  "{r7}" (scno)
	: "memory", "r0", "r1", "r2", "r3", "r4", "r5", "r7"
        : "volatile");
}

#[inline(always)]
pub unsafe fn seL4_Wait(src: seL4_CPtr, sender: *mut seL4_Word) -> seL4_MessageInfo {
	let info = ::core::mem::uninitialized();
	let msg0 = ::core::mem::uninitialized();
	let msg1 = ::core::mem::uninitialized();
	let msg2 = ::core::mem::uninitialized();
	let msg3 = ::core::mem::uninitialized();
	let scno = SyscallId::Wait as seL4_Word;
    asm!("swi $0"
	: "={r0}" (src), "={r1}" (info),
	  "={r2}" (msg0), "={r3}" (msg1),
	  "={r4}" (msg2), "={r5}" (msg3),
	  "={r1}"
	: "i" (swinum!(SyscallId::Wait)),
	  "{r7}" (scno)
	: "memory", "r0", "r1", "r2", "r3", "r4", "r5", "r7"
        : "volatile");

    seL4_SetMR(0, msg0);
    seL4_SetMR(1, msg1);
    seL4_SetMR(2, msg2);
    seL4_SetMR(3, msg3);

    opt_assign!(sender, src);
    info
}

#[inline(always)]
pub unsafe fn seL4_WaitWithMRs(src: seL4_CPtr, sender: *mut seL4_Word,
                               mr0: *mut seL4_Word, mr1: *mut seL4_Word) -> seL4_MessageInfo {
	let info = ::core::mem::uninitialized();
	let msg0 = ::core::mem::uninitialized();
	let msg1 = ::core::mem::uninitialized();
	let msg2 = ::core::mem::uninitialized();
	let msg3 = ::core::mem::uninitialized();
	let scno = SyscallId::Wait as seL4_Word;
    asm!("swi $0"
	: "={r0}" (src), "={r1}" (info),
	  "={r2}" (msg0), "={r3}" (msg1),
	  "={r4}" (msg2), "={r5}" (msg3),
	  "={r1}"
	: "i" (swinum!(SyscallId::Wait)),
	  "{r7}" (scno)
	: "memory", "r0", "r1", "r2", "r3", "r4", "r5", "r7"
        : "volatile");

    seL4_SetMR(0, msg0);
    seL4_SetMR(1, msg1);
    seL4_SetMR(2, msg2);
    seL4_SetMR(3, msg3);

    opt_assign!(sender, src);
    opt_assign!(mr0, msg0);
    opt_assign!(mr1, msg1);
    opt_assign!(mr2, msg2);
    opt_assign!(mr3, msg3);
    info
}

#[inline(always)]
pub unsafe fn seL4_Call(mut dest: seL4_CPtr, msgInfo: seL4_MessageInfo) -> seL4_MessageInfo {
	let info = ::core::mem::uninitialized();
	let msg0 = ::core::mem::uninitialized();
	let msg1 = ::core::mem::uninitialized();
	let msg2 = ::core::mem::uninitialized();
	let msg3 = ::core::mem::uninitialized();
	let scno = SyscallId::Call as seL4_Word;
    asm!("swi $0"
	: "={r0}" (src), "={r1}" (info),
	  "={r2}" (msg0), "={r3}" (msg1),
	  "={r4}" (msg2), "={r5}" (msg3),
	  "={r1}"
	: "i" (swinum!(SyscallId::Call)),
	  "{r7}" (scno)
	: "memory", "r0", "r1", "r2", "r3", "r4", "r5", "r7"
        : "volatile");

    seL4_SetMR(0, msg0);
    seL4_SetMR(1, msg1);
    seL4_SetMR(2, msg2);
    seL4_SetMR(3, msg3);

    opt_assign!(sender, src);
    info
}

#[inline(always)]
pub unsafe fn seL4_CallWithMRs(mut dest: seL4_CPtr, msgInfo: seL4_MessageInfo,
                               mr0: *mut seL4_Word, mr1: *mut seL4_Word) -> seL4_MessageInfo {
	let info = ::core::mem::uninitialized();
	let msg0 = ::core::mem::uninitialized();
	let msg1 = ::core::mem::uninitialized();
	let msg2 = ::core::mem::uninitialized();
	let msg3 = ::core::mem::uninitialized();
	let scno = SyscallId::Call as seL4_Word;
    asm!("swi $0"
	: "={r0}" (src), "={r1}" (info),
	  "={r2}" (msg0), "={r3}" (msg1),
	  "={r4}" (msg2), "={r5}" (msg3),
	  "={r1}"
	: "i" (swinum!(SyscallId::Call)),
	  "{r7}" (scno)
	: "memory", "r0", "r1", "r2", "r3", "r4", "r5", "r7"
        : "volatile");

    seL4_SetMR(0, msg0);
    seL4_SetMR(1, msg1);
    seL4_SetMR(2, msg2);
    seL4_SetMR(3, msg3);

    opt_assign!(sender, src);
    opt_assign!(mr0, msg0);
    opt_assign!(mr1, msg1);
    opt_assign!(mr2, msg2);
    opt_assign!(mr3, msg3);
    info
}

#[inline(always)]
pub unsafe fn seL4_ReplyWait(dest: seL4_CPtr, msgInfo: seL4_MessageInfo,
                             sender: *mut seL4_Word) -> seL4_MessageInfo {
	let info = ::core::mem::uninitialized();
	let msg0 = seL4_GetMr(0);
	let msg1 = seL4_GetMr(1);
	let msg2 = seL4_GetMr(2);
	let msg3 = seL4_GetMr(3);
	let scno = SyscallId::ReplyWait as seL4_Word;
    asm!("swi $0"
	: "={r0}" (src), "={r1}" (info),
	  "={r2}" (msg0), "={r3}" (msg1),
	  "={r4}" (msg2), "={r5}" (msg3),
	  "={r1}"
	: "i" (swinum!(SyscallId::Call)),
	  "{r7}" (scno)
	: "memory", "r0", "r1", "r2", "r3", "r4", "r5", "r7"
        : "volatile");

    seL4_SetMR(0, msg0);
    seL4_SetMR(1, msg1);
    seL4_SetMR(2, msg2);
    seL4_SetMR(3, msg3);

    opt_assign!(sender, src);
    info
}

#[inline(always)]
pub unsafe fn seL4_ReplayWaitWithMRs(dest: seL4_CPtr, msgInfo: seL4_MessageInfo, sender: *mut seL4_Word,
                                     mr0: *mut seL4_Word, mr1: *mut seL4_Word) -> seL4_MessageInfo {
	let info = ::core::mem::uninitialized();
	let msg0 = ::core::mem::uninitialized();
	let msg1 = ::core::mem::uninitialized();
	let msg2 = ::core::mem::uninitialized();
	let msg3 = ::core::mem::uninitialized();
	if !mr0.is_null() && msgInfo.get_length() > 0 {
		msg0 = *mr0;
	}
	if !mr1.is_null() && msgInfo.get_length() > 1 {
		msg1 = *mr1;
	}
	if !mr2.is_null() && msgInfo.get_length() > 2 {
		msg2 = *mr2;
	}
	if !mr3.is_null() && msgInfo.get_length() > 3 {
		msg3 = *mr3;
	}
	let scno = SyscallId::ReplyWait as seL4_Word;
    asm!("swi $0"
	: "={r0}" (src), "={r1}" (info),
	  "={r2}" (msg0), "={r3}" (msg1),
	  "={r4}" (msg2), "={r5}" (msg3),
	  "={r1}"
	: "i" (swinum!(SyscallId::Call)),
	  "{r7}" (scno)
	: "memory", "r0", "r1", "r2", "r3", "r4", "r5", "r7"
        : "volatile");

    opt_assign!(mr0, msg0);
    opt_assign!(mr1, msg1);
    opt_assign!(mr2, msg2);
    opt_assign!(mr3, msg3);

    opt_assign!(sender, src);
    info
}

#[inline(always)]
pub unsafe fn seL4_Yield() {
    asm!("pushl %ebp
          movl %esp, %ecx
          leal 1f, %edx
          1:
          sysenter
          popl %ebp"
        :
        : "a" (SyscallId::Yield as seL4_Word)
        : "%ebx", "%ecx", "%edx", "%esi", "%edi", "memory"
        : "volatile");
}

#[inline(always)]
#[cfg(feature = "SEL4_DEBUG")]
pub unsafe fn seL4_DebugPutChar(c: u8) {
    asm!("pushl %ebp
          movl %esp, %ecx
          leal 1f, %edx
          1:
          sysenter
          popl %ebp"
        :
        : "a" (SyscallId::DebugPutChar as seL4_Word),
        "b" (c)
        : "%ecx", "%edx", "%esi", "%edi", "memory"
        : "volatile");
}

#[inline(always)]
#[cfg(feature = "SEL4_DEBUG")]
pub unsafe fn seL4_DebugHalt() {
    asm!("pushl %ebp
          movl %esp, %ecx
          leal 1f, %edx
          1:
          sysenter
          popl %ebp"
        :
        : "a" (SyscallId::DebugHalt as seL4_Word)
        : "%ebx", "%ecx", "%edx", "%esi", "%edi", "memory"
        : "volatile");
}

#[inline(always)]
#[cfg(feature = "SEL4_DEBUG")]
pub unsafe fn seL4_DebugSnapshot() {
    asm!("pushl %ebp
          movl %esp, %ecx
          leal 1f, %edx
          1:
          sysenter
          popl %ebp"
        :
        : "a" (SyscallId::DebugSnapshot as seL4_Word)
        : "%ebx", "%ecx", "%edx", "%esi", "%edi", "memory"
        : "volatile");
}

#[inline(always)]
#[cfg(feature = "SEL4_DEBUG")]
pub unsafe fn seL4_DebugCapIdentify(cap: seL4_CPtr) -> u32 {
    let mut _cap = cap;
    asm!("pushl %ebp
          movl %esp, %ecx
          leal 1f, %edx
          1:
          sysenter
          popl %ebp"
        : "=b" (_cap)
        : "a" (SyscallId::DebugCapIdentify as seL4_Word),
          "b" (_cap)
          : "%ecx", "%edx", "%esi", "%edi", "memory"
        : "volatile");
    _cap
}

// Note: name MUST be NUL-terminated.
#[inline(always)]
#[cfg(feature = "SEL4_DEBUG")]
pub unsafe fn seL4_DebugNameThread(tcb: seL4_CPtr, name: &[u8]) {
    core::ptr::copy_nonoverlapping(seL4_GetIPCBuffer() as *mut u8, name.as_ptr(), name.len());
    asm!("pushl %ebp
          movl %esp, %ecx
          leal 1f, %edx
          1:
          sysenter
          popl %ebp"
        :
        : "a" (SyscallId::DebugNameThread as seL4_Word),
        "b" (tcb)
        : "%ecx", "%edx", "%esi", "%edi", "memory"
        : "volatile");
}

#[inline(always)]
#[cfg(feature = "SEL4_DANGEROUS_CODE_INJECTION")]
pub unsafe fn seL4_DebugRun(userfn: extern fn(*mut u8), userarg: *mut u8) {
    let userfnptr = userfn as *mut ();
    asm!("pushl %ebp
          movl %esp, %ecx
          leal 1f, %edx
          1:
          sysenter
          popl %ebp"
        :
        : "a" (SyscallId::DebugRun as seL4_Word),
        "b" (userfnptr),
          "S" (userarg)
          : "%ecx", "%edx", "%edi", "memory"
        : "volatile");
}

#[inline(always)]
#[cfg(feature = "SEL4_CONFIG_BENCHMARK")]
pub unsafe fn seL4_BenchmarkResetLog() {
    asm!("pushl %ebp
          movl %esp, %ecx
          leal 1f, %edx
          1:
          sysenter
          popl %ebp"
        :
        : "a" (SyscallId::BenchmarkResetLog as seL4_Word)
        : "%ecx", "%edx", "%edi", "memory"
        : "volatile");
}

#[inline(always)]
#[cfg(feature = "SEL4_CONFIG_BENCHMARK")]
pub unsafe fn seL4_BenchmarkDumpLog(start: seL4_Word, size: seL4_Word) -> u32 {
    let dump: u32;
    asm!("pushl %ebp
          movl %esp, %ecx
          leal 1f, %edx
          1:
          sysenter
          popl %ebp"
        : "=b" (dump)
        : "a" (SyscallId::BenchmarkDumpLog as seL4_Word),
          "b" (start),
          "S" (size)
        : "%ecx", "%edx", "%edi", "memory"
        : "volatile");
    dump
}

#[inline(always)]
#[cfg(feature = "SEL4_CONFIG_BENCHMARK")]
pub unsafe fn seL4_BenchmarkLogSize() -> u32 {
    let ret: u32;
    asm!("pushl %ebp
          movl %esp, %ecx
          leal 1f, %edx
          1:
          sysenter
          popl %ebp"
        : "=b" (ret)
        : "a" (SyscallId::BenchmarkLogSize as seL4_Word)
        : "%ecx", "%edx", "%edi", "memory"
        : "volatile");
    ret
}
