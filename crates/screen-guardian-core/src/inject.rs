use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;

use anyhow::{bail, Context};
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::{
        Diagnostics::{
            Debug::{ReadProcessMemory, WriteProcessMemory},
            ToolHelp::{
                CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
                TH32CS_SNAPMODULE,
            },
        },
        Memory::{
            VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        },
        Threading::{
            CreateRemoteThread, GetExitCodeThread, OpenProcess, WaitForSingleObject, INFINITE,
            PROCESS_CREATE_THREAD, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_OPERATION,
            PROCESS_VM_READ, PROCESS_VM_WRITE,
        },
    },
};

use crate::windows::{detect_process_architecture, ProcessArchitecture};

struct HandleGuard(HANDLE);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe { let _ = CloseHandle(self.0); }
    }
}

fn log_inject(msg: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("./gui-debug.log") {
        let _ = std::io::Write::write_fmt(&mut f, format_args!("[{}] [inject] {}\n", crate::timefmt::format_now(), msg));
    }
}

/// Read a DWORD from remote process memory
unsafe fn read_remote_dword(process_handle: HANDLE, addr: usize) -> anyhow::Result<u32> {
    let mut buffer = [0u8; 4];
    let mut bytes_read = 0;
    ReadProcessMemory(
        process_handle,
        addr as *const c_void,
        buffer.as_mut_ptr() as *mut c_void,
        4,
        Some(&mut bytes_read),
    ).context("ReadProcessMemory failed")?;
    Ok(u32::from_le_bytes(buffer))
}

/// Read bytes from remote process memory
unsafe fn read_remote_bytes(process_handle: HANDLE, addr: usize, size: usize) -> anyhow::Result<Vec<u8>> {
    let mut buffer = vec![0u8; size];
    let mut bytes_read = 0;
    ReadProcessMemory(
        process_handle,
        addr as *const c_void,
        buffer.as_mut_ptr() as *mut c_void,
        size,
        Some(&mut bytes_read),
    ).context("ReadProcessMemory failed")?;
    Ok(buffer)
}

/// Find the address of a function in a remote module by parsing its PE export table
unsafe fn find_remote_export(
    process_handle: HANDLE,
    module_base: usize,
    fn_name: &str,
) -> anyhow::Result<usize> {
    // Read e_lfanew (offset 0x3C in DOS header)
    let e_lfanew = read_remote_dword(process_handle, module_base + 0x3C)? as usize;
    let nt_headers = module_base + e_lfanew;
    let optional_header = nt_headers + 0x18;

    // Check if PE32 (0x10B) or PE32+ (0x20B)
    let magic = read_remote_dword(process_handle, optional_header)? & 0xFFFF;
    let is_pe32 = magic == 0x10B;

    // Data directory offset: PE32 at 0x60, PE32+ at 0x70
    let data_directory = optional_header + if is_pe32 { 0x60 } else { 0x70 };

    // Export directory RVA is at data_directory[0].VirtualAddress
    let export_rva = read_remote_dword(process_handle, data_directory)? as usize;
    if export_rva == 0 {
        bail!("No export directory in module");
    }
    let export_dir = module_base + export_rva;

    // Read export table fields
    let num_names = read_remote_dword(process_handle, export_dir + 0x18)? as usize;
    let names_rva = read_remote_dword(process_handle, export_dir + 0x20)? as usize;
    let ordinals_rva = read_remote_dword(process_handle, export_dir + 0x24)? as usize;
    let functions_rva = read_remote_dword(process_handle, export_dir + 0x1C)? as usize;

    let names_addr = module_base + names_rva;
    let ordinals_addr = module_base + ordinals_rva;
    let functions_addr = module_base + functions_rva;

    // Iterate over exported names
    for i in 0..num_names {
        let name_offset = read_remote_dword(process_handle, names_addr + i * 4)? as usize;
        let name_bytes = read_remote_bytes(process_handle, module_base + name_offset, 32)?;
        let name = std::ffi::CStr::from_bytes_until_nul(&name_bytes)
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();

        if name == fn_name {
            let ordinal = read_remote_dword(process_handle, ordinals_addr + i * 2)? & 0xFFFF;
            let func_rva = read_remote_dword(process_handle, functions_addr + ordinal as usize * 4)? as usize;
            return Ok(module_base + func_rva);
        }
    }

    bail!("Export '{}' not found in module", fn_name)
}

/// Build shellcode for x64: call SetWindowDisplayAffinity(hwnd, affinity)
/// Windows x64 calling convention: rcx=hwnd, rdx=affinity
fn build_shellcode_x64(hwnd: isize, affinity: u32, func_addr: usize) -> Vec<u8> {
    let mut code = Vec::new();
    // sub rsp, 0x30 (shadow space + alignment)
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x30]);
    // mov rcx, hwnd
    code.extend_from_slice(&[0x48, 0xB9]);
    code.extend_from_slice(&(hwnd as u64).to_le_bytes());
    // mov rdx, affinity
    code.extend_from_slice(&[0x48, 0xBA]);
    code.extend_from_slice(&(affinity as u64).to_le_bytes());
    // mov rax, func_addr
    code.extend_from_slice(&[0x48, 0xB8]);
    code.extend_from_slice(&(func_addr as u64).to_le_bytes());
    // call rax
    code.extend_from_slice(&[0xFF, 0xD0]);
    // add rsp, 0x30
    code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x30]);
    // ret
    code.push(0xC3);
    code
}

/// Build shellcode for x86: call SetWindowDisplayAffinity(hwnd, affinity)
/// x86 calling convention: pushed right-to-left, hwnd is return address placeholder
fn build_shellcode_x86(hwnd: isize, affinity: u32, func_addr: usize) -> Vec<u8> {
    let mut code = Vec::new();
    // push affinity
    code.push(0x68);
    code.extend_from_slice(&(affinity as u32).to_le_bytes());
    // push hwnd
    code.push(0x68);
    code.extend_from_slice(&(hwnd as u32).to_le_bytes());
    // mov eax, func_addr
    code.push(0xB8);
    code.extend_from_slice(&(func_addr as u32).to_le_bytes());
    // call eax
    code.extend_from_slice(&[0xFF, 0xD0]);
    // ret
    code.push(0xC3);
    code
}

/// Inject shellcode into remote process and call SetWindowDisplayAffinity
fn inject_shellcode(
    process_handle: HANDLE,
    target_pid: u32,
    hwnd: isize,
    affinity: u32,
    is_x86: bool,
) -> anyhow::Result<()> {
    unsafe {
        // Find user32.dll base in target process
        let user32_base = find_user32_base(target_pid)?;
        log_inject(&format!("user32.dll base in target: {user32_base:#x}"));

        // Find SetWindowDisplayAffinity export
        let func_addr = find_remote_export(process_handle, user32_base, "SetWindowDisplayAffinity")?;
        log_inject(&format!("SetWindowDisplayAffinity addr: {func_addr:#x}"));

        // Build shellcode
        let shellcode = if is_x86 {
            build_shellcode_x86(hwnd, affinity, func_addr)
        } else {
            build_shellcode_x64(hwnd, affinity, func_addr)
        };
        log_inject(&format!("shellcode size: {} bytes (x86={})", shellcode.len(), is_x86));

        // Allocate executable memory in target process
        let code_ptr = VirtualAllocEx(
            process_handle,
            None,
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if code_ptr.is_null() {
            bail!("VirtualAllocEx failed for shellcode");
        }

        // Write shellcode
        WriteProcessMemory(
            process_handle,
            code_ptr as *const c_void,
            shellcode.as_ptr() as *const c_void,
            shellcode.len(),
            None,
        ).context("WriteProcessMemory failed for shellcode")?;

        // Create remote thread to execute shellcode
        let thread_handle = CreateRemoteThread(
            process_handle,
            None,
            0,
            Some(std::mem::transmute(code_ptr)),
            None,
            0,
            None,
        ).context("CreateRemoteThread failed")?;
        let _tg = HandleGuard(thread_handle);

        let wait = WaitForSingleObject(thread_handle, INFINITE);
        if wait.0 == 0xFFFFFFFF {
            bail!("WaitForSingleObject failed");
        }

        let mut exit_code: u32 = 0;
        GetExitCodeThread(thread_handle, &mut exit_code).context("GetExitCodeThread failed")?;
        log_inject(&format!("remote thread exit code: {exit_code}"));

        // Cleanup
        let _ = VirtualFreeEx(process_handle, code_ptr, 0, MEM_RELEASE);

        Ok(())
    }
}

/// Find the base address of user32.dll in the target process
fn find_user32_base(target_pid: u32) -> anyhow::Result<usize> {
    let wide_dll: Vec<u16> = std::ffi::OsStr::new("user32.dll")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, target_pid)
            .map_err(|e| anyhow::anyhow!("CreateToolhelp32Snapshot failed: {}", e))?;
        let _sg = HandleGuard(snapshot);

        let mut module_entry = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
            ..std::mem::zeroed()
        };

        if Module32FirstW(snapshot, &mut module_entry).is_ok() {
            loop {
                let entry_name = &module_entry.szModule;
                let name_len = entry_name.iter().position(|&c| c == 0).unwrap_or(entry_name.len());
                if &entry_name[..name_len] == &wide_dll[..wide_dll.len()-1] {
                    return Ok(module_entry.modBaseAddr as usize);
                }
                if Module32NextW(snapshot, &mut module_entry).is_err() {
                    break;
                }
            }
        }

        bail!("user32.dll not found in target process modules");
    }
}

/// Inject shellcode to call SetWindowDisplayAffinity in a remote process
pub fn inject_set_affinity(target_pid: u32, hwnd: isize, affinity: u32) -> anyhow::Result<()> {
    let is_x86 = matches!(
        detect_process_architecture(target_pid)?,
        ProcessArchitecture::X86
    );

    let process_handle = unsafe {
        OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            target_pid,
        ).with_context(|| format!("OpenProcess failed for PID {target_pid}"))?
    };
    let _pg = HandleGuard(process_handle);

    inject_shellcode(process_handle, target_pid, hwnd, affinity, is_x86)
}
