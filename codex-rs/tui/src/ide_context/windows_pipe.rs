//! Windows named-pipe transport for the IDE context IPC client.

use std::io;
use std::io::Read;
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr;
use std::time::Instant;

use windows_sys::Win32::Foundation::BOOL;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::ERROR_IO_PENDING;
use windows_sys::Win32::Foundation::ERROR_NOT_FOUND;
use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;
use windows_sys::Win32::Foundation::ERROR_SEM_TIMEOUT;
use windows_sys::Win32::Foundation::GENERIC_READ;
use windows_sys::Win32::Foundation::GENERIC_WRITE;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Foundation::WAIT_FAILED;
use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
use windows_sys::Win32::Foundation::WAIT_TIMEOUT;
use windows_sys::Win32::Security::EqualSid;
use windows_sys::Win32::Security::GetTokenInformation;
use windows_sys::Win32::Security::TOKEN_QUERY;
use windows_sys::Win32::Security::TOKEN_USER;
use windows_sys::Win32::Security::TokenUser;
use windows_sys::Win32::Storage::FileSystem::CreateFileW;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;
use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OVERLAPPED;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE;
use windows_sys::Win32::Storage::FileSystem::OPEN_EXISTING;
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::Storage::FileSystem::WriteFile;
use windows_sys::Win32::System::IO::CancelIoEx;
use windows_sys::Win32::System::IO::GetOverlappedResult;
use windows_sys::Win32::System::IO::OVERLAPPED;
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
use windows_sys::Win32::System::Threading::CreateEventW;
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::System::Threading::OpenProcess;
use windows_sys::Win32::System::Threading::OpenProcessToken;
use windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;
use windows_sys::Win32::System::Threading::WaitForSingleObject;

const TRUE: BOOL = 1;
const FALSE: BOOL = 0;
const NULL_HANDLE: HANDLE = 0;

pub(super) struct WindowsPipeStream {
    handle: OwnedHandle,
    deadline: Instant,
}

impl WindowsPipeStream {
    pub(super) fn connect(pipe_path: PathBuf, deadline: Instant) -> io::Result<Self> {
        let wide_path = pipe_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();

        let handle = connect_to_pipe_before_deadline(&wide_path, deadline)?;

        let handle = OwnedHandle(handle);
        validate_pipe_server_owner(handle.raw())?;

        Ok(Self { handle, deadline })
    }

    pub(super) fn set_deadline(&mut self, deadline: Instant) {
        self.deadline = deadline;
    }
}

fn connect_to_pipe_before_deadline(wide_path: &[u16], deadline: Instant) -> io::Result<HANDLE> {
    loop {
        let handle = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                NULL_HANDLE,
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            return Ok(handle);
        }

        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_PIPE_BUSY as i32) {
            return Err(error);
        }

        let timeout_ms = remaining_timeout_ms(deadline);
        if timeout_ms == 0 {
            return Err(timeout_io_error());
        }

        if unsafe { WaitNamedPipeW(wide_path.as_ptr(), timeout_ms) } != 0 {
            continue;
        }

        let wait_error = io::Error::last_os_error();
        if wait_error.raw_os_error() == Some(ERROR_SEM_TIMEOUT as i32) {
            return Err(timeout_io_error());
        }
        return Err(wait_error);
    }
}

impl Read for WindowsPipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let bytes_to_read = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let mut operation = OverlappedOperation::new()?;
        let result = unsafe {
            ReadFile(
                self.handle.raw(),
                buf.as_mut_ptr(),
                bytes_to_read,
                ptr::null_mut(),
                operation.as_mut_ptr(),
            )
        };

        operation.complete(self.handle.raw(), result, self.deadline)
    }
}

impl Write for WindowsPipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let bytes_to_write = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let mut operation = OverlappedOperation::new()?;
        let result = unsafe {
            WriteFile(
                self.handle.raw(),
                buf.as_ptr(),
                bytes_to_write,
                ptr::null_mut(),
                operation.as_mut_ptr(),
            )
        };

        operation.complete(self.handle.raw(), result, self.deadline)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct OverlappedOperation {
    event: OwnedHandle,
    overlapped: OVERLAPPED,
}

impl OverlappedOperation {
    fn new() -> io::Result<Self> {
        let event = unsafe { CreateEventW(ptr::null(), TRUE, FALSE, ptr::null()) };
        if event == 0 {
            return Err(io::Error::last_os_error());
        }

        let mut overlapped = unsafe { std::mem::zeroed::<OVERLAPPED>() };
        overlapped.hEvent = event;
        Ok(Self {
            event: OwnedHandle(event),
            overlapped,
        })
    }

    fn as_mut_ptr(&mut self) -> *mut OVERLAPPED {
        &mut self.overlapped
    }

    fn complete(
        &mut self,
        handle: HANDLE,
        initial_result: BOOL,
        deadline: Instant,
    ) -> io::Result<usize> {
        if initial_result == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                return Err(error);
            }

            // Use a zero wait after the deadline so pending overlapped I/O still flows through
            // cancel_and_timeout instead of returning while the OS operation owns this OVERLAPPED.
            match unsafe { WaitForSingleObject(self.event.raw(), remaining_timeout_ms(deadline)) } {
                WAIT_OBJECT_0 => {}
                WAIT_TIMEOUT => return Err(self.cancel_and_timeout(handle)),
                WAIT_FAILED => return Err(io::Error::last_os_error()),
                other => {
                    return Err(io::Error::other(format!(
                        "unexpected WaitForSingleObject result: {other}"
                    )));
                }
            }
        }

        let mut bytes_transferred = 0;
        let result = unsafe {
            GetOverlappedResult(handle, self.as_mut_ptr(), &mut bytes_transferred, FALSE)
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(bytes_transferred as usize)
    }

    fn cancel_and_timeout(&mut self, handle: HANDLE) -> io::Error {
        let cancel_result = unsafe { CancelIoEx(handle, self.as_mut_ptr()) };
        if cancel_result == 0 {
            let cancel_error = io::Error::last_os_error();
            if cancel_error.raw_os_error() != Some(ERROR_NOT_FOUND as i32) {
                return cancel_error;
            }

            // ERROR_NOT_FOUND means the operation completed before cancellation was issued. Drain
            // it without waiting so the timeout path cannot block past the caller's deadline.
            let mut bytes_transferred = 0;
            unsafe {
                GetOverlappedResult(handle, self.as_mut_ptr(), &mut bytes_transferred, FALSE)
            };
            return timeout_io_error();
        }

        let mut bytes_transferred = 0;
        unsafe {
            GetOverlappedResult(handle, self.as_mut_ptr(), &mut bytes_transferred, TRUE);
        }
        timeout_io_error()
    }
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if self.0 != 0 && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

struct TokenUserBuffer {
    buffer: Vec<u8>,
}

impl TokenUserBuffer {
    fn sid(&self) -> io::Result<windows_sys::Win32::Foundation::PSID> {
        if self.buffer.len() < std::mem::size_of::<TOKEN_USER>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "token user buffer is too small",
            ));
        }

        // GetTokenInformation writes TOKEN_USER into a byte buffer. Vec<u8> has
        // no TOKEN_USER alignment guarantee, so copy the fixed header out with
        // an unaligned read before using its SID pointer.
        let token_user =
            unsafe { std::ptr::read_unaligned(self.buffer.as_ptr() as *const TOKEN_USER) };
        Ok(token_user.User.Sid)
    }
}

fn validate_pipe_server_owner(pipe_handle: HANDLE) -> io::Result<()> {
    let mut server_process_id = 0;
    let result = unsafe { GetNamedPipeServerProcessId(pipe_handle, &mut server_process_id) };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }

    let server_process =
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, server_process_id) };
    if server_process == 0 {
        return Err(io::Error::last_os_error());
    }
    let server_process = OwnedHandle(server_process);
    let server_token = open_process_token(server_process.raw())?;
    let current_token = open_process_token(unsafe { GetCurrentProcess() })?;
    let server_user = token_user(server_token.raw())?;
    let current_user = token_user(current_token.raw())?;

    if unsafe { EqualSid(server_user.sid()?, current_user.sid()?) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "IDE context provider is not owned by the current user",
        ));
    }

    Ok(())
}

fn open_process_token(process: HANDLE) -> io::Result<OwnedHandle> {
    let mut token = 0;
    let result = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(OwnedHandle(token))
}

fn token_user(token: HANDLE) -> io::Result<TokenUserBuffer> {
    let mut return_length = 0;
    unsafe {
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut return_length);
    }
    if return_length == 0 {
        return Err(io::Error::last_os_error());
    }

    let mut buffer = vec![0_u8; return_length as usize];
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr() as *mut _,
            return_length,
            &mut return_length,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(TokenUserBuffer { buffer })
}

fn remaining_timeout_ms(deadline: Instant) -> u32 {
    let now = Instant::now();
    if now >= deadline {
        return 0;
    }

    let millis = deadline.duration_since(now).as_millis().max(1);
    u32::try_from(millis).unwrap_or(u32::MAX)
}

fn timeout_io_error() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "timed out waiting for IDE context")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;
    use windows_sys::Win32::System::Pipes::CreateNamedPipeW;
    use windows_sys::Win32::System::Pipes::PIPE_READMODE_BYTE;
    use windows_sys::Win32::System::Pipes::PIPE_TYPE_BYTE;
    use windows_sys::Win32::System::Pipes::PIPE_WAIT;

    const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;

    #[test]
    fn connect_waits_for_busy_pipe_until_deadline() {
        let pipe_name = unique_pipe_name();
        let wide_path = pipe_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();

        let server = unsafe {
            CreateNamedPipeW(
                wide_path.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                ptr::null_mut(),
            )
        };
        assert!(server != 0 && server != INVALID_HANDLE_VALUE);
        let _server = OwnedHandle(server);

        let first_client = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL_HANDLE,
            )
        };
        assert!(first_client != 0 && first_client != INVALID_HANDLE_VALUE);
        let _first_client = OwnedHandle(first_client);

        let deadline = Instant::now() + Duration::from_millis(50);
        let error = connect_to_pipe_before_deadline(&wide_path, deadline).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    fn unique_pipe_name() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after epoch")
            .as_nanos();
        format!(r"\\.\pipe\codex-ide-test-{}-{nanos}", std::process::id())
    }
}
