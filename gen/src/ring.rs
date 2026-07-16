use std::ffi::CString;
use std::fmt;
use std::os::raw::{c_char, c_int, c_void};

unsafe extern "C" {
    fn ring_open(name: *const c_char, size: usize, out_handle: *mut c_int) -> c_int;
    fn ring_write(handle: c_int, buf: *const c_void, len: usize) -> c_int;
    fn ring_close(handle: c_int);
}

#[derive(Debug)]
pub enum RingError {
    InvalidName,
    OpenFailed(i32),
    WriteFailed(i32),
}

impl fmt::Display for RingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RingError::InvalidName => write!(f, "ring name contains interior NUL"),
            RingError::OpenFailed(code) => write!(f, "ring_open failed with errno {}", code),
            RingError::WriteFailed(code) => write!(f, "ring_write failed with errno {}", code),
        }
    }
}

impl std::error::Error for RingError {}

pub struct Ring {
    handle: c_int,
}

impl Ring {
    pub fn open(name: &str, size: usize) -> Option<Self> {
        Self::try_open(name, size).ok()
    }

    pub fn try_open(name: &str, size: usize) -> Result<Self, RingError> {
        let c_name = CString::new(name).map_err(|_| RingError::InvalidName)?;
        let mut handle: c_int = -1;
        let rc = unsafe { ring_open(c_name.as_ptr(), size, &mut handle as *mut c_int) };
        if rc != 0 {
            return Err(RingError::OpenFailed(rc));
        }
        Ok(Self { handle })
    }

    pub fn write(&self, buf: &[u8]) -> Result<(), RingError> {
        let rc = unsafe { ring_write(self.handle, buf.as_ptr() as *const c_void, buf.len()) };
        if rc != 0 {
            return Err(RingError::WriteFailed(rc));
        }
        Ok(())
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        unsafe {
            ring_close(self.handle);
        }
    }
}
