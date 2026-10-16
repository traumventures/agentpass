//! Locked, guarded memory for secrets and process hardening.
//!
//! [`SecureBuf`] allocates its own anonymous mapping:
//!
//! ```text
//! | guard page (PROT_NONE) | data pages (mlock, MADV_DONTDUMP) | guard page (PROT_NONE) |
//! ```
//!
//! The data pages are never swapped out, excluded from core dumps (Linux),
//! not inherited by forked children (Linux, `MADV_WIPEONFORK`) and wiped with
//! volatile writes before they are unmapped. Buffers have a fixed capacity, so
//! they never reallocate and leave stray copies behind.

use std::io;
use std::ptr::NonNull;

use zeroize::Zeroize;

pub struct SecureBuf {
    map: NonNull<u8>,
    map_len: usize,
    data: NonNull<u8>,
    data_len: usize,
    len: usize,
}

// SAFETY: SecureBuf owns its mapping exclusively; access goes through &/&mut.
unsafe impl Send for SecureBuf {}
unsafe impl Sync for SecureBuf {}

fn page_size() -> usize {
    // SAFETY: sysconf has no preconditions.
    let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if p <= 0 {
        4096
    } else {
        p as usize
    }
}

impl SecureBuf {
    /// Allocates a zeroed buffer of exactly `len` usable bytes.
    pub fn new(len: usize) -> io::Result<Self> {
        let page = page_size();
        let data_len = len.max(1).div_ceil(page) * page;
        let map_len = data_len + 2 * page;
        // SAFETY: anonymous private mapping, checked for MAP_FAILED below.
        let map = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                map_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if map == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let map = map as *mut u8;
        // From here on, `guard` unmaps on early return.
        struct Unmap(*mut u8, usize);
        impl Drop for Unmap {
            fn drop(&mut self) {
                // SAFETY: the region was mapped by us with this length.
                unsafe { libc::munmap(self.0 as *mut libc::c_void, self.1) };
            }
        }
        let guard = Unmap(map, map_len);
        // SAFETY: all pointers stay within the mapping created above.
        unsafe {
            let data = map.add(page);
            check(libc::mprotect(map as *mut _, page, libc::PROT_NONE))?;
            check(libc::mprotect(
                data.add(data_len) as *mut _,
                page,
                libc::PROT_NONE,
            ))?;
            if libc::mlock(data as *const _, data_len) != 0 {
                let err = io::Error::last_os_error();
                return Err(io::Error::new(
                    err.kind(),
                    format!("could not lock secret memory (mlock): {err}; raise `ulimit -l`"),
                ));
            }
            #[cfg(target_os = "linux")]
            {
                check(libc::madvise(data as *mut _, data_len, libc::MADV_DONTDUMP))?;
                // Best effort: not available before Linux 4.14.
                libc::madvise(data as *mut _, data_len, libc::MADV_WIPEONFORK);
            }
            std::mem::forget(guard);
            Ok(Self {
                map: NonNull::new_unchecked(map),
                map_len,
                data: NonNull::new_unchecked(data),
                data_len,
                len,
            })
        }
    }

    /// Copies `bytes` into a new buffer.
    pub fn from_slice(bytes: &[u8]) -> io::Result<Self> {
        let mut buf = Self::new(bytes.len())?;
        buf.as_mut_slice().copy_from_slice(bytes);
        Ok(buf)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Shrinks the visible length; bytes past it are wiped.
    pub fn truncate(&mut self, len: usize) {
        if len < self.len {
            self.as_mut_slice()[len..].zeroize();
            self.len = len;
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: data points to at least `len` initialised bytes we own.
        unsafe { std::slice::from_raw_parts(self.data.as_ptr(), self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as above, and &mut self guarantees exclusivity.
        unsafe { std::slice::from_raw_parts_mut(self.data.as_ptr(), self.len) }
    }

    /// Address of the data region, for diagnostics and tests.
    pub fn addr(&self) -> usize {
        self.data.as_ptr() as usize
    }
}

impl Drop for SecureBuf {
    fn drop(&mut self) {
        // SAFETY: the full data region is ours and writable.
        unsafe {
            std::slice::from_raw_parts_mut(self.data.as_ptr(), self.data_len).zeroize();
            libc::munlock(self.data.as_ptr() as *const _, self.data_len);
            libc::munmap(self.map.as_ptr() as *mut _, self.map_len);
        }
    }
}

impl std::fmt::Debug for SecureBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureBuf([REDACTED; {}])", self.len)
    }
}

fn check(rc: libc::c_int) -> io::Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Disables core dumps for this process (inherited by children).
pub fn disable_core_dumps() -> io::Result<()> {
    let lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: valid pointer to an initialised rlimit.
    check(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &lim) })
}

/// Prevents normal same-user processes from attaching with ptrace or reading
/// `/proc/<pid>/mem` (Linux). Reset by `execve`.
pub fn deny_same_user_inspection() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl with integer arguments.
        check(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) })?;
    }
    Ok(())
}

/// Hardening applied to short-lived CLI processes that handle plaintext.
pub fn harden_client() {
    let _ = disable_core_dumps();
    let _ = deny_same_user_inspection();
}

/// Hardening applied to the long-lived daemon. Fails closed.
pub fn harden_daemon() -> io::Result<()> {
    disable_core_dumps()?;
    deny_same_user_inspection()?;
    #[cfg(target_os = "macos")]
    {
        const PT_DENY_ATTACH: libc::c_int = 31;
        // SAFETY: PT_DENY_ATTACH takes no address or data.
        unsafe { libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_roundtrip_and_truncate() {
        let mut b = SecureBuf::from_slice(b"hello world").unwrap();
        assert_eq!(b.as_slice(), b"hello world");
        b.truncate(5);
        assert_eq!(b.as_slice(), b"hello");
        assert_eq!(format!("{b:?}"), "SecureBuf([REDACTED; 5])");
    }

    #[test]
    fn empty_and_multi_page_buffers() {
        let b = SecureBuf::new(0).unwrap();
        assert!(b.is_empty());
        let mut big = SecureBuf::new(3 * page_size() + 7).unwrap();
        big.as_mut_slice().fill(0xAB);
        assert!(big.as_slice().iter().all(|&x| x == 0xAB));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn data_pages_are_locked_and_excluded_from_dumps() {
        let b = SecureBuf::from_slice(&[7u8; 32]).unwrap();
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let start = format!("{:x}-", b.addr());
        // VmFlags is the last line of each mapping's section.
        let flags = smaps
            .lines()
            .skip_while(|l| !l.starts_with(&start))
            .find(|l| l.starts_with("VmFlags:"))
            .expect("mapping present in smaps");
        assert!(flags.contains(" lo"), "not mlocked: {flags}");
        assert!(flags.contains(" dd"), "not MADV_DONTDUMP: {flags}");
    }
}
