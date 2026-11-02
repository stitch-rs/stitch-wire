//! SIMD feature detection and hardware capabilities for `#![no_std]`.

#[cfg(all(target_arch = "x86_64", not(miri)))]
use core::sync::atomic::{AtomicU8, Ordering};

/// Returns `true` if the host CPU and OS support AVX2 instructions.
///
/// Detected once via CPUID and cached atomically with zero runtime overhead.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn has_avx2() -> bool {
    #[cfg(miri)]
    return false;

    #[cfg(not(miri))]
    {
        // 0 = uninitialized, 1 = supported, 2 = unsupported
        static STATE: AtomicU8 = AtomicU8::new(0);

        let val = STATE.load(Ordering::Relaxed);
        if val == 1 {
            return true;
        }
        if val == 2 {
            return false;
        }

        let max_leaf = core::arch::x86_64::__cpuid(0).eax;
        if max_leaf < 7 {
            STATE.store(2, Ordering::Relaxed);
            return false;
        }

        let leaf1 = core::arch::x86_64::__cpuid(1);
        let osxsave = (leaf1.ecx & (1 << 27)) != 0;
        let avx = (leaf1.ecx & (1 << 28)) != 0;

        if !osxsave || !avx {
            STATE.store(2, Ordering::Relaxed);
            return false;
        }

        // SAFETY: We verified OSXSAVE bit (bit 27 of cpuid leaf 1) is set before calling _xgetbv.
        let xcr0 = unsafe { core::arch::x86_64::_xgetbv(0) };
        if (xcr0 & 0b110) != 0b110 {
            STATE.store(2, Ordering::Relaxed);
            return false;
        }

        let leaf7 = core::arch::x86_64::__cpuid_count(7, 0);
        let avx2 = (leaf7.ebx & (1 << 5)) != 0;

        if avx2 {
            STATE.store(1, Ordering::Relaxed);
            true
        } else {
            STATE.store(2, Ordering::Relaxed);
            false
        }
    }
}

/// Returns `false` on non-x86_64 targets.
#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub const fn has_avx2() -> bool {
    false
}
