#[must_use]
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && constant_time_ne(a, b) == 0
}

#[inline]
#[must_use]
fn constant_time_ne(a: &[u8], b: &[u8]) -> u8 {
    assert!(a.len() == b.len());

    // These useless slices make the optimizer elide the bounds checks.
    // See the comment in clone_from_slice() added on Rust commit 6a7bc47.
    let len = a.len();
    let a = &a[..len];
    let b = &b[..len];

    let mut tmp = 0;
    for i in 0..len {
        tmp |= a[i] ^ b[i];
    }

    // The compare with 0 must happen outside this function.
    optimizer_hide(tmp)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
#[must_use]
fn optimizer_hide(mut value: u8) -> u8 {
    // SAFETY: the input value is passed unchanged to the output, the inline assembly does nothing.
    unsafe {
        core::arch::asm!("/* {0} */", inout(reg_byte) value, options(pure, nomem, nostack, preserves_flags));
        value
    }
}

#[cfg(any(
    target_arch = "arm",
    target_arch = "aarch64",
    target_arch = "riscv32",
    target_arch = "riscv64"
))]
#[inline]
#[must_use]
#[allow(asm_sub_register)]
fn optimizer_hide(mut value: u8) -> u8 {
    // SAFETY: the input value is passed unchanged to the output, the inline assembly does nothing.
    unsafe {
        core::arch::asm!("/* {0} */", inout(reg) value, options(pure, nomem, nostack, preserves_flags));
        value
    }
}
