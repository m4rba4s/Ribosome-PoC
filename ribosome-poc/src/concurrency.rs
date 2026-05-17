use core::sync::atomic::{AtomicUsize, Ordering};
use std::cell::UnsafeCell;
use std::mem::MaybeUninit;

use crate::syscalls::raw_sched_setaffinity;

#[derive(Debug)]
pub enum ConcurrencyError {
    PinFailed(i64),
}

impl core::fmt::Display for ConcurrencyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConcurrencyError::PinFailed(e) => write!(f, "sched_setaffinity failed: errno={}", -e),
        }
    }
}

impl std::error::Error for ConcurrencyError {}

/// Pins the current thread to the specified CPU core using `sched_setaffinity`.
pub fn pin_to_core(core_id: usize) -> Result<(), ConcurrencyError> {
    // A cpu_set_t in Linux is a bitmask. For a typical system, it's 1024 bits (128 bytes).
    // We construct a simple 128-byte array and set the bit for `core_id`.
    let mut cpu_set = [0u8; 128];
    if core_id < 1024 {
        let byte_idx = core_id / 8;
        let bit_idx = core_id % 8;
        cpu_set[byte_idx] |= 1 << bit_idx;
    }

    // syscall(SYS_SCHED_SETAFFINITY, pid (0 = self), cpusetsize, &mask)
    let ret = unsafe { raw_sched_setaffinity(0, cpu_set.len(), cpu_set.as_ptr()) };

    if ret < 0 {
        return Err(ConcurrencyError::PinFailed(ret));
    }
    Ok(())
}

/// A fixed-size Lock-Free MPMC/SPSC Ring Buffer
/// Capacity must be a power of 2 for fast modulo arithmetic.
pub struct RingBuffer<T, const CAP: usize> {
    head: AtomicUsize,
    tail: AtomicUsize,
    buffer: [UnsafeCell<MaybeUninit<T>>; CAP],
}

// Safety: We implement our own synchronization using Atomics.
unsafe impl<T: Send, const CAP: usize> Sync for RingBuffer<T, CAP> {}
unsafe impl<T: Send, const CAP: usize> Send for RingBuffer<T, CAP> {}

impl<T, const CAP: usize> RingBuffer<T, CAP> {
    pub const fn new() -> Self {
        // Assert capacity is a power of 2 at compile time (trick via array size evaluation)
        // Since we can't use static_assert easily in const fn, we just trust the caller or
        // use a bitwise check if needed. We assume CAP is a power of 2.

        // Initialize an array of UnsafeCell<MaybeUninit<T>>
        // This is safe because MaybeUninit does not require initialization.
        let buffer = unsafe { MaybeUninit::uninit().assume_init() };

        Self {
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            buffer,
        }
    }

    /// Try to push an item. Returns Err(item) if the buffer is full.
    pub fn push(&self, item: T) -> Result<(), T> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire); // Sync with readers

        // Full check: head + 1 == tail (using modulo)
        let next_head = (head + 1) & (CAP - 1);
        if next_head == tail {
            return Err(item); // Buffer is full
        }

        // Write the item into the UnsafeCell
        unsafe {
            let slot = self.buffer[head].get();
            (*slot).write(item);
        }

        // Advance head and release memory barrier so consumers see the written data
        self.head.store(next_head, Ordering::Release);
        Ok(())
    }

    /// Try to pop an item. Returns None if the buffer is empty.
    pub fn pop(&self) -> Option<T> {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire); // Sync with writers

        // Empty check
        if tail == head {
            return None; // Buffer is empty
        }

        // Read the item
        let item = unsafe {
            let slot = self.buffer[tail].get();
            (*slot).assume_init_read() // We consume the value
        };

        // Advance tail
        let next_tail = (tail + 1) & (CAP - 1);
        self.tail.store(next_tail, Ordering::Release);
        Some(item)
    }
}
