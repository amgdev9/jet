use std::{
    alloc::{Layout, alloc, dealloc},
    ops::Range,
    ptr::NonNull,
    thread::{self, ThreadId},
};

use log::{error, warn};
use range_alloc::RangeAllocator;
use unicorn_engine::{Prot, Unicorn};

pub struct Allocator {
    alloc_impl: RangeAllocator<u64>,
    allocations: Vec<Allocation>,
}

#[derive(Clone)]
pub struct UnsafeNonNull<T>(NonNull<T>);
unsafe impl<T> Send for UnsafeNonNull<T> {}
unsafe impl<T> Sync for UnsafeNonNull<T> {}

impl UnsafeNonNull<u8> {
    pub fn new(ptr: *mut u8) -> Option<Self> {
        NonNull::new(ptr).map(Self)
    }
    pub fn as_ptr(&self) -> *mut u8 {
        self.0.as_ptr()
    }
}

#[derive(Clone)]
pub struct Allocation {
    pub address: u64,
    pub host_address: UnsafeNonNull<u8>, // SAFETY: safe as long as the emulated program treats it safely
    pub size: u64,
    pub mappings: Vec<MemoryMapping>,
    pub status: AllocationStatus,
    pub mapped_threads: Vec<ThreadId>,
}

impl Allocation {
    pub fn map_to_current_thread(&mut self, emu: &mut Unicorn<'_, ()>) {
        let thread_id = thread::current().id();
        self.mappings.iter().for_each(|it| unsafe {
            emu.mem_map_ptr(
                self.address + it.offset,
                it.size,
                it.prot,
                self.host_address.as_ptr().add(it.offset as usize) as *mut _,
            )
            .unwrap();
        });
        self.mapped_threads.push(thread_id);
    }
}

#[derive(Clone, PartialEq)]
pub enum AllocationStatus {
    Ready,
    ToBeFreed,
}

#[derive(Clone)]
pub struct MemoryMapping {
    pub offset: u64,
    pub size: u64,
    pub prot: Prot,
    // TODO Ensure size is 4KB aligned (define ::new)
}

impl Allocator {
    pub fn new() -> Self {
        Self {
            alloc_impl: RangeAllocator::new(Range {
                start: 0,
                end: u64::MAX,
            }),
            allocations: Vec::new(),
        }
    }

    pub fn simple_alloc<'a>(
        &mut self,
        emu: &mut Unicorn<'a, ()>,
        size: u64,
        prot: Prot,
    ) -> Option<Allocation> {
        // Align to 4KB pages so mapping is safe
        let size = (size + 0xFFF) & !0xFFF;

        self.alloc(
            emu,
            size,
            vec![MemoryMapping {
                offset: 0,
                size,
                prot,
            }],
        )
    }

    pub fn alloc<'a>(
        &mut self,
        emu: &mut Unicorn<'a, ()>,
        size: u64,
        mappings: Vec<MemoryMapping>,
    ) -> Option<Allocation> {
        // TODO Maybe calling this on every allocation is suboptimal
        self.garbage_collect_thread(emu);

        let start_addr = self.alloc_impl.allocate_range(size).ok().map(|it| it.start);
        let Some(start_addr) = start_addr else {
            return None;
        };
        let host_ptr = unsafe { alloc(Layout::from_size_align(size as usize, 1).unwrap()) };
        let Some(host_ptr) = UnsafeNonNull::new(host_ptr) else {
            return None;
        };

        let mut allocation = Allocation {
            address: start_addr,
            host_address: host_ptr,
            size,
            mappings: mappings.clone(),
            status: AllocationStatus::Ready,
            mapped_threads: vec![],
        };

        allocation.map_to_current_thread(emu);

        self.allocations.push(allocation.clone());

        Some(allocation)
    }

    pub fn free<'a>(&mut self, emu: &mut Unicorn<'a, ()>, allocation: &Allocation) {
        let allocation = self
            .allocations
            .iter_mut()
            .find(|it| it.address == allocation.address);
        let Some(allocation) = allocation else {
            warn!("Double free detected");
            return;
        };
        allocation.status = AllocationStatus::ToBeFreed;

        // Free in case this thread was the only one using the allocation
        self.garbage_collect_thread(emu);
    }

    pub fn page_fault_handler<'a>(&mut self, emu: &mut Unicorn<'a, ()>, addr: u64) -> bool {
        let thread_id = thread::current().id();
        let allocation = self
            .allocations
            .iter_mut()
            .filter(|it| it.status == AllocationStatus::Ready)
            .filter(|it| !it.mapped_threads.contains(&thread_id))
            .find(|it| it.address <= addr && addr < it.address + it.size);
        let Some(allocation) = allocation else {
            error!("Page fault on unmapped address: {:#x}", addr);
            return false;
        };
        allocation.map_to_current_thread(emu);
        true
    }

    // Used to reclaim freed memory used by the current thread
    // Recommended to call this on thread exit to ensure memory is not leaked
    pub fn garbage_collect_thread<'a>(&mut self, emu: &mut Unicorn<'a, ()>) {
        let thread_id = thread::current().id();

        let mut mapped_freed_allocations = self
            .allocations
            .iter_mut()
            .filter(|it| it.mapped_threads.contains(&thread_id))
            .filter(|it| it.status == AllocationStatus::ToBeFreed)
            .collect::<Vec<_>>();

        mapped_freed_allocations.iter_mut().for_each(|allocation| {
            allocation.mappings.iter().for_each(|it| {
                emu.mem_unmap(allocation.address + it.offset, it.size)
                    .unwrap();
            });

            allocation.mapped_threads.retain(|it| *it != thread_id);

            // Free if this is the last thread using the allocation
            if allocation.mapped_threads.is_empty() {
                unsafe {
                    dealloc(
                        allocation.host_address.as_ptr(),
                        Layout::from_size_align(allocation.size as usize, 1).unwrap(),
                    );
                };
                self.alloc_impl.free_range(Range {
                    start: allocation.address,
                    end: allocation.address + allocation.size,
                });
            }
        });

        self.allocations.retain(|it| !it.mapped_threads.is_empty());
    }
}
