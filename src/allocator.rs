use std::{
    alloc::{Layout, alloc, dealloc},
    ops::Range,
    ptr::NonNull,
};

use range_alloc::RangeAllocator;
use unicorn_engine::{Prot, Unicorn};

pub struct Allocator {
    allocator: RangeAllocator<u64>,
}

pub struct Allocation {
    pub address: u64,
    pub host_address: NonNull<u8>,
    pub size: u64,
}

impl Allocator {
    pub fn new(start: u64, end: u64) -> Self {
        Self {
            allocator: RangeAllocator::new(Range { start, end }),
        }
    }

    pub fn alloc_unmapped(&mut self, size: u64) -> Option<Allocation> {
        let start_addr = self.allocator.allocate_range(size).ok().map(|it| it.start);
        let Some(start_addr) = start_addr else {
            return None;
        };
        let ptr = unsafe { alloc(Layout::from_size_align(size as usize, 1).unwrap()) };
        let ptr = NonNull::new(ptr).unwrap();
        Some(Allocation {
            address: start_addr,
            host_address: ptr,
            size,
        })
    }

    pub fn free_unmapped(&mut self, allocation: &Allocation) {
        unsafe {
            dealloc(
                allocation.host_address.as_ptr(),
                Layout::from_size_align(allocation.size as usize, 1).unwrap(),
            );
        };
        self.allocator.free_range(Range {
            start: allocation.address,
            end: allocation.address + allocation.size,
        });
    }

    pub fn alloc_mapped(
        &mut self,
        emu: &mut Unicorn<'_, ()>,
        size: u64,
        prot: Prot,
    ) -> Option<Allocation> {
        let size = align_size(size);
        let Some(allocation) = self.alloc_unmapped(size) else {
            return None;
        };
        unsafe {
            emu.mem_map_ptr(
                allocation.address,
                allocation.size,
                prot,
                allocation.host_address.as_ptr() as *mut _,
            )
            .unwrap();
        }
        Some(allocation)
    }

    pub fn free_mapped(&mut self, emu: &mut Unicorn<'_, ()>, allocation: &Allocation) { 
        emu.mem_unmap(allocation.address, allocation.size).unwrap();
        self.free_unmapped(allocation);
    }
}

fn align_size(size: u64) -> u64 {
    // Align to 4KB pages
    (size + 0xFFF) & !0xFFF
}
