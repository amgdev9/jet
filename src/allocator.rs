use std::{
    alloc::{Layout, alloc, dealloc},
    ops::Range,
    ptr::NonNull,
};

use log::warn;
use range_alloc::RangeAllocator;
use unicorn_engine::{Prot, Unicorn};

pub struct Allocator {
    alloc_impl: RangeAllocator<u64>,
    allocations: Vec<Allocation>,
}

#[derive(Clone)]
pub struct Allocation {
    pub address: u64,
    pub host_address: NonNull<u8>,
    pub size: u64,
    pub mappings: Vec<MemoryMapping>,
}

#[derive(Clone)]
pub struct MemoryMapping {
    pub offset: u64,
    pub size: u64,
    pub prot: Prot,
}

impl Allocator {
    pub fn new(start: u64, end: u64) -> Self {
        Self {
            alloc_impl: RangeAllocator::new(Range { start, end }),
            allocations: Vec::new(),
        }
    }

    pub fn simple_alloc(
        &mut self,
        emu: &mut Unicorn<'_, ()>,
        size: u64,
        prot: Prot,
    ) -> Option<Allocation> {
        // Align to 4KB pages
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

    pub fn alloc(
        &mut self,
        emu: &mut Unicorn<'_, ()>,
        size: u64,
        mappings: Vec<MemoryMapping>,
    ) -> Option<Allocation> {
        let start_addr = self.alloc_impl.allocate_range(size).ok().map(|it| it.start);
        let Some(start_addr) = start_addr else {
            return None;
        };
        let host_ptr = unsafe { alloc(Layout::from_size_align(size as usize, 1).unwrap()) };
        let Some(host_ptr) = NonNull::new(host_ptr) else {
            return None;
        };

        mappings.iter().for_each(|it| unsafe {
            emu.mem_map_ptr(
                start_addr + it.offset,
                it.size,
                it.prot,
                host_ptr.as_ptr().add(it.offset as usize) as *mut _,
            )
            .unwrap();
        });

        let allocation = Allocation {
            address: start_addr,
            host_address: host_ptr,
            size,
            mappings,
        };

        self.allocations.push(allocation.clone());

        Some(allocation)
    }

    pub fn free(&mut self, emu: &mut Unicorn<'_, ()>, allocation: &Allocation) {
        let num_allocs = self.allocations.len();
        self.allocations
            .retain(|it| it.address != allocation.address);
        if self.allocations.len() == num_allocs {
            warn!("Allocation not found, maybe double free?");
            return;
        }

        allocation.mappings.iter().for_each(|it| {
            emu.mem_unmap(allocation.address + it.offset, it.size)
                .unwrap();
        });
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
}
