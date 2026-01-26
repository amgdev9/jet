use std::ops::Range;

use range_alloc::RangeAllocator;
use unicorn_engine::{Prot, Unicorn};

pub struct Allocator {
    allocator: RangeAllocator<u64>,
}

impl Allocator {
    pub fn new(start: u64, end: u64) -> Self {
        Self {
            allocator: RangeAllocator::new(Range { start, end }),
        }
    }

    pub fn alloc_unmapped(&mut self, size: u64) -> Option<u64> {
        let start_addr = self.allocator.allocate_range(size).ok().map(|it| it.start);
        let Some(start_addr) = start_addr else {
            return None;
        };
        Some(start_addr)
    }

    pub fn free_unmapped(&mut self, start_addr: u64, size: u64) {
        self.allocator.free_range(Range {
            start: start_addr,
            end: start_addr + size,
        });
    }

    pub fn alloc_mapped(
        &mut self,
        emu: &mut Unicorn<'_, ()>,
        size: u64,
        prot: Prot,
    ) -> Option<u64> {
        let size = align_size(size);
        let Some(start_addr) = self.alloc_unmapped(size) else {
            return None;
        };
        emu.mem_map(start_addr, size, prot).unwrap();
        Some(start_addr)
    }

    pub fn free_mapped(&mut self, emu: &mut Unicorn<'_, ()>, start_addr: u64, size: u64) {
        let size = align_size(size);
        emu.mem_unmap(start_addr, size).unwrap();
        self.free_unmapped(start_addr, size);
    }
}

fn align_size(size: u64) -> u64 {
    // Align to 4KB pages
    (size + 0xFFF) & !0xFFF
}
