use std::ops::Range;

use range_alloc::RangeAllocator;
use unicorn_engine::{Prot, Unicorn};

pub struct Allocator {
    /*
     * The memory layout of the program is like this
     * PROGRAM | HEAP_START .. MMAP_START .. MMAP_END | STACK
     * Between HEAP_START and MMAP_START is the heap, and can grow or shrink
     * Between MMAP_START and MMAP_END is the MMAP region, used to allocate bigger chunks
     */
    pub heap_start: u64,
    pub mmap_start: u64,
    pub mmap_end: u64,
    allocator: RangeAllocator<u64>,
}

impl Allocator {
    pub fn new(heap_start: u64, mmap_start: u64, mmap_end: u64) -> Self {
        Self {
            heap_start,
            mmap_start,
            mmap_end,
            allocator: RangeAllocator::new(Range {
                start: mmap_start,
                end: mmap_end,
            }),
        }
    }

    pub fn mmap_alloc(&mut self, emu: &mut Unicorn<'_, ()>, size: u64) -> Option<u64> {
        // Align size to 4KB pages
        let size = (size + 0xFFF) & !0xFFF;
        let start_addr = self.allocator.allocate_range(size).ok().map(|it| it.start);
        let Some(start_addr) = start_addr else {
            return None;
        };
        emu.mem_map(start_addr, size, Prot::ALL).unwrap();
        Some(start_addr)
    }

    pub fn mmap_free(&mut self, emu: &mut Unicorn<'_, ()>, start_addr: u64, size: u64) {
        // Align size to 4KB pages
        let size = (size + 0xFFF) & !0xFFF;
        emu.mem_unmap(start_addr, size).unwrap();
        self.allocator.free_range(Range {
            start: start_addr,
            end: start_addr + size,
        });
    }

    // TODO Implement brk
}
