use core::{mem::size_of, ptr::null_mut};

extern "C" {
    static HEAP_START: usize;
    static HEAP_SIZE: usize;
}

// We will use ALLOC_START to mark the start of the actual
// memory we can dish out.
static mut ALLOC_START: usize = 0;
const PAGE_ORDER: usize = 12;
pub const PAGE_SIZE: usize = 1 << 12;

/// Align (set to a multiple of some power of two)
/// This takes an order which is the exponent to 2^order
/// Therefore, all alignments must be made as a power of two.
/// This function always rounds up.
pub const fn align_val(val: usize, order: usize) -> usize {
    let o = (1usize << order) - 1;
    (val + o) & !o
}

// These are the page flags, we represent this
// as a u8, since the Page stores this flag.
#[repr(u8)]
pub enum PageBits {
    Empty = 0,
    Taken = 1 << 0,
    Last = 1 << 1,
}

impl PageBits {
    pub fn val(self) -> u8 {
        self as u8
    }
}

pub struct Page {
    flags: u8,
}

impl Page {
    pub fn is_last(&self) -> bool {
        if self.flags & PageBits::Last.val() != 0 {
            true
        } else {
            false
        }
    }

    pub fn is_taken(&self) -> bool {
        if self.flags & PageBits::Taken.val() != 0 {
            true
        } else {
            false
        }
    }

    pub fn is_free(&self) -> bool {
        !self.is_taken()
    }

    pub fn clear(&mut self) {
        self.flags = PageBits::Empty.val();
    }

    pub fn set_flag(&mut self, flag: PageBits) {
        self.flags |= flag.val();
    }

    pub fn clear_flag(&mut self, flag: PageBits) {
        self.flags &= !(flag.val());
    }
}

/// Init the memory page allocation subsystem. If called twice, this will panic.
pub fn init() {
    unsafe {
        let num_pages = HEAP_SIZE / PAGE_SIZE;
        let ptr = HEAP_START as *mut Page;
        // Clear all pages so they aren't seen as taken
        for i in 0..num_pages {
            (*ptr.add(i)).clear();
        }

        assert_eq!(ALLOC_START, 0);

        // Determine where useful memory starts, after all Page structures.
        // This must be aligned to 4096 bytes.
        ALLOC_START = align_val(HEAP_START + num_pages * size_of::<Page>(), PAGE_ORDER);
    }
}

pub fn alloc(pages: usize) -> *mut u8 {
    // We have to find a contiguous allocation of pages
    assert!(pages > 0);
    unsafe {
        // We create a Page structure for each page on the heap. We
        // actually might have more since HEAP_SIZE moves and so does
        // the size of our structure, but we'll only waste a few bytes.
        let num_pages = HEAP_SIZE / PAGE_SIZE;
        let ptr = HEAP_START as *mut Page;
        for i in 0..num_pages - pages {
            let mut found = false;
            // Check to see if this Page is free. If so, we have our
            // first candidate memory address.
            if (*ptr.add(i)).is_free() {
                // It was FREE! Yay!
                found = true;
                for j in i..i + pages {
                    // Now check to see if we have a
                    // contiguous allocation for all of the
                    // request pages. If not, we should
                    // check somewhere else.
                    if (*ptr.add(j)).is_taken() {
                        found = false;
                        break;
                    }
                }
            }

            // We've checked to see if there are enough contiguous
            // pages to form what we need. If we couldn't, found
            // will be false, otherwise it will be true, which means
            // we've found valid memory we can allocate.
            if found {
                for k in i..i + pages - 1 {
                    (*ptr.add(k)).set_flag(PageBits::Taken);
                }
                // The marker for the last page is
                // PageBits::Last This lets us know when we've
                // hit the end of this particular allocation.
                (*ptr.add(i + pages - 1)).set_flag(PageBits::Taken);
                (*ptr.add(i + pages - 1)).set_flag(PageBits::Last);
                // The Page structures themselves aren't the
                // useful memory. Instead, there is 1 Page
                // structure per 4096 bytes starting at
                // ALLOC_START.
                return (ALLOC_START + PAGE_SIZE * i) as *mut u8;
            }
        }
    }

    // If we get here, that means that no contiguous allocation was
    // found.
    null_mut()
}

pub fn dealloc(ptr: *mut u8) {
    // Make sure we don't try to free a null pointer.
    assert!(!ptr.is_null());
    unsafe {
        let addr = HEAP_START + (ptr as usize - ALLOC_START) / PAGE_SIZE;
        // Make sure that the address makes sense. The address we
        // calculate here is the page structure, not the HEAP address!
        assert!(addr >= HEAP_START && addr < HEAP_START + HEAP_SIZE);
        let mut p = addr as *mut Page;
        // Keep clearing pages until we hit the last page.
        while (*p).is_taken() && !(*p).is_last() {
            (*p).clear();
            p = p.add(1);
        }
        // If the following assertion fails, it is most likely
        // caused by a double-free.
        assert!(
            (*p).is_last() == true,
            "Possible double-free detected! (Not taken found \
					before last)"
        );
        // If we get here, we've taken care of all previous pages and
        // we are on the last page.
        (*p).clear();
    }
}

/// Allocate and zero a page or multiple pages
/// pages: the number of pages to allocate
/// Each page is PAGE_SIZE which is calculated as 1 << PAGE_ORDER
/// On RISC-V, this typically will be 4,096 bytes.
pub fn zalloc(pages: usize) -> *mut u8 {
    // Allocate and zero a page.
    // First, let's get the allocation
    let ret = alloc(pages);
    if !ret.is_null() {
        let size = (PAGE_SIZE * pages) / 8;
        let big_ptr = ret as *mut u64;
        for i in 0..size {
            // We use big_ptr so that we can force an
            // sd (store doubleword) instruction rather than
            // the sb. This means 8x fewer stores than before.
            // Typically we have to be concerned about remaining
            // bytes, but fortunately 4096 % 8 = 0, so we
            // won't have any remaining bytes.
            unsafe {
                (*big_ptr.add(i)) = 0;
            }
        }
    }
    ret
}

/// Print all page allocations
/// This is mainly used for debugging.
pub fn print_page_allocations() {
    unsafe {
        let num_pages = HEAP_SIZE / PAGE_SIZE;
        let mut beg = HEAP_START as *const Page;
        let end = beg.add(num_pages);
        let alloc_beg = ALLOC_START;
        let alloc_end = ALLOC_START + num_pages * PAGE_SIZE;
        println!();
        println!(
            "PAGE ALLOCATION TABLE\nMETA: {:p} -> {:p}\nPHYS: \
					0x{:x} -> 0x{:x}",
            beg, end, alloc_beg, alloc_end
        );
        println!("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        let mut num = 0;
        while beg < end {
            if (*beg).is_taken() {
                let start = beg as usize;
                let memaddr = ALLOC_START + (start - HEAP_START) * PAGE_SIZE;
                print!("0x{:x} => ", memaddr);
                loop {
                    num += 1;
                    if (*beg).is_last() {
                        let end = beg as usize;
                        let memaddr = ALLOC_START + (end - HEAP_START) * PAGE_SIZE + PAGE_SIZE - 1;
                        print!("0x{:x}: {:>3} page(s)", memaddr, (end - start + 1));
                        println!(".");
                        break;
                    }
                    beg = beg.add(1);
                }
            }
            beg = beg.add(1);
        }
        println!("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        println!(
            "Allocated: {:>6} pages ({:>10} bytes).",
            num,
            num * PAGE_SIZE
        );
        println!(
            "Free     : {:>6} pages ({:>10} bytes).",
            num_pages - num,
            (num_pages - num) * PAGE_SIZE
        );
        println!();
    }
}

// Represent (repr) our entry bits as unsigned 64-bit integers.
#[repr(i64)]
#[derive(Copy, Clone)]
pub enum EntryBits {
    None = 0,
    Valid = 1 << 0,
    Read = 1 << 1,
    Write = 1 << 2,
    Execute = 1 << 3,
    User = 1 << 4,
    Global = 1 << 5,
    Access = 1 << 6,
    Dirty = 1 << 7,

    // Convenience combinations
    ReadWrite = 1 << 1 | 1 << 2,
    ReadExecute = 1 << 1 | 1 << 3,
    ReadWriteExecute = 1 << 1 | 1 << 2 | 1 << 3,

    // User Convenience Combinations
    UserReadWrite = 1 << 1 | 1 << 2 | 1 << 4,
    UserReadExecute = 1 << 1 | 1 << 3 | 1 << 4,
    UserReadWriteExecute = 1 << 1 | 1 << 2 | 1 << 3 | 1 << 4,
}

impl EntryBits {
    pub fn val(self) -> i64 {
        self as i64
    }
}

/// A single entry, using an i64 so that it will sign-extend rather than
/// zero-extend since RISC-V requires that the reserved sections take on
/// the most significant bit.
pub struct Entry {
    pub entry: i64,
}

impl Entry {
    /// The first bit is the v bit, for valid.
    pub fn is_valid(&self) -> bool {
        self.get_entry() & EntryBits::Valid.val() != 0
    }

    pub fn is_invalid(&self) -> bool {
        !self.is_valid()
    }

    /// A leaf has one or more RWX bits set
    pub fn is_leaf(&self) -> bool {
        self.get_entry() & 0xe != 0
    }

    pub fn is_branch(&self) -> bool {
        !self.is_leaf()
    }

    pub fn set_entry(&mut self, entry: i64) {
        self.entry = entry
    }

    pub fn get_entry(&self) -> i64 {
        self.entry
    }
}

pub struct Table {
    pub entries: [Entry; 512],
}

impl Table {
    pub fn len() -> usize {
        512
    }
}

pub fn map(root: &mut Table, vaddr: usize, paddr: usize, bits: i64, level: usize) {
    // Ensure that Read, Write, or Execute bits have been set. If these aren't set,
    // memory will leak and result in a page fault.
    assert!(bits & 0xe != 0);

    // Extract out the VPN from the virtual address. Each VPN is 9 bits of the virtual
    // address, which is why we use the mask 0x1ff == 0b1_1111_1111 (9 bits).
    let vpn = [
        // VPN[0] = vaddr[20:12]
        (vaddr >> 12) & 0x1ff,
        // VPN[1] = vaddr[29:21]
        (vaddr >> 21) & 0x1ff,
        // VPN[2] = vaddr[38:30]
        (vaddr >> 30) & 0x1ff,
    ];

    // Just like the virtual address, extract the physical address number (PPN). PPN[2]
    // stores 26 bits instead of 9. This requires that you use
    // 0x3ff_ffff == 0b11_1111_1111_1111_1111_1111_1111 (26 bits).
    let ppn = [
        // PPN[0] = paddr[20:12]
        (paddr >> 12) & 0x1ff,
        // PPN[1] = paddr[29:21]
        (paddr >> 29) & 0x1ff,
        // PPN[2] = paddr[55:30]
        (paddr >> 30) & 0x3ff_ffff,
    ];

    // We will use this as a reference to get individual entries as we walk the table.
    let mut v = &mut root.entries[vpn[2]];

    // Traverse the page table and set bits appropriately. We expect the root to be valid,
    // but we're required to create anything beyond the root.
    //
    // This also abuses the fact that `..` in rust is exclusive on the end, but inclusive
    // at the start, meaning that (0..2) iterates 0 and 1.
    for i in (level..2).rev() {
        if !v.is_valid() {
            // allocate a page
            let page = zalloc(1);
            // The page is 4096-aligned, so store it dorectly in the entry shifted right by
            // two places.
            v.set_entry((page as i64 >> 2) | EntryBits::Valid.val());
        }

        // Extract out the entry.
        let entry = ((v.get_entry() & !0x3ff) << 2) as *mut Entry;
        v = unsafe { entry.add(vpn[i]).as_mut().unwrap() };
    }

    // When we get here, we should be at VPN[0] and v should be pointing to our entry. The
    // entry structure is figure 4.18 in the RISC-V Privileged Specification.
    #[rustfmt::skip]
    let entry =
        (ppn[2] << 28) as i64 | // PPN[2] = [53:28]
        (ppn[1] << 19) as i64 | // PPN[1] = [27:19]
        (ppn[0] << 10) as i64 | // PPN[0] = [18:10]
        bits |                  // Specified buts such as User, Read, Write, etc.
        EntryBits::Valid.val(); // Valid bit

    // Set the entry, the above loop should set v to the correct pointer.
    v.set_entry(entry);
}

/// Unmap and frees all memory associated with a table. Takes the root table to start
/// freeing. This does NOT free the root directly. The root MUST be freed manually.
/// Roots are typically embedded into process structures.
pub fn unmap(root: &mut Table) {
    // Start with level 2 of the page table.
    for lv2 in 0..Table::len() {
        let ref entry_lv2 = root.entries[lv2];
        if entry_lv2.is_valid() && entry_lv2.is_branch() {
            // This is a valid entry, so drill down and free.
            let memaddr_lv1 = (entry_lv2.get_entry() & !0x3ff) << 2;
            let table_lv1 = unsafe {
                // Make table_lv1 a mutable reference instead of a pointer.
                (memaddr_lv1 as *mut Table).as_mut().unwrap()
            };
            for lv1 in 0..Table::len() {
                let ref entry_lv1 = table_lv1.entries[lv1];
                if entry_lv1.is_valid() && entry_lv1.is_branch() {
                    let memaddr_lv0 = (entry_lv1.get_entry() & !0x3ff) << 2;
                    // Next level is level 0, which can't have branches. Free the page.
                    dealloc(memaddr_lv0 as *mut u8);
                }
            }
            dealloc(memaddr_lv1 as *mut u8);
        }
    }
}

/// Manually walk the page table to convert virtual addresses to physical addresses.
/// User processes will always have different virtual addresses than physical addresses
/// do. The kernel needs to write to physical addresses. We can pass any table into this
/// function regardless of if it is used by the MMU or not.
pub fn virt_to_phys(root: &Table, vaddr: usize) -> Option<usize> {
    // Walk to the page table pointed to by root.
    let vpn = [
				// VPN[0] = vaddr[20:12]
				(vaddr >> 12) & 0x1ff,
				// VPN[1] = vaddr[29:21]
				(vaddr >> 21) & 0x1ff,
				// VPN[2] = vaddr[38:30]
				(vaddr >> 30) & 0x1ff,
    ];

    let mut v = &root.entries[vpn[2]];
    // (0..=2) does an inclusive range.
    for i in (0..=2).rev() {
        if v.is_invalid() {
            // This is an invalid entry, meaning this is a page fault.
            break;
        } else if v.is_leaf() {
            // A leaf can be at any level.

            // The offset masks off the PPN, each PPN is 9 bits and starts at bit 12.
            let off_mask = (1 << (12 + i * 9)) - 1;
            let vaddr_pgoff = vaddr & off_mask;
            let addr = ((v.get_entry() << 2) as usize) & !off_mask;
            return Some(addr | vaddr_pgoff);
        }

        // Set v to the next entry. Unshift by 2 bits.
        let entry = ((v.get_entry() & !0x3ff) << 2) as *const Entry;

        // We do i-1 here, we should get None or Some() above before we get -1.
        v = unsafe { entry.add(vpn[i-1]).as_ref().unwrap() };
    }

    // If we get here, we've exhausted all valid tables and haven't found a leaf.
    // This is probably a page fault.
    None
}
