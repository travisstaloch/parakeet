const std = @import("std");
const mem = std.mem;

pub fn allocator(self: *@This()) mem.Allocator {
    return .{
        .ptr = self,
        .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .free = free,
        },
    };
}
fn alloc(
    ctx: *anyopaque,
    len: usize,
    log2_ptr_align: u8,
    return_address: usize,
) ?[*]u8 {
    _ = return_address;
    _ = log2_ptr_align;
    _ = len;
    _ = ctx;
    return null;
}

fn resize(
    ctx: *anyopaque,
    old_mem: []u8,
    log2_old_align: u8,
    new_len: usize,
    ra: usize,
) bool {
    _ = ra;
    _ = new_len;
    _ = log2_old_align;
    _ = old_mem;
    _ = ctx;
    return false;
}
fn free(
    ctx: *anyopaque,
    old_mem: []u8,
    log2_old_align: u8,
    ra: usize,
) void {
    _ = ra;
    _ = log2_old_align;
    _ = old_mem;
    _ = ctx;
}
