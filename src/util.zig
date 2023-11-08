const std = @import("std");
const mem = std.mem;

pub fn startsWith(haystk: []const u8, needle: []const u8) bool {
    return (needle.len <= haystk.len and eql(haystk[0..needle.len], needle));
}

pub fn eqlNaive(a: []const u8, b: []const u8) bool {
    std.debug.assert(a.len == b.len);
    for (a, b) |a_elem, b_elem| {
        if (a_elem != b_elem) return false;
    }
    return true;
}

pub fn eql(a: []const u8, b: []const u8) bool {
    std.debug.assert(a.len == b.len);
    const U = usize;
    const size = @sizeOf(U);
    const len: u32 = @truncate(a.len);
    var index: u32 = 0;
    while (true) : (index += size) {
        if (index + size >= len) break;
        const ai = mem.readInt(U, a.ptr[index..][0..size], .little);
        const bi = mem.readInt(U, b.ptr[index..][0..size], .little);
        if (ai != bi) return false;
    }
    return eqlNaive(a.ptr[index..len], b.ptr[index..len]);
}
