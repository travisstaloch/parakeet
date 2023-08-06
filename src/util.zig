const std = @import("std");
const mem = std.mem;

pub fn startsWith(comptime T: type, haystk: []const T, needle: []const T) bool {
    return (needle.len <= haystk.len and eql(T, haystk[0..needle.len], needle));
}

pub const eql = if (@import("build_options").eql_naive) eqlNaive else eqlFast;

pub fn eqlNaive(comptime T: type, a: []const T, b: []const T) bool {
    for (a, b) |a_elem, b_elem| {
        if (a_elem != b_elem) return false;
    }
    return true;
}

pub fn eqlFast(comptime T: type, a: []const T, b: []const T) bool {
    std.debug.assert(a.len == b.len);
    const U = usize;
    const size = @sizeOf(U);
    const len = a.len;
    var index: usize = 0;
    while (true) : (index += size) {
        if (index + size >= len) break;
        const ai = mem.readIntNative(U, a.ptr[index..][0..size]);
        const bi = mem.readIntNative(U, b.ptr[index..][0..size]);
        if (ai != bi) return false;
    }
    return eqlNaive(T, a.ptr[index..len], b.ptr[index..len]);
}
