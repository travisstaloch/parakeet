const std = @import("std");
const pk = @import("parakeet");
const ps = pk.parsers;

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    std.debug.print("TODO - add example parser code\n", .{});
}
