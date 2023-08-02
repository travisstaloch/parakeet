const std = @import("std");
const pk = @import("parakeet");
const peg = pk.peg;
const Peg = peg.Peg;

fn nextArg(args: *[]const []const u8) ?[]const u8 {
    if (args.len == 0) return null;
    defer args.* = args.*[1..];
    return args.*[0];
}

fn usage(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print(fmt ++ "\n", args);
    std.os.exit(1);
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const alloc = arena.allocator();
    var args = try std.process.argsAlloc(alloc);
    args = args[1..];
    const filename = nextArg(&args) orelse
        usage("missing argument: <file>", .{});
    const file = try std.fs.cwd().openFile(filename, .{});
    defer file.close();
    const input = try file.readToEndAlloc(alloc, std.math.maxInt(u32));
    const g = try peg.parseString(Peg.grammar, input, alloc);
    const stdout = std.io.getStdOut().writer();
    try stdout.print("{}\n", .{g});
}
