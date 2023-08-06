const std = @import("std");
const pk = @import("parakeet");
const peg = pk.peg;
const Peg = @import("peg-parsers.zig");

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
    const stdout = std.io.getStdOut().writer();

    const bg = pk.build_options.grammar;
    if (bg.len != 0) {
        const pg = if (comptime std.mem.eql(u8, bg, "peg"))
            @import("gen/peg.peg.zig")
        else if (comptime std.mem.eql(u8, bg, "zig"))
            @import("gen/zig-grammar.y.zig")
        else
            unreachable;
        const opts = .{ .eval_branch_quota = 2000 };
        const G = pg.Grammar(pk, opts);
        const start = nextArg(&args) orelse
            usage("missing argument: <start>", .{});
        const start_id = std.meta.stringToEnum(G.RuleType, start) orelse
            usage("invalid start rule name '{s}'", .{start});
        const r = peg.Pattern.parse(
            G.Rule,
            &G.rules,
            @intFromEnum(start_id),
            input,
            .{ .allocator = alloc },
        );
        try stdout.print("parse {s} input={}\n", .{ @tagName(r.output), r.input });
        if (r.output == .err) std.os.exit(1);
    } else {
        const g = try peg.parseString(Peg.grammar, input, alloc);
        try stdout.print("{}\n", .{g.fmtGen()});
    }
}
