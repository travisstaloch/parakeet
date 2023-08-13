const std = @import("std");
const pk = @import("parakeet");
const peg = pk.peg;
const Peg = @import("peg-parsers.zig");

fn nextArg(args: *[]const [:0]const u8) ?[:0]const u8 {
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
    const stdout = std.io.getStdOut().writer();

    const grammar_opt = pk.build_options.grammar;
    if (grammar_opt.len != 0) {
        const pg = if (comptime std.mem.eql(u8, grammar_opt, "peg"))
            @import("gen/peg.peg.zig")
        else if (comptime std.mem.eql(u8, grammar_opt, "zig"))
            @import("gen/zig-grammar.y.zig")
        else if (comptime std.mem.eql(u8, grammar_opt, "c"))
            @import("gen/c.peg.zig")
        else if (comptime std.mem.eql(u8, grammar_opt, "json"))
            @import("gen/json.peg.zig")
        else if (comptime std.mem.eql(u8, grammar_opt, "json_memo"))
            @import("gen/json_memo.peg.zig")
        else
            unreachable;
        const opts = .{ .eval_branch_quota = 8000 };
        const G = pg.Grammar(pk, opts);
        const start = nextArg(&args) orelse
            usage("missing argument: <start>", .{});
        const start_id = std.meta.stringToEnum(G.NonTerminal, start) orelse
            usage("invalid start rule name '{s}'", .{start});
        var files = std.ArrayList([2][:0]const u8).init(alloc);
        while (nextArg(&args)) |arg| {
            const file = std.fs.cwd().openFile(arg, .{}) catch |e| switch (e) {
                error.FileNotFound => continue,
                else => return e,
            };
            const input: [:0]const u8 = try file.readToEndAllocOptions(alloc, std.math.maxInt(u32), null, 1, 0);
            defer file.close();
            try files.append(.{ arg, input });
        }
        var errcount: usize = 0;
        var bytes_processed: usize = 0;
        var timer = try std.time.Timer.start();
        for (files.items) |file| {
            // std.debug.print("path={s}\n", .{file[0]});
            const r = peg.Pattern.parse(
                G,
                @intFromEnum(start_id),
                file[1],
                .{ .allocator = alloc },
                .optimized,
            );
            if (r.output == .err) {
                try stdout.print("parse {s} {s} input={}\n", .{ @tagName(r.output), file[0], r.input });
                errcount += 1;
            }
            bytes_processed += r.input.index;
        }
        const ns = timer.read();
        const dashes = "-" ** 40;
        std.debug.print("{s}\n", .{dashes});
        std.debug.print("PARSE SUMMARY\n", .{});
        std.debug.print("{s}\n", .{dashes});
        const successes = files.items.len - errcount;
        const fmt1 = "{s: <12}";
        std.debug.print(fmt1 ++ " {d: >9.1}% - {}/{}/{} ok/total/err\n", .{
            "files parsed",
            @as(f64, @floatFromInt(successes)) / @as(f64, @floatFromInt(files.items.len)) * 100,
            successes,
            files.items.len,
            errcount,
        });
        std.debug.print(fmt1 ++ " {d: >10.3} - {} bytes\n", .{ "size", std.fmt.fmtIntSizeBin(bytes_processed), bytes_processed });
        std.debug.print(fmt1 ++ " {: >10}\n", .{ "time", std.fmt.fmtDuration(ns) });
        const gb = (@as(f64, @floatFromInt(bytes_processed)) / (1024 * 1024 * 1024));
        const mb = (@as(f64, @floatFromInt(bytes_processed)) / (1024 * 1024));
        const seconds = @as(f64, @floatFromInt(ns)) / std.time.ns_per_s;
        std.debug.print(fmt1 ++ "{d: >2.3} GiB/s - {d:.3} MiB/s\n", .{ "speed", gb / seconds, mb / seconds });
        std.debug.print("{s}\n", .{dashes});
        if (errcount > 0) std.os.exit(1);
    } else {
        const filename = nextArg(&args) orelse
            usage("missing argument: <file>", .{});
        const file = try std.fs.cwd().openFile(filename, .{});
        defer file.close();
        const input = try file.readToEndAlloc(alloc, std.math.maxInt(u32));
        const g = try peg.parseString(Peg.grammar, input, alloc);
        try stdout.print("{}\n", .{g.fmtGen()});
    }
}
