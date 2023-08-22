const std = @import("std");
const pk = @import("parakeet");

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

    const peg_path = nextArg(&args) orelse
        usage("missing argument: <peg_path>", .{});
    const pegfile = try std.fs.cwd().openFile(peg_path, .{});
    defer pegfile.close();
    const peg_content = try pegfile.readToEndAlloc(alloc, std.math.maxInt(u32));

    var files = std.ArrayList([2][:0]const u8).init(alloc);
    while (nextArg(&args)) |arg| {
        const file = std.fs.cwd().openFile(arg, .{}) catch |e| switch (e) {
            error.FileNotFound => continue,
            else => return e,
        };
        const input: [:0]const u8 =
            try file.readToEndAllocOptions(alloc, std.math.maxInt(u32), null, 1, 0);
        defer file.close();
        try files.append(.{ arg, input });
    }
    var errcount: usize = 0;
    var bytes_processed: f64 = 0;
    const Ctx = pk.pattern.ParseContext(void);
    var timer = try std.time.Timer.start();

    const g = try pk.peg.parseString(pk.peg.parsers.grammar, peg_content, alloc);
    var ctx = try Ctx.init(.{ .allocator = alloc }, g);
    try stdout.print("parsed grammar with {} rules\n", .{g.grammar.len});
    for (files.items) |file| {
        // std.debug.print("path={s}\n", .{file[0]});
        const r = pk.pattern.parse(
            Ctx,
            &ctx,
            // TODO bring back start_id
            0,
            file[1],
        );
        if (r.output == .err) {
            try stdout.print(
                "parse {s} {s} input={}\n",
                .{ @tagName(r.output), file[0], r.input },
            );
            errcount += 1;
        }
        bytes_processed += @floatFromInt(r.input.index);
    }
    const ns = timer.read();
    var lines: f64 = 0;
    for (files.items) |file| {
        for (file[1]) |c| {
            if (c == '\n') lines += 1;
        }
    }
    const dashes = "-" ** 40;
    std.debug.print("{s}\n", .{dashes});
    std.debug.print("PARSE SUMMARY\n", .{});
    std.debug.print("{s}\n", .{dashes});
    const successes = files.items.len - errcount;
    const fmt1 = "{s: <12}";
    std.debug.print(fmt1 ++ " {d: >9.1}% - {}/{}/{} ok/total/err\n", .{
        "files parsed",
        @as(f64, @floatFromInt(successes)) /
            @as(f64, @floatFromInt(files.items.len)) * 100,
        successes,
        files.items.len,
        errcount,
    });
    std.debug.print(fmt1 ++ " {d: >10.3} - {d:.3}K lines\n", .{
        "size",
        std.fmt.fmtIntSizeBin(@intFromFloat(bytes_processed)),
        lines / 1024,
    });
    std.debug.print(fmt1 ++ " {: >10}\n", .{ "time", std.fmt.fmtDuration(ns) });
    const gb = (bytes_processed / (1024 * 1024 * 1024));
    const mb = (bytes_processed / (1024 * 1024));
    const seconds = @as(f64, @floatFromInt(ns)) / std.time.ns_per_s;
    std.debug.print(fmt1 ++ "{d: >2.3} GiB/s - {d:.3} MiB/s - {d:.3}K lines/s\n", .{
        "speed",
        gb / seconds,
        mb / seconds,
        lines / 1024 / seconds,
    });
    std.debug.print("{s}\n", .{dashes});
    if (errcount > 0) std.os.exit(1);
}
