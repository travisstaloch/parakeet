const std = @import("std");
const mem = std.mem;
const pk = @import("lib.zig");
const Expr = pk.peg.Expr;

pub const Result = struct {
    input: pk.Input,
    output: Output,

    const Output = union(enum) {
        err: pk.ParseError,
        // TODO perhaps change ok back to []const u8 now that run()
        // 'returns' by out pointer
        /// start and end indices for input.s
        ok: [2]u32,
    };

    pub fn err(i: pk.Input) Result {
        return .{ .input = i, .output = .{ .err = error.ParseFailure } };
    }
    pub fn errWith(i: pk.Input, e: pk.ParseError) Result {
        return .{ .input = i, .output = .{ .err = e } };
    }
    pub fn ok(i: pk.Input, s: [2]u32) Result {
        return .{ .input = i, .output = .{ .ok = s } };
    }
};

pub const MemoTable = std.AutoHashMapUnmanaged([2]u32, Result);

pub fn ParseContext(comptime G: type) type {
    return struct {
        in: pk.Input,
        id: u32,
        allocator: mem.Allocator,
        rules: [*]const Rule(G.NonTerminal, PatternMut),
        memo: MemoTable = .{},
        // TODO make void in non-debug builds, eventually remove.
        nonterm_visit_counts: ?*anyopaque = null,

        /// only initializes 'rules' field. 'in' and 'id' fields will be
        /// initialized in Pattern.parse
        pub fn init(
            arena: mem.Allocator,
            mode: Pattern.OptimizeMode,
        ) !@This() {
            const rules = try Pattern.optimize(G, arena, mode);
            return .{
                .allocator = arena,
                .rules = rules.ptr,
                .in = undefined,
                .id = undefined,
            };
        }
    };
}

pub const Literal = struct { ptr: [*]const u8, len: u32 };

/// a data format similar to Expr for encoding parsers
pub const Pattern = union(enum) {
    literal: Literal,
    class: *const Expr.Class,
    alt: []const Pattern,
    seq: []const Pattern,
    many: *const Pattern,
    plus: *const Pattern,
    opt: *const Pattern,
    not: *const Pattern,
    amp: *const Pattern,
    group: *const Pattern,
    memo: Memo,
    nonterm: u32,
    dot,
    eos,
    empty,

    comptime {
        std.debug.assert(24 == @sizeOf(Pattern));
    }
    pub const Tag = std.meta.Tag(Pattern);
    pub const Memo = struct { pat: *const Pattern, id: u32 };

    pub fn format(
        p: Pattern,
        comptime fmt: []const u8,
        opts: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        return formatImpl(Pattern, @TypeOf(writer).Error, p, fmt, opts, writer);
    }

    pub fn literal(payload: []const u8) Pattern {
        return .{ .literal = .{
            .ptr = payload.ptr,
            .len = @intCast(payload.len),
        } };
    }
    pub fn class(payload: *const Expr.Class) Pattern {
        return .{ .class = payload };
    }
    pub fn alt(payload: []const Pattern) Pattern {
        return .{ .alt = payload };
    }
    pub fn seq(payload: []const Pattern) Pattern {
        return .{ .seq = payload };
    }
    pub fn many(payload: *const Pattern) Pattern {
        return .{ .many = payload };
    }
    pub fn plus(payload: *const Pattern) Pattern {
        return .{ .plus = payload };
    }
    pub fn opt(payload: *const Pattern) Pattern {
        return .{ .opt = payload };
    }
    pub fn not(payload: *const Pattern) Pattern {
        return switch (payload.*) {
            .dot => .eos,
            else => .{ .not = payload },
        };
    }
    pub fn amp(payload: *const Pattern) Pattern {
        return .{ .amp = payload };
    }
    pub fn group(payload: *const Pattern) Pattern {
        return .{ .group = payload };
    }
    pub fn nonterm(payload: u32) Pattern {
        return .{ .nonterm = payload };
    }
    pub fn dot() Pattern {
        return .dot;
    }
    pub fn empty() Pattern {
        return .empty;
    }
    pub fn memo(payload: *const Pattern, id: u32) Pattern {
        return .{ .memo = .{ .pat = payload, .id = id } };
    }

    pub fn parse(
        comptime G: type,
        ctx: *ParseContext(G),
        start_rule_id: u32,
        input: []const u8,
    ) Result {
        ctx.in = pk.input(input);
        ctx.id = start_rule_id;

        const Counts = std.enums.EnumArray(G.NonTerminal, usize);
        var nonterm_visit_counts = Counts.initDefault(0, .{});
        if (show_nonterm_visit_counts) ctx.nonterm_visit_counts = &nonterm_visit_counts;
        var result: Result = undefined;
        ctx.rules[ctx.id][1].run(G, ctx, &result);
        if (show_nonterm_visit_counts) {
            std.sort.insertion(usize, &nonterm_visit_counts.values, {}, std.sort.desc(usize));
            for (std.meta.tags(G.NonTerminal)) |tag| {
                std.debug.print("{s}={}\n", .{ @tagName(tag), nonterm_visit_counts.get(tag) });
            }
        }
        return result;
    }

    /// if all choices are charsets or single chars, return a class of the union
    fn combineAlt(pats: []const Pattern) ?Expr.Class.Set {
        for (pats) |pat| {
            if (!(pat == .class or
                (pat == .literal and pat.literal.len == 1)))
                return null;
        }
        var bitset = Expr.Class.Set.initEmpty();
        for (pats) |pat| {
            switch (pat) {
                .class => |other| bitset.setUnion(other.bitset),
                .literal => |lit| {
                    std.debug.assert(lit.len == 1);
                    bitset.set(lit.ptr[0]);
                },
                else => unreachable,
            }
        }
        return bitset;
    }

    fn lastOfSeq(pat: PatternMut) ?PatternMut {
        if (pat != .seq) return null;
        std.debug.assert(pat.seq.len > 1);
        return pat.seq[pat.seq.len - 1];
    }

    pub fn eql(p: PatternMut, other: PatternMut) bool {
        return @as(PatternMut.Tag, p) == @as(PatternMut.Tag, other) and switch (p) {
            .literal => |lit| pk.util.eql(lit.ptr[0..lit.len], other.literal.ptr[0..other.literal.len]),
            .class => |klass| klass.bitset.eql(other.class.bitset),
            .alt => |pats| pats.len == other.alt.len and for (pats, 0..) |subp, i| {
                if (!eql(subp, other.alt[i])) break false;
            } else true,
            .seq => |pats| pats.len == other.seq.len and for (pats, 0..) |subp, i| {
                if (!eql(subp, other.seq[i])) break false;
            } else true,
            inline .many,
            .plus,
            .opt,
            .not,
            .amp,
            .group,
            => |ip, tag| eql(ip.*, @field(other, @tagName(tag)).*),
            .memo => |m| m.id == other.memo.id and eql(m.pat.*, other.memo.pat.*),
            .nonterm => |id| id == other.nonterm,
            .dot,
            .eos,
            .empty,
            => true,
        };
    }

    /// when all arms of an alt end with the same pattern, it may be hoisted
    /// out.  this results in less duplicated parsing work.
    /// a z / b z => (a / b) z
    fn reduceAlt(pats: []PatternMut, arena: mem.Allocator) !?PatternMut {
        std.debug.assert(pats.len > 1);
        const z = lastOfSeq(pats[0]) orelse return null;
        for (pats[1..]) |p| {
            const z2 = lastOfSeq(p) orelse return null;
            if (!eql(z, z2)) return null;
        }
        // reduce by removing last pattern from all seqs
        for (0..pats.len) |i| {
            // TODO other optimizations for single item?
            // a c / b c / c => (a / b)? c
            const tmp = pats[i].seq;
            pats[i] = if (tmp.len == 2)
                tmp[0]
            else
                .{ .seq = tmp[0 .. tmp.len - 1] };
        }

        const newalt = try arena.create(PatternMut);
        newalt.* = .{ .alt = pats };
        const newseq = try arena.alloc(PatternMut, 2);
        newseq[0] = .{ .group = newalt };
        newseq[1] = z;

        return .{ .seq = newseq };
    }

    /// combine sequences of literals into a single literal
    fn combineSeq(pats: []const Pattern, arena: mem.Allocator) !?PatternMut {
        const ok = for (pats) |pat| {
            if (!(pat == .literal or pat == .empty)) break false;
        } else true;
        if (!ok) return null;

        var s = std.ArrayList(u8).init(arena);
        defer s.deinit();
        for (pats) |pat| {
            if (pat != .empty) try s.appendSlice(pat.literal.ptr[0..pat.literal.len]);
        }
        const r = try s.toOwnedSlice();
        return .{ .literal = .{ .ptr = r.ptr, .len = @intCast(r.len) } };
    }

    fn optimizeImpl(
        comptime G: type,
        pat: Pattern,
        depth: u8,
        arena: mem.Allocator,
        mode: OptimizeMode,
    ) !PatternMut {
        return switch (pat) {
            .alt => |pats| {
                if (mode == .optimized) {
                    if (combineAlt(pats)) |bitset| {
                        const klass = try arena.create(Expr.Class);
                        klass.* = .{ .bitset = bitset };
                        return .{ .class = klass };
                    }
                }
                const r = try arena.alloc(PatternMut, pats.len);
                for (0..pats.len) |i|
                    r[i] = try optimizeImpl(G, pats[i], depth + 1, arena, mode);

                if (mode == .optimized) {
                    return if (try reduceAlt(r, arena)) |reduced|
                        reduced
                    else
                        .{ .alt = r };
                } else return .{ .alt = r };
            },
            .seq => |pats| {
                if (mode == .optimized)
                    if (try combineSeq(pats, arena)) |r| return r;
                const r = try arena.alloc(PatternMut, pats.len);
                for (0..pats.len) |i|
                    r[i] = try optimizeImpl(G, pats[i], depth + 1, arena, mode);
                return .{ .seq = r };
            },
            inline .not, .amp, .opt, .many, .plus, .group => |p, tag| {
                const r = try arena.create(PatternMut);
                r.* = try optimizeImpl(G, p.*, depth, arena, mode);
                return @unionInit(PatternMut, @tagName(tag), r);
            },
            inline .literal, .class => |p, tag| return @unionInit(PatternMut, @tagName(tag), p),
            .nonterm => |id| return if (depth < 2)
                try optimizeImpl(G, G.rules[id][1], depth + 1, arena, mode)
            else
                .{ .nonterm = id },
            .dot => return .dot,
            .empty => return .empty,
            .eos => return .eos,
            .memo => |m| return .{ .memo = .{
                .pat = blk: {
                    const r = try arena.create(PatternMut);
                    r.* = try optimizeImpl(G, m.pat.*, depth, arena, mode);
                    break :blk r;
                },
                .id = m.id,
            } },
        };
    }

    pub const OptimizeMode = enum { optimized, unoptimized };

    /// convert the rules from the grammar G to an optimized, mutable format on
    /// the heap for better performance.
    pub fn optimize(
        comptime G: type,
        arena: mem.Allocator,
        mode: OptimizeMode,
    ) ![]const Rule(G.NonTerminal, PatternMut) {
        const rules = try arena.alloc(Rule(G.NonTerminal, PatternMut), G.rules.len);
        for (0..G.rules.len) |i| {
            rules[i][0] = G.rules[i][0];
            // std.debug.print("rule={s}\n", .{@tagName(rule[0])});
            rules[i][1] = try optimizeImpl(G, G.rules[i][1], 0, arena, mode);
        }
        return rules;
    }
};

const show_nonterm_visit_counts = false;

pub fn Rule(comptime NonTerminal: type, comptime Pat: type) type {
    return struct { NonTerminal, Pat };
}

/// a data format similar to Expr for running parsers
pub const PatternMut = union(enum) {
    literal: Literal,
    class: *const Expr.Class,
    alt: []PatternMut,
    seq: []PatternMut,
    many: *PatternMut,
    plus: *PatternMut,
    opt: *PatternMut,
    not: *PatternMut,
    amp: *PatternMut,
    group: *PatternMut,
    memo: Memo,
    nonterm: u32,
    dot,
    eos,
    empty,

    comptime {
        std.debug.assert(24 == @sizeOf(PatternMut));
    }
    pub const Tag = std.meta.Tag(PatternMut);
    pub const Memo = struct { pat: *PatternMut, id: u32 };

    pub fn format(
        p: PatternMut,
        comptime fmt: []const u8,
        opts: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        return formatImpl(PatternMut, @TypeOf(writer).Error, p, fmt, opts, writer);
    }

    // run() is recursive so it is optimized to reduce fn call overhead by
    // passing 'ctx' and 'res' as pointers. because of this, they are often
    //  reused below and some control flow may be sligntly non-intuitive.
    pub fn run(
        pat: PatternMut,
        comptime G: type,
        ctx: *ParseContext(G),
        res: *Result,
    ) void {
        const in = ctx.in;
        const debugthis = false;
        if (debugthis) {
            std.debug.print("{}", .{in});
            if (pat != .nonterm) std.debug.print("{}\n", .{pat});
        }
        switch (pat) {
            .nonterm => |id| {
                if (show_nonterm_visit_counts) {
                    const Counts = std.enums.EnumArray(G.NonTerminal, usize);
                    var nonterm_visit_counts = @as(?*Counts, @ptrCast(@alignCast(ctx.nonterm_visit_counts))) orelse
                        unreachable;
                    var timer = std.time.Timer.start() catch unreachable;
                    const prev_id = ctx.id;
                    defer ctx.id = prev_id;
                    ctx.id = id;
                    const p = ctx.rules[id][1];
                    if (debugthis)
                        std.debug.print("{s} {s}\n", .{ @tagName(ctx.rules[id][0]), @tagName(p) });
                    defer {
                        const ns = timer.read();
                        nonterm_visit_counts.getPtr(@as(G.NonTerminal, @enumFromInt(id))).* += ns;
                    }
                    p.run(G, ctx, res);
                } else {
                    const prev_id = ctx.id;
                    defer ctx.id = prev_id;
                    ctx.id = id;
                    const p = ctx.rules[id][1];
                    if (debugthis)
                        std.debug.print("{s} {s}\n", .{ @tagName(ctx.rules[id][0]), @tagName(p) });
                    @call(.always_tail, run, .{ p, G, ctx, res });
                }
            },
            .literal => |lit| {
                res.* = if (in.startsWith(lit.ptr[0..lit.len]))
                    Result.ok(in.advanceBy(lit.len), in.range(lit.len))
                else
                    Result.err(in);
            },
            .class => |klass| {
                const ic = in.get(0) orelse {
                    res.* = Result.err(in);
                    return;
                };
                res.* = if (klass.bitset.isSet(ic))
                    Result.ok(in.advanceBy(1), in.range(1))
                else
                    Result.err(in);
            },
            .dot => res.* = if (in.hasCount(1))
                Result.ok(in.advanceBy(1), in.range(1))
            else
                Result.err(in),
            .empty => res.* = Result.ok(in, in.range(0)),
            .seq => |pats| {
                for (pats) |p| {
                    p.run(G, ctx, res);
                    if (res.output == .err) return;
                    ctx.in.index = res.input.index;
                }
                res.* = Result.ok(ctx.in, in.rangeTo(ctx.in.index));
            },
            .alt => |pats| {
                for (pats) |*p| {
                    ctx.in.index = in.index;
                    p.run(G, ctx, res);
                    if (res.output == .ok) return;
                }
                res.* = Result.err(in);
            },
            .many => |p| {
                while (true) {
                    p.run(G, ctx, res);
                    ctx.in.index = res.input.index;
                    if (res.output == .err) break;
                }
                res.* = Result.ok(ctx.in, in.rangeTo(ctx.in.index));
            },
            .plus => |p| {
                p.run(G, ctx, res);
                ctx.in.index = res.input.index;
                if (res.output == .err) return;
                while (true) {
                    p.run(G, ctx, res);
                    ctx.in.index = res.input.index;
                    if (res.output == .err) break;
                }
                res.* = Result.ok(ctx.in, in.rangeTo(ctx.in.index));
            },
            .group => |p| p.run(G, ctx, res),
            .not => |p| {
                p.run(G, ctx, res);
                ctx.in.index = in.index;
                res.* = if (res.output == .ok)
                    Result.err(in)
                else
                    Result.ok(in, in.rangeTo(res.input.index));
            },
            .amp => |p| {
                p.run(G, ctx, res);
                ctx.in.index = in.index;
                res.* = .{ .input = in, .output = res.output };
            },
            .eos => res.* = if (in.eos())
                Result.ok(in, in.restRange())
            else
                Result.err(in),
            .opt => |p| {
                p.run(G, ctx, res);
                if (res.output == .ok) return;
                ctx.in.index = in.index;
                res.* = Result.ok(in, in.range(0));
            },
            .memo => |m| {
                const gop = ctx.memo.getOrPut(
                    ctx.allocator,
                    .{ m.id, in.index },
                ) catch |e| {
                    res.* = Result.errWith(in, e);
                    return;
                };
                // if (gop.found_existing)
                //     std.debug.print("found existing memo entry\n", .{});
                if (gop.found_existing) {
                    res.* = gop.value_ptr.*;
                    return;
                }
                m.pat.run(G, ctx, res);
                gop.value_ptr.* = res.*;
            },
        }
    }
};

fn formatImpl(
    comptime Pat: type,
    comptime E: type,
    pat: Pat,
    comptime fmt: []const u8,
    opts: std.fmt.FormatOptions,
    writer: anytype,
) E!void {
    // try writer.print("{s}: ", .{@tagName(pat)});
    switch (pat) {
        .literal => |lit| {
            try writer.writeByte('"');
            try Expr.unescape(.{ .litD = lit.ptr[0..lit.len] }, writer);
            try writer.writeByte('"');
        },
        .nonterm => |id| _ = try writer.print("{}", .{id}),
        .class => |klass| try writer.print("{}", .{klass}),
        .alt => |pats| for (pats, 0..) |p, i| {
            if (i != 0) _ = try writer.write(" / ");
            try p.format(fmt, opts, writer);
        },
        .seq => |pats| for (pats, 0..) |p, i| {
            if (i != 0) _ = try writer.write(" ");
            try p.format(fmt, opts, writer);
        },
        .many,
        .plus,
        .opt,
        => |ip| try ip.format(fmt, opts, writer),
        .group => |ip| {
            _ = try writer.write("( ");
            try ip.format(fmt, opts, writer);
            _ = try writer.write(" )");
        },
        .memo => |m| {
            _ = try writer.write("{{ ");
            try m.pat.format(fmt, opts, writer);
            _ = try writer.write(" }}");
        },
        .eos, .empty => {},
        .not => |ip| {
            _ = try writer.writeByte('!');
            try ip.format(fmt, opts, writer);
        },
        .amp => |ip| {
            _ = try writer.writeByte('&');
            try ip.format(fmt, opts, writer);
        },
        .dot => _ = try writer.writeByte('.'),
    }
}