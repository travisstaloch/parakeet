const std = @import("std");
const mem = std.mem;
const pk = @import("lib.zig");
const ps = pk.parsers;

pub const Charset = union(enum) {
    range: [2]u8,
    one: u8,

    pub fn one(c: u8) Charset {
        return .{ .one = c };
    }
    pub fn range(a: u8, b: u8) Charset {
        return .{ .range = .{ a, b } };
    }

    pub fn format(
        cset: Charset,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        switch (cset) {
            .one => |c| try Expr.unescapeByte(c, writer, .class),
            .range => |ab| {
                try Expr.unescapeByte(ab[0], writer, .class);
                try writer.writeByte('-');
                try Expr.unescapeByte(ab[1], writer, .class);
            },
        }
    }
};

pub const Expr = union(enum) {
    ident: []const u8,
    /// single quoted literal
    litS: []const u8,
    /// double quoted literal
    litD: []const u8,
    class: Class,
    dot,
    /// positive lookahead
    amp: *const Expr,
    /// negative lookahead
    not: *const Expr,
    opt: *const Expr,
    star: *const Expr,
    plus: *const Expr,
    group: *const Expr,
    memo: Memo,
    alt: []const Expr,
    seq: []const Expr,
    grammar: []const Def,
    empty,

    pub const Def = struct { []const u8, Expr };
    pub const Tag = std.meta.Tag(Expr);
    pub const Class = struct {
        /// if more than 1/2 of the 256 bits are set the Class is
        /// implicitly 'negated'. this removes the need for a 'negated' bool field
        /// and shrinks the size of this struct from 40 to 32.
        bitset: Set,

        pub const Set = std.StaticBitSet(256);

        pub fn format(
            c: Class,
            comptime _: []const u8,
            _: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            try writer.writeByte('[');
            try Expr.unescape(.{ .class = c }, writer);
            try writer.writeByte(']');
        }

        comptime {
            std.debug.assert(@sizeOf(Class) == 32);
        }

        pub fn init(cs: []const Charset) Class {
            const negated = cs.len > 0 and cs[0] == .one and cs[0].one == '^';
            var bitset = Class.Set.initEmpty();
            for (cs[@intFromBool(negated)..]) |cset| {
                switch (cset) {
                    .one => |c| bitset.set(c),
                    .range => |ab| for (ab[0]..ab[1] + 1) |c| bitset.set(c),
                }
            }
            return .{ .bitset = if (negated) bitset.complement() else bitset };
        }
    };
    pub const Memo = struct { expr: *const Expr, id: u32 };

    pub fn deinit(e: Expr, allocator: mem.Allocator) void {
        switch (e) {
            .alt, .seq => |es| {
                for (es) |*ie| ie.deinit(allocator);
                allocator.free(es);
            },
            .not, .amp, .opt, .star, .plus, .group => |ie| {
                ie.deinit(allocator);
                allocator.destroy(ie);
            },
            .grammar => |ds| {
                for (ds) |d| d[1].deinit(allocator);
                allocator.free(ds);
            },
            .litD, .litS => |s| allocator.free(s),
            .ident, .dot, .empty, .class => {},
            .memo => |m| {
                m.expr.deinit(allocator);
                allocator.destroy(m.expr);
            },
        }
    }

    pub fn dot(_: u8) Expr {
        return .dot;
    }
    pub fn initFn(comptime tag: Tag) fn (anytype) Expr {
        return struct {
            fn func(x: anytype) Expr {
                return @unionInit(Expr, @tagName(tag), x);
            }
        }.func;
    }
    pub const PlusRes = struct { Expr, []const Expr };
    pub fn initPlusRes(e: Expr, es: []const Expr) PlusRes {
        return .{ e, es };
    }

    const FnAlloc = fn (PlusRes, ?mem.Allocator) pk.ParseError!Expr;
    pub fn initFnAlloc(comptime tag: Tag) FnAlloc {
        return struct {
            fn func(
                plus_res: PlusRes,
                mallocator: ?mem.Allocator,
            ) pk.ParseError!Expr {
                const e = plus_res[0];
                const es = plus_res[1];
                // std.debug.print("initFnAlloc({s}) e={} es={any}\n", .{ @tagName(tag), e, es });
                if (es.len == 0)
                    return e;

                const allocator = mallocator orelse
                    return error.AllocatorRequired;
                const res = try allocator.alloc(Expr, es.len + 1);
                res[0] = e;
                @memcpy(res[1..], es);
                allocator.free(es);
                return @unionInit(Expr, @tagName(tag), res);
            }
        }.func;
    }

    pub fn class(bitset: Expr.Class.Set) Expr {
        return .{ .class = .{ .bitset = bitset } };
    }
    var memoid: u32 = 0;
    pub fn memo(e: Expr, mallocator: ?mem.Allocator) !Expr {
        defer memoid += 1;
        const allocator = mallocator orelse return error.AllocatorRequired;
        const o = try allocator.create(Expr);
        o.* = e;
        return .{ .memo = .{ .expr = o, .id = memoid } };
    }
    pub fn group(e: Expr, mallocator: ?mem.Allocator) !Expr {
        // if its a single node, just return it. only allow seq and alt nodes in group
        switch (e) {
            .seq, .alt => {},
            else => return e,
        }
        const allocator = mallocator orelse return error.AllocatorRequired;
        const o = try allocator.create(Expr);
        o.* = e;
        return .{ .group = o };
    }

    pub fn escape(c: u8) ?u8 {
        return switch (c) {
            'a' => '\x07',
            'b' => '\x08',
            'e' => '\x1b',
            'f' => '\x0c',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'v' => '\x0b',
            '\'' => '\'',
            '"' => '"',
            '[' => '[',
            ']' => ']',
            '\\' => '\\',
            '^' => '^',
            else => null,
        };
    }

    pub fn unescapeByte(c: u8, writer: anytype, tag: Tag) !void {
        switch (c) {
            '\x07' => _ = try writer.write("\\a"),
            '\x08' => _ = try writer.write("\\b"),
            '\x1b' => _ = try writer.write("\\e"),
            '\x0c' => _ = try writer.write("\\f"),
            '\n' => _ = try writer.write("\\n"),
            '\r' => _ = try writer.write("\\r"),
            '\t' => _ = try writer.write("\\t"),
            '\x0b' => _ = try writer.write("\\v"),
            '\'' => _ = try writer.write((if (tag == .litS) "\\\'" else "'")),
            '"' => _ = try writer.write((if (tag == .litD) "\\\"" else "\"")),
            '[' => _ = try writer.write((if (tag == .class) "\\[" else "[")),
            ']' => _ = try writer.write((if (tag == .class) "\\]" else "]")),
            '\\' => _ = try writer.write("\\\\"),
            '-' => _ = try writer.write((if (tag == .class) "\\-" else "-")),
            '^' => _ = try writer.write((if (tag == .class) "\\^" else "^")),
            // TODO not sure isPrint() is the correct way to decide if 'c' needs
            // octal escaping
            else => if (std.ascii.isPrint(c))
                try writer.writeByte(c)
            else {
                try writer.writeByte('\\');
                try std.fmt.formatInt(c, 8, .lower, .{}, writer);
            },
        }
    }

    const ClassIterState = union(enum) {
        first_iter,
        in_range: u8,
        other,
    };

    fn bitsetIterCountLeft(iter: Expr.Class.Set.Iterator(.{})) usize {
        var res = @popCount(iter.bits_remain);
        for (iter.words_remain) |word| res += @popCount(word);
        return res;
    }

    pub fn unescape(e: Expr, writer: anytype) !void {
        switch (e) {
            .litS, .litD => |s| for (s) |c| try unescapeByte(c, writer, e),
            .class => |klass| {
                // here we must infer the difference between a range like [a-z]
                // and lone characters like [az]
                const negated = klass.bitset.count() * 2 > Expr.Class.Set.bit_length;
                if (negated) try writer.writeByte('^');
                var iter = if (negated)
                    klass.bitset.complement().iterator(.{})
                else
                    klass.bitset.iterator(.{});
                var state: ClassIterState = .first_iter;
                var prev: u8 = undefined;
                while (iter.next()) |_c| {
                    const c: u8 = @truncate(_c);
                    // std.debug.print("state={s} c='{}' prev='{}' left={}\n", .{ @tagName(state), std.zig.fmtEscapes(&.{c}), std.zig.fmtEscapes(if (prev) |p| &.{p} else &.{}), @popCount(iter.bits_remain) });
                    if (bitsetIterCountLeft(iter) == 0)
                        // last iteration
                        switch (state) {
                            .first_iter => try unescapeByte(c, writer, e),
                            .in_range => {
                                if (prev + 1 != c) {
                                    try unescapeByte(state.in_range, writer, e);
                                    try writer.writeByte('-');
                                    try unescapeByte(prev, writer, e);
                                    try unescapeByte(c, writer, e);
                                } else {
                                    try unescapeByte(state.in_range, writer, e);
                                    try writer.writeByte('-');
                                    try unescapeByte(c, writer, e);
                                }
                            },
                            .other => {
                                try unescapeByte(prev, writer, e);
                                try unescapeByte(c, writer, e);
                            },
                        }
                    else switch (state) {
                        .first_iter => state = .other,
                        .in_range => {
                            if (prev + 1 != c) {
                                // end of range
                                try unescapeByte(state.in_range, writer, e);
                                try writer.writeByte('-');
                                try unescapeByte(prev, writer, e);
                                state = .other;
                            } else {
                                // stay in range
                            }
                        },
                        .other => {
                            if (prev + 1 == c)
                                state = ClassIterState{ .in_range = prev }
                            else
                                try unescapeByte(prev, writer, e);
                        },
                    }
                    prev = c;
                }
            },
            else => unreachable,
        }
    }

    pub fn format(
        e: Expr,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try e.formatImpl(writer, 0);
    }

    pub fn formatImpl(
        e: Expr,
        writer: anytype,
        depth: u8,
    ) !void {
        switch (e) {
            .ident => |s| _ = try writer.write(s),
            .litS => {
                try writer.writeByte('\'');
                try unescape(e, writer);
                try writer.writeByte('\'');
            },
            .litD => {
                try writer.writeByte('"');
                try unescape(e, writer);
                try writer.writeByte('"');
            },
            .class => |klass| try writer.print("{}", .{klass}),
            .dot => try writer.writeByte('.'),
            .seq => |es| for (es, 0..) |ie, i| {
                if (i != 0) try writer.writeByte(' ');
                try ie.formatImpl(writer, depth);
            },
            .alt => |es| for (es, 0..) |ie, i| {
                if (i != 0) _ = try writer.write(if (depth == 0)
                    "\n    / "
                else
                    " / ");
                try ie.formatImpl(writer, depth + 1);
            },
            .not => |ie| {
                try writer.writeByte('!');
                try ie.formatImpl(writer, depth);
            },
            .amp => |ie| {
                try writer.writeByte('&');
                try ie.formatImpl(writer, depth);
            },
            .opt => |ie| {
                try ie.formatImpl(writer, depth);
                try writer.writeByte('?');
            },
            .star => |ie| {
                try ie.formatImpl(writer, depth);
                try writer.writeByte('*');
            },
            .plus => |ie| {
                try ie.formatImpl(writer, depth);
                try writer.writeByte('+');
            },
            .group => |ie| {
                _ = try writer.write("( ");
                try ie.formatImpl(writer, depth + 1);
                _ = try writer.write(" )");
            },
            .memo => |m| {
                _ = try writer.write("{{ ");
                try m.expr.formatImpl(writer, depth + 1);
                _ = try writer.write(" }}");
            },
            .grammar => |ds| {
                for (ds, 0..) |d, i| {
                    if (i != 0) try writer.writeByte('\n');
                    _ = try writer.write(d[0]);
                    _ = try writer.write(if (d[1] == .alt)
                        " <-\n      "
                    else
                        " <- ");
                    try d[1].formatImpl(writer, depth);
                }
            },
            .empty => {},
        }
    }

    pub fn fmtGen(e: Expr) std.fmt.Formatter(formatGen) {
        return .{ .data = e };
    }

    pub fn formatGen(
        e: Expr,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try e.formatGenImpl(writer, 0);
    }

    pub fn formatGenImpl(
        e: Expr,
        writer: anytype,
        depth: u8,
    ) !void {
        if (depth > 0) _ = try writer.writeByte('&');
        switch (e) {
            .grammar => |rules| {
                _ = try writer.write(
                    \\pub fn Grammar(
                    \\    comptime pk: type,
                    \\    comptime options: struct { eval_branch_quota: usize = 1000 },
                    \\) type {
                    \\    return struct {
                    \\    pub const Rule = struct{NonTerminal, pk.peg.Pattern};
                    \\    pub const NonTerminal = enum {
                    \\
                );
                for (rules) |rule| {
                    try writer.writeByteNTimes(' ', 8);
                    _ = try writer.write(rule[0]);
                    _ = try writer.write(",\n");
                }
                _ = try writer.write(
                    \\    };
                    \\
                    \\    const pat = pk.peg.Pattern;
                    \\    const Class = pk.peg.Expr.Class;
                    \\    const n = @typeInfo(NonTerminal).Enum.fields.len;
                    \\    fn _rules() [n]Rule {
                    \\        @setEvalBranchQuota(options.eval_branch_quota);
                    \\        return [_]Rule{
                    \\
                );
                for (rules) |rule| {
                    try writer.writeByteNTimes(' ', 8);
                    try writer.print(".{{ .{s}, ", .{rule[0]});
                    try rule[1].formatGenImpl(writer, depth);
                    _ = try writer.write("},\n");
                }
                _ = try writer.write(
                    \\        };
                    \\    }
                    \\
                    \\    const rules_array = _rules();
                    \\    pub const rules: [*]const Rule = &rules_array;
                    \\    };
                    \\}
                );
            },
            .ident => |s| {
                try writer.print("pat.nonterm(@intFromEnum(NonTerminal.{s}))", .{s});
            },
            .litS, .litD => |s| {
                _ = try writer.write("pat.literal(\"");
                try writer.print("{}", .{std.zig.fmtEscapes(s)});
                _ = try writer.write("\")");
            },
            .class => |klass| {
                // here we must infer the difference between a range like [a-z]
                // and lone characters like [az]
                _ = try writer.write("pat.class(&Class.init(&.{");
                const negated = klass.bitset.count() * 2 > Expr.Class.Set.bit_length;
                if (negated) _ = try writer.write(".{.one = '^'},");
                var iter = if (negated)
                    klass.bitset.complement().iterator(.{})
                else
                    klass.bitset.iterator(.{});
                var state: ClassIterState = .first_iter;
                var prev: u8 = undefined;
                while (iter.next()) |_c| {
                    const c: u8 = @truncate(_c);
                    // std.debug.print("state={s} c='{}' prev='{}' left={}\n", .{ @tagName(state), std.zig.fmtEscapes(&.{c}), std.zig.fmtEscapes(if (prev) |p| &.{p} else &.{}), bitsetIterCountLeft(iter) });
                    if (bitsetIterCountLeft(iter) == 0) {
                        switch (state) {
                            .first_iter => {
                                try writer.print(".{{.one='{'}'}}, ", .{
                                    std.zig.fmtEscapes(&.{c}),
                                });
                            },
                            .in_range => {
                                if (prev + 1 != c) {
                                    try writer.print(".{{.range=.{{'{'}', '{'}'}}}}, ", .{
                                        std.zig.fmtEscapes(&.{state.in_range}),
                                        std.zig.fmtEscapes(&.{prev}),
                                    });
                                    try writer.print(".{{.one='{'}'}}, ", .{
                                        std.zig.fmtEscapes(&.{c}),
                                    });
                                } else {
                                    try writer.print(".{{.range=.{{'{'}', '{'}'}}}}, ", .{
                                        std.zig.fmtEscapes(&.{state.in_range}),
                                        std.zig.fmtEscapes(&.{c}),
                                    });
                                }
                            },
                            .other => {
                                try writer.print(".{{.one='{'}'}}, ", .{
                                    std.zig.fmtEscapes(&.{prev}),
                                });
                                try writer.print(".{{.one='{'}'}}, ", .{
                                    std.zig.fmtEscapes(&.{c}),
                                });
                            },
                        }
                    } else switch (state) {
                        .first_iter => state = .other,
                        .in_range => {
                            if (prev + 1 != c) {
                                // exit range
                                try writer.print(".{{.range=.{{'{'}', '{'}'}}}}, ", .{
                                    std.zig.fmtEscapes(&.{state.in_range}),
                                    std.zig.fmtEscapes(&.{prev}),
                                });
                                state = .other;
                            } else {
                                // stay in range
                            }
                        },
                        .other => {
                            if (prev + 1 == c)
                                state = ClassIterState{ .in_range = prev }
                            else
                                try writer.print(".{{.one='{'}'}}, ", .{
                                    std.zig.fmtEscapes(&.{prev}),
                                });
                        },
                    }
                    prev = c;
                }
                _ = try writer.write("}))");
            },
            .dot => _ = try writer.write("pat.dot()"),
            .empty => _ = try writer.write("pat.empty()"),
            .seq => |es| {
                _ = try writer.write("pat.seq(&.{");
                for (es) |ie| {
                    try ie.formatGenImpl(writer, 0);
                    _ = try writer.write(", ");
                }
                _ = try writer.write("})");
            },
            .alt => |es| {
                _ = try writer.write("pat.alt(&.{");
                for (es) |ie| {
                    try ie.formatGenImpl(writer, 0);
                    _ = try writer.write(", ");
                }
                _ = try writer.write("})");
            },
            .not => |ie| {
                _ = try writer.write("pat.not(");
                try ie.formatGenImpl(writer, depth + 1);
                _ = try writer.write(")");
            },
            .amp => |ie| {
                _ = try writer.write("pat.amp(");
                try ie.formatGenImpl(writer, depth + 1);
                _ = try writer.write(")");
            },
            .opt => |ie| {
                _ = try writer.write("pat.opt(");
                try ie.formatGenImpl(writer, depth + 1);
                _ = try writer.write(")");
            },
            .star => |ie| {
                _ = try writer.write("pat.many(");
                try ie.formatGenImpl(writer, depth + 1);
                _ = try writer.write(")");
            },
            .plus => |ie| {
                _ = try writer.write("pat.plus(");
                try ie.formatGenImpl(writer, depth + 1);
                _ = try writer.write(")");
            },
            .group => |ie| {
                _ = try writer.write("pat.group(");
                try ie.formatGenImpl(writer, depth + 1);
                _ = try writer.write(")");
            },
            .memo => |m| {
                _ = try writer.write("pat.memo(");
                try m.expr.formatGenImpl(writer, depth + 1);
                try writer.print(", {})", .{m.id});
            },
        }
    }
};

/// a data format similar to Expr for encoding parsers and running them
/// on input with Pattern.parse() and run().
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
    pub const Literal = struct { ptr: [*]const u8, len: u32 };
    pub const Tag = std.meta.Tag(Pattern);
    pub const Memo = struct { pat: *const Pattern, id: u32 };

    pub fn literal(comptime payload: []const u8) Pattern {
        return .{ .literal = .{
            .ptr = payload.ptr,
            .len = @intCast(payload.len),
        } };
    }
    pub fn class(payload: *const Expr.Class) Pattern {
        return .{ .class = payload };
    }
    pub fn alt(comptime payload: []const Pattern) Pattern {
        return if (comptime combineAlt(payload)) |bitset|
            .{ .class = &.{ .bitset = bitset } }
        else if (comptime reduceAlt(payload)) |pat|
            return pat
        else
            .{ .alt = payload };
    }
    pub fn seq(payload: []const Pattern) Pattern {
        return comptime if (combineSeq(payload)) |pat|
            pat
        else
            .{ .seq = payload };
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
    pub fn not(comptime payload: *const Pattern) Pattern {
        comptime {
            return switch (payload.*) {
                .dot => .eos,
                else => .{ .not = payload },
            };
        }
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
    fn lastOfSeq(pat: Pattern) ?Pattern {
        if (pat != .seq) return null;
        std.debug.assert(pat.seq.len > 1);
        return pat.seq[pat.seq.len - 1];
    }
    pub fn eql(p: Pattern, other: Pattern) bool {
        return @as(Tag, p) == @as(Tag, other) and switch (p) {
            .literal => |s| pk.util.eql(s, other.literal),
            .class => |klass| klass.bitset.eql(other.class.bitset),
            .alt => |pats| pats.len == other.alt.len and for (pats, 0..) |subp, i| {
                if (!subp.eql(other.alt[i])) break false;
            } else true,
            .seq => |pats| pats.len == other.seq.len and for (pats, 0..) |subp, i| {
                if (!subp.eql(other.seq[i])) break false;
            } else true,
            inline .many,
            .plus,
            .opt,
            .not,
            .amp,
            .group,
            => |ip, tag| ip.eql(@field(other, @tagName(tag)).*),
            .memo => |m| m.id == other.memo.id and m.pat.eql(other.memo.pat),
            .nonterm => |id| id == other.nonterm,
            .dot,
            .eos,
            .empty,
            => true,
        };
    }
    // TODO - add a pre-parsing step which optimizes patterns, preferably at
    // comptime. that step needs to happen before this
    /// when all arms of an alt end with the same pattern, it may be hoisted
    /// out.  this results in less duplicated work.
    /// a z / b z => (a / b) z
    fn reduceAlt(comptime pats: []const Pattern) ?Pattern {
        comptime {
            std.debug.assert(pats.len > 1);
            const z = lastOfSeq(pats[0]) orelse return null;
            for (pats[1..]) |p| {
                const z2 = lastOfSeq(p) orelse return null;
                if (!z.eql(z2)) return null;
            }
            // reduce removing z from all seqs
            var newpats: [pats.len]Pattern = undefined;
            for (pats, 0..) |p, i|
                // TODO other optimizations for single item?
                // a c / b c / c => (a / b)? c
                newpats[i] = if (p.seq.len == 2)
                    p.seq[0]
                else
                    .{ .seq = p.seq[0 .. p.seq.len - 1] };
            return seq(&.{ group(&alt(&newpats)), z });
        }
    }

    /// combine sequences of literals into a single literal
    fn combineSeq(comptime pats: []const Pattern) ?Pattern {
        const ok = for (pats) |pat| {
            if (!(pat == .literal or pat == .empty)) break false;
        } else true;
        if (!ok) return null;

        var s: []const u8 = "";
        for (pats) |pat| {
            if (pat != .empty) s = s ++ pat.literal.ptr[0..pat.literal.len];
        }
        return literal(s);
    }

    pub const ParseError = pk.ParseError;

    pub const Result = struct {
        input: pk.Input,
        output: Output,

        const Output = union(enum) {
            err: ParseError,
            // TODO perhaps change ok back to []const u8 now that run()
            // 'returns' by out pointer
            /// start and end indices for input.s
            ok: [2]u32,
        };

        pub fn err(i: pk.Input) Result {
            return .{ .input = i, .output = .{ .err = error.ParseFailure } };
        }
        pub fn errWith(i: pk.Input, e: ParseError) Result {
            return .{ .input = i, .output = .{ .err = e } };
        }
        pub fn ok(i: pk.Input, s: [2]u32) Result {
            return .{ .input = i, .output = .{ .ok = s } };
        }
    };

    pub const MemoTable = std.AutoHashMapUnmanaged([2]u32, Result);

    pub const RunCtx = struct {
        in: pk.Input,
        id: u32,
        allocator: mem.Allocator,
        memo: MemoTable = .{},
        // TODO make void in non-debug builds, eventually remove.
        nonterm_visit_counts: ?*anyopaque = null,

        pub fn init(
            in: pk.Input,
            id: u32,
            allocator: mem.Allocator,
        ) @This() {
            return .{ .in = in, .id = id, .allocator = allocator };
        }
    };

    const show_nonterm_visit_counts = false;

    pub fn parse(
        comptime Grammar: type,
        start_rule_id: u32,
        input: []const u8,
        opts: pk.Options,
    ) Result {
        var in = pk.input(input);
        const allocator = opts.allocator orelse pk.failing_allocator;

        const Counts = std.enums.EnumArray(Grammar.NonTerminal, usize);
        var nonterm_visit_counts = Counts.initDefault(0, .{});

        var ctx = RunCtx.init(in, start_rule_id, allocator);
        if (show_nonterm_visit_counts) ctx.nonterm_visit_counts = &nonterm_visit_counts;
        var result: Result = undefined;
        Grammar.rules[start_rule_id][1].run(Grammar, &ctx, &result);
        if (show_nonterm_visit_counts) {
            std.sort.insertion(usize, &nonterm_visit_counts.values, {}, std.sort.desc(usize));
            for (std.meta.tags(Grammar.NonTerminal)) |tag| {
                std.debug.print("{s}={}\n", .{ @tagName(tag), nonterm_visit_counts.get(tag) });
            }
        }
        return result;
    }

    // run() is recursive so it is optimized to reduce fn call overhead by
    // passing 'ctx' and 'res' as pointers. because of this, they are often
    //  reused below and some control flow may be sligntly non-intuitive.
    pub fn run(
        pat: Pattern,
        comptime Grammar: type,
        ctx: *RunCtx,
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
                    const Counts = std.enums.EnumArray(Grammar.NonTerminal, usize);
                    var nonterm_visit_counts = @as(?*Counts, @ptrCast(@alignCast(ctx.nonterm_visit_counts))) orelse
                        unreachable;
                    var timer = std.time.Timer.start() catch unreachable;
                    const prev_id = ctx.id;
                    defer ctx.id = prev_id;
                    ctx.id = id;
                    const p = Grammar.rules[id][1];
                    if (debugthis)
                        std.debug.print("{s} {s}\n", .{ @tagName(Grammar.rules[id][0]), @tagName(p) });
                    defer {
                        const ns = timer.read();
                        nonterm_visit_counts.getPtr(@as(Grammar.NonTerminal, @enumFromInt(id))).* += ns;
                    }
                    p.run(Grammar, ctx, res);
                } else {
                    const prev_id = ctx.id;
                    defer ctx.id = prev_id;
                    ctx.id = id;
                    const p = Grammar.rules[id][1];
                    if (debugthis)
                        std.debug.print("{s} {s}\n", .{ @tagName(Grammar.rules[id][0]), @tagName(p) });
                    @call(.always_tail, run, .{ p, Grammar, ctx, res });
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
                    p.run(Grammar, ctx, res);
                    if (res.output == .err) return;
                    ctx.in.index = res.input.index;
                }
                res.* = Result.ok(ctx.in, in.rangeTo(ctx.in.index));
            },
            .alt => |pats| {
                for (pats) |*p| {
                    ctx.in.index = in.index;
                    p.run(Grammar, ctx, res);
                    if (res.output == .ok) return;
                }
                res.* = Result.err(in);
            },
            .many => |p| {
                while (true) {
                    p.run(Grammar, ctx, res);
                    ctx.in.index = res.input.index;
                    if (res.output == .err) break;
                }
                res.* = Result.ok(ctx.in, in.rangeTo(ctx.in.index));
            },
            .plus => |p| {
                p.run(Grammar, ctx, res);
                ctx.in.index = res.input.index;
                if (res.output == .err) return;
                while (true) {
                    p.run(Grammar, ctx, res);
                    ctx.in.index = res.input.index;
                    if (res.output == .err) break;
                }
                res.* = Result.ok(ctx.in, in.rangeTo(ctx.in.index));
            },
            .group => |p| p.run(Grammar, ctx, res),
            .not => |p| {
                p.run(Grammar, ctx, res);
                ctx.in.index = in.index;
                res.* = if (res.output == .ok)
                    Result.err(in)
                else
                    Result.ok(in, in.rangeTo(res.input.index));
            },
            .amp => |p| {
                p.run(Grammar, ctx, res);
                ctx.in.index = in.index;
                res.* = .{ .input = in, .output = res.output };
            },
            .eos => res.* = if (in.eos())
                Result.ok(in, in.restRange())
            else
                Result.err(in),
            .opt => |p| {
                p.run(Grammar, ctx, res);
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
                m.pat.run(Grammar, ctx, res);
                gop.value_ptr.* = res.*;
            },
        }
    }

    pub fn format(
        pat: Pattern,
        comptime fmt: []const u8,
        opts: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        // try writer.print("{s}: ", .{@tagName(pat)});
        switch (pat) {
            .literal => |lit| _ = try writer.write(lit.ptr[0..lit.len]),
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
            .not => _ = try writer.writeByte('!'),
            .amp => _ = try writer.writeByte('&'),
            .dot => _ = try writer.writeByte('.'),
        }
    }
};

pub fn parseString(
    p: anytype,
    s: []const u8,
    allocator: mem.Allocator,
) !ps.PType(@TypeOf(p)).Ok {
    const r = p.run(pk.input(s), .{ .allocator = allocator });
    if (r.output == .err) {
        // debug("failed at {} err={}\n", .{ r.input, r.output.err });
        return r.output.err;
    }
    return r.output.ok;
}
