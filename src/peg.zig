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
    memo: ExprId,
    cap: ExprId,
    alt: []const Expr,
    seq: []const Expr,
    grammar: []const Def,
    empty,

    pub const Def = struct { []const u8, Expr };
    pub const Tag = std.meta.Tag(Expr);
    pub const ExprId = struct { expr: *const Expr, id: u32 };

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
            .memo, .cap => |m| {
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
        // std.debug.print("{s}={} es={any}\n", .{ @tagName(e), e, es });
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
        const allocator = mallocator orelse return error.AllocatorRequired;
        const o = try allocator.create(Expr);
        o.* = e;
        defer memoid += 1;
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
            .memo => |eid| {
                _ = try writer.write("{{ ");
                try eid.expr.formatImpl(writer, depth + 1);
                _ = try writer.write(" }}");
            },
            .cap => |eid| {
                try eid.expr.formatImpl(writer, depth + 1);
                try writer.print(":{}", .{eid.id});
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
            .empty => {
                // _ = try writer.write("__empty_string");
            },
        }
    }

    const ExprAllr = struct { Expr, mem.Allocator };
    pub fn fmtGen(e: Expr, allocator: mem.Allocator) std.fmt.Formatter(formatGen) {
        return .{ .data = .{ e, allocator } };
    }

    pub const FmtMode = enum { enum_literals, string_literals };
    pub const NonTerminalIdMap = std.StringHashMap(u32);
    pub fn formatGen(
        ea: ExprAllr,
        comptime fmt: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        const mode: FmtMode = if (fmt.len == 0)
            .enum_literals
        else if (comptime mem.eql(u8, fmt, "s"))
            .string_literals
        else
            @compileError("formatGen() unsupported fmt: '" ++ fmt ++ "'");
        var nonterms = NonTerminalIdMap.init(ea[1]);
        try ea[0].formatGenImpl(mode, &nonterms, writer);
    }

    pub fn formatGenImpl(
        e: Expr,
        mode: FmtMode,
        nonterms: *NonTerminalIdMap,
        writer: anytype,
    ) !void {
        switch (e) {
            .grammar => |rules| {
                if (mode == .enum_literals) {
                    _ = try writer.write(
                        \\pub fn Grammar(
                        \\    comptime pk: type,
                        \\    comptime options: struct { eval_branch_quota: usize = 1000 },
                        \\) type {
                        \\    return struct {
                        \\    pub const Rule = pk.pattern.Rule(NonTerminal, pk.pattern.Pattern);
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
                        \\    const rules_len = @typeInfo(NonTerminal).Enum.fields.len;
                        \\
                        \\    const P = pk.pattern.Pattern;
                        \\    const Class = pk.peg.Expr.Class;
                        \\    const nonterm = Rule.nonterm;
                        \\    fn _rules() [rules_len]Rule {
                        \\        @setEvalBranchQuota(options.eval_branch_quota);
                        \\        return [_]Rule{
                        \\
                    );
                    for (rules) |rule| {
                        try writer.writeByteNTimes(' ', 8);
                        try writer.print("Rule.init(.{s}, ", .{rule[0]});
                        try rule[1].formatGenImpl(mode, nonterms, writer);
                        _ = try writer.write("),\n");
                    }

                    _ = try writer.write(
                        \\        };
                        \\    }
                        \\
                        \\    pub const rules = _rules();
                        \\    };
                        \\}
                    );
                } else {
                    _ = try writer.write(
                        \\pub fn grammar(
                        \\    comptime pk: type,
                        \\    comptime options: struct { eval_branch_quota: usize = 1000 },
                        \\) []const struct { []const u8, pk.pattern.Pattern } {
                        \\        @setEvalBranchQuota(options.eval_branch_quota);
                        \\
                    );
                    for (rules, 0..) |rule, i| {
                        const gop = nonterms.getOrPut(rule[0]) catch |err| {
                            std.debug.panic("unrecoverable grammar error: '{s}'\n", .{@errorName(err)});
                        };
                        if (gop.found_existing)
                            std.debug.panic("grammar error: redifinition of '{s}'\n", .{rule[0]});
                        gop.value_ptr.* = @intCast(i);
                    }
                    _ = try writer.write(
                        \\    const P = pk.pattern.Pattern;
                        \\    const Class = pk.peg.Expr.Class;
                        \\    const nonterm = P.nontermNamed;
                        \\    return comptime &.{
                        \\
                    );
                    for (rules) |rule| {
                        try writer.writeByteNTimes(' ', 8);
                        try writer.print(".{{\"{s}\", ", .{rule[0]});
                        try rule[1].formatGenImpl(mode, nonterms, writer);
                        _ = try writer.write("},\n");
                    }
                    _ = try writer.write("    };\n}");
                }
            },
            .ident => |s| {
                if (mode == .enum_literals)
                    try writer.print("nonterm(.{s})", .{s})
                else {
                    const id = nonterms.get(s) orelse {
                        std.debug.panic("unrecoverable grammar error: invalid nonterminal '{s}'\n", .{s});
                    };
                    try writer.print("nonterm(\"{s}\", {})", .{ s, id });
                }
            },
            .litS, .litD => |s| {
                _ = try writer.write("P.literal(\"");
                try writer.print("{}", .{std.zig.fmtEscapes(s)});
                _ = try writer.write("\")");
            },
            .class => |klass| {
                // here we must infer the difference between a range like [a-z]
                // and lone characters like [az]
                _ = try writer.write("P.class(&Class.init(&.{");
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
            .dot => _ = try writer.write("P.dot()"),
            .empty => _ = try writer.write("P.empty()"),
            .seq => |es| {
                _ = try writer.write("P.seq(&.{");
                for (es) |ie| {
                    try ie.formatGenImpl(mode, nonterms, writer);
                    _ = try writer.write(", ");
                }
                _ = try writer.write("})");
            },
            .alt => |es| {
                _ = try writer.write("P.alt(&.{");
                for (es) |ie| {
                    try ie.formatGenImpl(mode, nonterms, writer);
                    _ = try writer.write(", ");
                }
                _ = try writer.write("})");
            },
            .not => |ie| {
                _ = try writer.write("P.not(&");
                try ie.formatGenImpl(mode, nonterms, writer);
                _ = try writer.write(")");
            },
            .amp => |ie| {
                _ = try writer.write("P.amp(&");
                try ie.formatGenImpl(mode, nonterms, writer);
                _ = try writer.write(")");
            },
            .opt => |ie| {
                _ = try writer.write("P.opt(&");
                try ie.formatGenImpl(mode, nonterms, writer);
                _ = try writer.write(")");
            },
            .star => |ie| {
                _ = try writer.write("P.many(&");
                try ie.formatGenImpl(mode, nonterms, writer);
                _ = try writer.write(")");
            },
            .plus => |ie| {
                _ = try writer.write("P.seq(&.{");
                try ie.formatGenImpl(mode, nonterms, writer);
                _ = try writer.write(", P.many(&");
                try ie.formatGenImpl(mode, nonterms, writer);
                _ = try writer.write(")})");
            },
            .group => |ie| {
                try ie.formatGenImpl(mode, nonterms, writer);
            },
            .memo => |eid| {
                _ = try writer.write("P.memo(&");
                try eid.expr.formatGenImpl(mode, nonterms, writer);
                try writer.print(", {})", .{eid.id});
            },
            .cap => |eid| {
                _ = try writer.write("P.capture(&");
                try eid.expr.formatGenImpl(mode, nonterms, writer);
                try writer.print(", {})", .{eid.id});
            },
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
        // std.debug.print("failed at {} err={}\n", .{ r.input, r.output.err });
        return r.output.err;
    }
    return r.output.ok;
}

pub const parsers = struct {
    pub const eol = ps.choice(.{ ps.str("\r\n"), ps.str("\n"), ps.str("\r") });
    pub const space = ps.choice(.{ ps.anycharIn(" \t").asStr(), eol });
    pub const comment = ps.char('#')
        .discardL(ps.until(ps.takeWhile(ps.anychar, .{}), eol).discardR(eol));
    pub const spacing = ps.takeWhile(ps.choice(.{ space, comment }), .{});

    // zig fmt: off
    pub const ident_str = ps.seq(.{
        ps.choice(.{
            ps.satisfy(std.ascii.isAlphabetic),
            ps.char('_'),
        }),
        ps.choice(.{
            ps.satisfy(std.ascii.isAlphanumeric), 
            ps.char('_') 
        })
            .takeWhile(.{}) 
    })
        .asStr()
        .discardR(spacing);
    // zig fmt: on

    pub const ident = ident_str.map(Expr.initFn(.ident));

    pub const group = ps.seq(.{
        ps.discardSeq(.{ ps.char('('), spacing }),
        ps.ref(exprRef).discardR(spacing),
        ps.discardSeq(.{ ps.char(')'), spacing }),
    })
        .mapAlloc(Expr.group);

    pub const escape = ps.satisfyOpt(Expr.escape);
    pub const bslash = ps.char('\\');
    pub const bslash_dash = bslash.discardL(ps.char('-'));
    pub const octal = bslash.discardL(ps.int(u8, .{ .max = 3 }, 8));
    pub const chr_c = ps.choice(.{
        bslash.discardL(escape),
        octal,
        bslash_dash,
        ps.anychar,
    });

    fn litWithTag(comptime tag: Expr.Tag) fn ([]const u8) Expr {
        return struct {
            fn func(s: []const u8) Expr {
                return @unionInit(Expr, @tagName(tag), s);
            }
        }.func;
    }

    pub fn ExprP(comptime E: type) type {
        return pk.ParserWithErrorSet(
            pk.Input,
            Expr,
            std.fmt.ParseIntError || pk.ParseError || E,
        );
    }

    // Literal <-
    //      ['] (!['] Char )* ['] Spacing
    //    / ["] (!["] Char )* ["] Spacing
    fn litStr(comptime c: u8, tag: Expr.Tag) ExprP(error{}) {
        const cp = ps.char(c);
        return cp
            .discardL(ps.many1(ps.seq(.{ ps.peekNot(cp), chr_c })))
            .discardR(cp)
            .discardR(spacing)
            .map(litWithTag(tag));
    }

    pub const literal = ps.choice(.{
        litStr('\'', .litS),
        litStr('"', .litD),
    });

    pub const dot = ps.char('.').discardR(spacing).map(Expr.dot);

    pub const range1 = ps.seqMap(
        .{ chr_c, ps.char('-').discard(), chr_c },
        Charset.range,
    );
    pub const range = ps.choice(.{
        range1,
        ps.peek(ps.notchar(']')).discardL(chr_c.map(Charset.one)),
    });

    fn accCharsets(set: *Expr.Class.Set, cset: Charset) void {
        switch (cset) {
            .one => |c| set.set(c),
            .range => |ab| set.setRangeValue(
                .{ .start = ab[0], .end = ab[1] + 1 },
                true,
            ),
        }
    }

    /// returns error if zero or more than 1/2 of the class bits are set
    pub fn maybeNegate(neg: bool, bitset: Expr.Class.Set) !Expr.Class.Set {
        const count = bitset.count();
        if (count * 2 > Expr.Class.Set.bit_length) {
            if (!@import("builtin").is_test)
                std.debug.print(
                    "error: character class must have less than half of its bits " ++
                        "set.  expected at most {} bits set.  found {} bits set. ",
                    .{ Expr.Class.Set.bit_length / 2, count },
                );
            return error.InvalidCharacterClass;
        } else if (count == 0) {
            if (!@import("builtin").is_test)
                std.debug.print("error: character class with 0 elements", .{});
            return error.InvalidCharacterClass;
        }
        return if (neg) bitset.complement() else bitset;
    }

    // zig fmt: off
    pub const class = ps.char('[')
        .discardL(ps.seqMap(.{
            ps.option(ps.char('^')).map(pk.isNonEmptyString),
            ps.foldWhile(Expr.Class.Set.initEmpty(), range, accCharsets),
        }, maybeNegate)
        .map(Expr.class))
        .discardR(ps.char(']'))
        .discardR(spacing);
    // zig fmt: on

    /// '{{' expression '}}'
    pub const memo = ps.seqMapAlloc(.{
        ps.discardSeq(.{ ps.str("{{"), spacing }),
        ps.ref(exprRef).discardR(spacing),
        ps.discardSeq(.{ ps.str("}}"), spacing }),
    }, Expr.memo);

    pub const primary = ps.choice(.{
        group,
        literal,
        class,
        memo,
        ps.seq(.{ ident, ps.peekNot(left_arrow) }),
        dot,
    });

    fn exprTag(comptime t: ?Expr.Tag) fn (u8) ?Expr.Tag {
        return struct {
            fn func(_: u8) ?Expr.Tag {
                return t;
            }
        }.func;
    }

    var capid: u32 = 0;
    fn suffixFn(e: Expr, mt: ?Expr.Tag, _cap_str: ?[]const u8, mallocator: ?mem.Allocator) !Expr {
        const allocator = mallocator orelse return error.AllocatorRequired;
        const is_cap = _cap_str != null;
        const cap_str = _cap_str orelse "";
        // std.debug.print("is_cap={} cap_str='{s}'\n", .{ is_cap, cap_str });
        defer capid += @intFromBool(is_cap and cap_str.len != 0);
        return if (!is_cap)
            switch (mt orelse return e) {
                inline .opt, .star, .plus => |tag| blk: {
                    const o = try allocator.create(Expr);
                    o.* = e;
                    break :blk @unionInit(Expr, @tagName(tag), o);
                },
                else => error.ParseFailure,
            }
        else if (mt) |t| switch (t) {
            inline .opt, .star, .plus => |tag| blk: {
                const cap_id = if (cap_str.len == 0)
                    capid
                else
                    try std.fmt.parseInt(u32, cap_str, 10);
                const o = try allocator.create(Expr);
                o.* = e;
                const o2 = try allocator.create(Expr);
                o2.* = @unionInit(Expr, @tagName(tag), o);
                break :blk .{ .cap = .{ .expr = o2, .id = cap_id } };
            },
            else => error.ParseFailure,
        } else blk: {
            const cap_id = if (cap_str.len == 0)
                capid
            else
                try std.fmt.parseInt(u32, cap_str, 10);
            const o = try allocator.create(Expr);
            o.* = e;
            break :blk .{ .cap = .{ .expr = o, .id = cap_id } };
        };
    }

    /// Suffix <- Primary (QUESTION / STAR / PLUS)? (':' digits)?
    pub const suffix = ps.seqMapAlloc(.{
        primary,
        ps.choice(.{
            ps.char('?').discardR(spacing).map(exprTag(.opt)),
            ps.char('*').discardR(spacing).map(exprTag(.star)),
            ps.char('+').discardR(spacing).map(exprTag(.plus)),
            ps.constant(pk.Input, @as(?Expr.Tag, null)),
        }),
        ps.optional(ps.seq(.{
            ps.discardSeq(.{ ps.char(':'), spacing }),
            ps.option(ps.digits(10)).discardR(spacing),
        })),
    }, suffixFn);

    fn prefixFn(mt: ?Expr.Tag, e: Expr, mallocator: ?mem.Allocator) !Expr {
        const t = mt orelse return e;
        const allocator = mallocator orelse return error.AllocatorRequired;
        return switch (t) {
            inline .amp, .not => |tag| blk: {
                const o = try allocator.create(Expr);
                o.* = e;
                break :blk @unionInit(Expr, @tagName(tag), o);
            },
            else => error.ParseFailure,
        };
    }

    /// Prefix <- AND Suffix / NOT Suffix / Suffix
    pub const prefix = ps.seqMapAlloc(.{
        ps.choice(.{
            ps.char('&').discardR(spacing).map(exprTag(.amp)),
            ps.char('!').discardR(spacing).map(exprTag(.not)),
            ps.constant(pk.Input, @as(?Expr.Tag, null)),
        }),
        suffix,
    }, prefixFn);

    /// Sequence <- Prefix (Prefix)* /
    pub const sequence = ps.choice(.{
        ps.seqMap(.{ prefix, ps.many(prefix, .{}) }, Expr.initPlusRes),
        // the following allows for lone trailing '/' which translates to
        // 'or empty string'.  this only happens when prefix fails and
        // 'eos or end of def' succeeds.
        ps.choice(.{
            ps.discardSeq(.{ spacing, ps.eos }),
            ps.peek(ps.seq(.{ ident_str, left_arrow })).discard(),
        })
            .discardL(
            ps.constant(pk.Input, Expr.PlusRes{ .empty, &.{} }),
        ),
    })
        .mapAlloc(Expr.initFnAlloc(.seq));

    /// Expression <- Sequence (SLASH Sequence)*
    pub const expression = ps.seqMap(.{
        sequence,
        ps.char('/')
            .discardR(spacing)
            .discardL(sequence)
            .many(.{}),
    }, Expr.initPlusRes)
        .mapAlloc(Expr.initFnAlloc(.alt));

    fn exprRef() ExprP(error{InvalidCharacterClass}) {
        return expression;
    }

    pub const left_arrow = ps.discardSeq(.{ ps.str("<-"), spacing });
    pub const ident_arrow = ident_str.discardR(left_arrow);

    /// Definition <- Identifier LEFTARROW Expression
    pub const def = ps.seq(.{ ident_arrow, expression });

    /// Grammar <- Spacing Definition+ EndOfFile
    pub const grammar = spacing
        .discardL(def.many1())
        .discardR(ps.eos)
        .map(Expr.initFn(.grammar));
};
