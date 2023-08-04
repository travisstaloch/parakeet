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
    alt: []const Expr,
    seq: []const Expr,
    grammar: []const Def,
    empty,

    pub const Def = struct { []const u8, Expr };
    pub const Tag = std.meta.Tag(Expr);
    pub const Class = struct {
        sets: []const Charset,
        negated: bool = false,
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
            .class => |klass| allocator.free(klass.sets),
            .ident, .dot, .empty => {},
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
    pub const PlusRes = struct {
        Expr,
        []const Expr,
    };
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

    pub fn class(cs: []const Charset) !Expr {
        const negated = cs.len > 0 and cs[0] == .one and cs[0].one == '^';
        return .{ .class = .{
            .sets = cs[@intFromBool(negated)..],
            .negated = negated,
        } };
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

    pub fn unescape(e: Expr, writer: anytype) !void {
        switch (e) {
            .litS, .litD => |s| for (s) |c| try unescapeByte(c, writer, e),
            .class => |klass| {
                if (klass.negated) try writer.writeByte('^');
                for (klass.sets) |set| {
                    switch (set) {
                        .one => |c| try unescapeByte(c, writer, e),
                        .range => |ab| {
                            try unescapeByte(ab[0], writer, e);
                            try writer.writeByte('-');
                            try unescapeByte(ab[1], writer, e);
                        },
                    }
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
            .grammar => |ds| {
                _ = try writer.write(
                    \\pub inline fn Rules(
                    \\    comptime pk: type,
                    \\    comptime options: struct { eval_branch_quota: usize = 1000 },
                    \\) []const pk.peg.Rule {
                    \\    @setEvalBranchQuota(options.eval_branch_quota);
                    \\    const pat = pk.peg.Pattern;
                    \\    return comptime &.{
                    \\
                );
                for (ds) |d| {
                    _ = try writer.write(".{ \"");
                    _ = try writer.write(d[0]);
                    _ = try writer.write("\", ");
                    try d[1].formatGenImpl(writer, depth);
                    _ = try writer.write("},\n");
                }
                _ = try writer.write("};}\n");
            },
            .ident => |s| {
                _ = try writer.write("pat.nonterm(\"");
                _ = try writer.write(s);
                _ = try writer.write("\")");
            },
            .litS, .litD => |s| {
                _ = try writer.write("pat.literal(\"");
                try writer.print("{}", .{std.zig.fmtEscapes(s)});
                _ = try writer.write("\")");
            },
            .class => |klass| {
                _ = try writer.write("pat.class(.{.sets = &.{");
                // TODO optimize. if if all .one, use Pattern.anychar
                for (klass.sets) |c| {
                    switch (c) {
                        .range => |ab| try writer.print(".{{.range=.{{'{'}', '{'}'}}}}", .{
                            std.zig.fmtEscapes(&.{ab[0]}),
                            std.zig.fmtEscapes(&.{ab[1]}),
                        }),
                        .one => |a| try writer.print(".{{.one='{'}'}}", .{
                            std.zig.fmtEscapes(&.{a}),
                        }),
                    }
                    _ = try writer.write(", ");
                }
                _ = try writer.write("}");
                if (klass.negated) _ = try writer.write(",.negated = true");
                _ = try writer.write("})");
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
        }
    }
};

/// a data format similar to Expr for encoding parsers and running them
/// on input with Pattern.parse() and run().  run() uses recursion.
pub const Pattern = union(enum) {
    literal: []const u8,
    class: Expr.Class,
    alt: []const Pattern,
    seq: []const Pattern,
    many: *const Pattern,
    plus: *const Pattern,
    opt: *const Pattern,
    not: *const Pattern,
    amp: *const Pattern,
    group: *const Pattern,
    nonterm: []const u8,
    dot,
    eos,
    empty,
    anychar: []const u8,

    pub const Tag = std.meta.Tag(Pattern);

    pub fn literal(payload: []const u8) Pattern {
        return .{ .literal = payload };
    }
    pub fn class(payload: Expr.Class) Pattern {
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
        return if (payload.* == .dot)
            .eos
        else
            .{ .not = payload };
    }
    pub fn amp(payload: *const Pattern) Pattern {
        return .{ .amp = payload };
    }
    pub fn group(payload: *const Pattern) Pattern {
        return .{ .group = payload };
    }
    pub fn nonterm(payload: []const u8) Pattern {
        return .{ .nonterm = payload };
    }
    pub fn dot() Pattern {
        return .dot;
    }
    pub fn empty() Pattern {
        return .empty;
    }
    pub fn anychar(payload: []const u8) Pattern {
        return .{ .anychar = payload };
    }

    pub const ParseError = error{ ParseFailure, MissingRule };
    pub const Result = struct {
        input: pk.Input,
        output: Output,

        const Output = union(enum) {
            err: ParseError,
            ok: []const u8,
        };

        pub fn err(i: pk.Input) Result {
            return .{ .input = i, .output = .{ .err = error.ParseFailure } };
        }
        pub fn ok(i: pk.Input, s: []const u8) Result {
            return .{ .input = i, .output = .{ .ok = s } };
        }
        pub fn errWith(i: pk.Input, e: ParseError) Result {
            return .{ .input = i, .output = .{ .err = e } };
        }
    };

    const debug = std.log.debug;

    pub fn parse(
        rules: anytype,
        start_rule_name: []const u8,
        input: []const u8,
        opts: pk.Options,
    ) Result {
        var i = pk.input(input);
        // defer debug("parse() start={s}", .{start_rule_name});
        const pat = rules.get(start_rule_name) orelse
            return Result.errWith(i, error.MissingRule);
        return pat.run(rules, start_rule_name, i, opts);
    }

    pub fn run(
        pat: *const Pattern,
        rules: anytype,
        rule_name: []const u8,
        i: pk.Input,
        opts: pk.Options,
    ) Result {
        switch (pat.*) {
            .nonterm => |name| {
                const p = rules.get(name) orelse
                    return Result.errWith(i, error.MissingRule);
                const r = p.run(rules, name, i, opts);
                // if (r.output == .ok)
                //     debug("{} - {} {s} ok depth={}/{}", .{ r.input, p, name });
                return r;
            },
            .literal => |s| {
                return if (i.startsWith(s))
                    Result.ok(i.advanceBy(s.len), i.sliceAssume(s.len))
                else
                    Result.err(i);
            },
            .class => |klass| {
                const ic = i.get(0) orelse return Result.err(i);
                const err = for (klass.sets) |set| {
                    switch (set) {
                        .one => |c| if ((c == ic))
                            break klass.negated,
                        .range => |ab| if ((ab[0] <= ic and ic <= ab[1]))
                            break klass.negated,
                    }
                } else !klass.negated;
                return if (err)
                    Result.err(i)
                else
                    Result.ok(i.advanceBy(1), i.sliceAssume(1));
            },
            .dot => return if (i.hasCount(1))
                Result.ok(i.advanceBy(1), i.sliceAssume(1))
            else
                Result.err(i),
            .empty => return Result.ok(i, i.sliceAssume(0)),
            .anychar => @panic("TODO tag=anychar"),
            .seq => |pats| {
                var ii = i;
                for (pats) |*p| {
                    const r = p.run(rules, rule_name, ii, opts);
                    if (r.output == .err) return r;
                    ii.index = r.input.index;
                }
                return Result.ok(ii, i.sliceTo(ii.index));
            },
            .alt => |pats| {
                for (pats) |*p| {
                    const r = p.run(rules, rule_name, i, opts);
                    if (r.output == .ok) return r;
                }
                return Result.err(i);
            },
            .many => |p| {
                var ii = i;
                while (true) {
                    const r = p.run(rules, rule_name, ii, opts);
                    if (r.output == .err) break;
                    ii.index = r.input.index;
                }
                return Result.ok(ii, i.sliceTo(ii.index));
            },
            .plus => |p| {
                var ii = i;
                const r = p.run(rules, rule_name, ii, opts);
                ii.index = r.input.index;
                if (r.output == .err) return r;
                while (true) {
                    const r2 = p.run(rules, rule_name, ii, opts);
                    if (r2.output == .err) break;
                    ii.index = r2.input.index;
                }
                return Result.ok(ii, i.sliceTo(ii.index));
            },
            .group => |p| return p.run(rules, rule_name, i, opts),
            .not => |p| {
                const r = p.run(rules, rule_name, i, opts);
                const rr = if (r.output == .ok)
                    Result.err(i)
                else
                    Result.ok(i, i.sliceTo(r.input.index));
                // std.debug.print("not rr={}\n", .{rr});
                return rr;
            },
            .amp => |p| {
                const r = p.run(rules, rule_name, i, opts);
                return .{ .input = i, .output = r.output };
            },
            .eos => return if (i.eos())
                Result.ok(i, i.rest())
            else
                Result.err(i),
            .opt => |p| {
                const r = p.run(rules, rule_name, i, opts);
                return if (r.output == .err)
                    Result.ok(i, i.sliceTo(r.input.index))
                else
                    r;
            },
        }
        unreachable;
    }

    pub fn format(
        pat: Pattern,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("{s}: ", .{@tagName(pat)});
        switch (pat) {
            .nonterm, .literal => |s| _ = try writer.write(s),
            .seq, .alt => |pats| _ = try writer.print("{}", .{pats.len}),
            .many,
            .plus,
            .group,
            .opt,
            => |_| {},
            .eos, .empty => {},
            .not => _ = try writer.writeByte('!'),
            .amp => _ = try writer.writeByte('&'),
            .anychar => |s| try writer.print("anychar={s}", .{s}),
            .class => |klass| try writer.print("{}", .{klass}),
            .dot => _ = try writer.writeByte('.'),
        }
    }
};

pub const Rule = struct { []const u8, Pattern };

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
