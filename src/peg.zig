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
                    \\pub fn Grammar(
                    \\    comptime pk: type,
                    \\    comptime options: struct { eval_branch_quota: usize = 1000 },
                    \\) type {
                    \\    return struct {
                    \\    pub const Rule = struct{RuleType, pk.peg.Pattern};
                    \\    pub const RuleType = enum {
                    \\
                );
                for (ds) |d| {
                    _ = try writer.write(d[0]);
                    _ = try writer.write(",\n");
                }
                _ = try writer.write(
                    \\
                    \\};
                    \\    const pat = pk.peg.Pattern;
                    \\    const n = @typeInfo(RuleType).Enum.fields.len;
                    \\    fn _rules() [n]Rule {
                    \\    @setEvalBranchQuota(options.eval_branch_quota);
                    \\    return [_]Rule{
                    \\
                );
                for (ds) |d| {
                    try writer.print(".{{ .{s}, ", .{d[0]});
                    try d[1].formatGenImpl(writer, depth);
                    _ = try writer.write("},\n");
                }
                _ = try writer.write(
                    \\};
                    \\}
                    \\    pub const rules = _rules();
                    \\};
                    \\}
                );
            },
            .ident => |s| {
                try writer.print("pat.nontermId(@intFromEnum(RuleType.{s}))", .{s});
            },
            .litS, .litD => |s| {
                _ = try writer.write("pat.literal(\"");
                try writer.print("{}", .{std.zig.fmtEscapes(s)});
                _ = try writer.write("\")");
            },
            .class => |klass| {
                _ = try writer.write("pat.class(&.{.sets = &.{");
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
/// on input with Pattern.parse() and run().
pub const Pattern = union(enum) {
    literal: []const u8,
    class: *const Expr.Class,
    alt: []const Pattern,
    seq: []const Pattern,
    many: *const Pattern,
    plus: *const Pattern,
    opt: *const Pattern,
    not: *const Pattern,
    amp: *const Pattern,
    group: *const Pattern,
    nonterm_id: usize,
    dot,
    eos,
    empty,
    anychar: []const u8,

    comptime {
        std.debug.assert(24 == @sizeOf(Pattern));
    }

    pub const Tag = std.meta.Tag(Pattern);

    pub fn literal(payload: []const u8) Pattern {
        return .{ .literal = payload };
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
    pub fn nontermId(payload: usize) Pattern {
        return .{ .nonterm_id = payload };
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

    pub const ParseError = error{ParseFailure};
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
        pub fn ok(i: pk.Input, s: [2]u32) Result {
            return .{ .input = i, .output = .{ .ok = s } };
        }
    };

    const debug = std.log.debug;

    pub fn RunCtx(comptime Rules: type) type {
        return struct {
            in: pk.Input,
            rules: Rules,
            id: usize,

            pub fn init(in: pk.Input, rules: Rules, id: usize) @This() {
                return .{ .in = in, .rules = rules, .id = id };
            }
        };
    }

    pub fn parse(
        comptime Rule: type,
        rules: []const Rule,
        start_rule_id: usize,
        input: []const u8,
        opts: pk.Options,
    ) Result {
        _ = opts;
        var in = pk.input(input);
        const rule = rules[start_rule_id];
        var ctx = RunCtx([]const Rule).init(in, rules, start_rule_id);
        var result: Result = undefined;
        rule[1].run(Rule, &ctx, &result);
        return result;
    }

    pub fn run(
        pat: Pattern,
        comptime Rule: type,
        ctx: *RunCtx([]const Rule),
        res: *Result,
    ) void {
        const in = ctx.in;
        switch (pat) {
            .nonterm_id => |id| {
                const p = ctx.rules[id][1];
                const oldid = ctx.id;
                defer ctx.id = oldid;
                ctx.id = id;
                p.run(Rule, ctx, res);
                // if (r.output == .ok)
                //     debug("{} {} {s} ok", .{ r.input, p, name });
            },
            .literal => |s| {
                res.* = if (in.startsWith(s))
                    Result.ok(in.advanceBy(@intCast(s.len)), in.range(@intCast(s.len)))
                else
                    Result.err(in);
            },
            .class => |klass| {
                const ic = in.get(0) orelse {
                    res.* = Result.err(in);
                    return;
                };
                const err = for (klass.sets) |set| {
                    switch (set) {
                        .one => |c| if (c == ic)
                            break klass.negated,
                        .range => |ab| if (ic -% ab[0] < ab[1] -% ab[0] + 1)
                            break klass.negated,
                    }
                } else !klass.negated;
                res.* = if (err)
                    Result.err(in)
                else
                    Result.ok(in.advanceBy(1), in.range(1));
            },
            .dot => res.* = if (in.hasCount(1))
                Result.ok(in.advanceBy(1), in.range(1))
            else
                Result.err(in),
            .empty => res.* = Result.ok(in, in.range(0)),
            .anychar => @panic("TODO tag=anychar"),
            .seq => |pats| {
                for (pats) |p| {
                    p.run(Rule, ctx, res);
                    if (res.output == .err) return;
                    ctx.in.index = res.input.index;
                }
                res.* = Result.ok(ctx.in, in.rangeTo(ctx.in.index));
            },
            .alt => |pats| {
                for (pats) |*p| {
                    ctx.in.index = in.index;
                    p.run(Rule, ctx, res);
                    if (res.output == .ok) return;
                }
                res.* = Result.err(in);
            },
            .many => |p| {
                while (true) {
                    p.run(Rule, ctx, res);
                    ctx.in.index = res.input.index;
                    if (res.output == .err) break;
                }
                res.* = Result.ok(ctx.in, in.rangeTo(ctx.in.index));
            },
            .plus => |p| {
                p.run(Rule, ctx, res);
                ctx.in.index = res.input.index;
                if (res.output == .err) return;
                while (true) {
                    p.run(Rule, ctx, res);
                    ctx.in.index = res.input.index;
                    if (res.output == .err) break;
                }
                res.* = Result.ok(ctx.in, in.rangeTo(ctx.in.index));
            },
            .group => |p| p.run(Rule, ctx, res),
            .not => |p| {
                p.run(Rule, ctx, res);
                ctx.in.index = in.index;
                res.* = if (res.output == .ok)
                    Result.err(in)
                else
                    Result.ok(in, in.rangeTo(res.input.index));
            },
            .amp => |p| {
                p.run(Rule, ctx, res);
                ctx.in.index = in.index;
                res.* = .{ .input = in, .output = res.output };
            },
            .eos => res.* = if (in.eos())
                Result.ok(in, in.restRange())
            else
                Result.err(in),
            .opt => |p| {
                p.run(Rule, ctx, res);
                if (res.output == .ok) return;
                ctx.in.index = in.index;
                res.* = Result.ok(in, in.range(0));
            },
        }
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
