const std = @import("std");
const mem = std.mem;
const pk = @import("lib.zig");
const ps = pk.parsers;

pub const Charset = union(enum) {
    range: [2]u8,
    one: u8,

    fn one(c: u8) Charset {
        return .{ .one = c };
    }
    fn range(a: u8, b: u8) Charset {
        return .{ .range = .{ a, b } };
    }
};

pub const Expr = union(enum) {
    ident: []const u8,
    /// single quoted literal
    litS: []const u8,
    /// double quoted literal
    litD: []const u8,
    class: []const Charset,
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

    pub const Def = struct { []const u8, Expr };
    pub const Tag = std.meta.Tag(Expr);

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
            .class => |sets| allocator.free(sets),
            .ident, .dot => {},
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
    const FnAlloc = fn ([]const Expr, ?mem.Allocator) pk.ParseError!Expr;
    pub fn initFnAlloc(comptime tag: Tag) FnAlloc {
        return struct {
            fn func(
                es: []const Expr,
                mallocator: ?mem.Allocator,
            ) pk.ParseError!Expr {
                if (es.len == 1) {
                    const allocator = mallocator orelse
                        return error.AllocatorRequired;
                    defer allocator.free(es);
                    return es[0];
                }
                return @unionInit(Expr, @tagName(tag), es);
            }
        }.func;
    }

    pub fn group(e: Expr, mallocator: ?mem.Allocator) !Expr {
        const allocator = mallocator orelse return error.AllocatorRequired;
        const o = try allocator.create(Expr);
        o.* = e;
        return .{ .group = o };
    }

    fn escape(c: u8) ?u8 {
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
            .class => |sets| for (sets) |set| {
                switch (set) {
                    .one => |c| try unescapeByte(c, writer, e),
                    .range => |ab| {
                        try unescapeByte(ab[0], writer, e);
                        try writer.writeByte('-');
                        try unescapeByte(ab[1], writer, e);
                    },
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
        // comptime fmt: []const u8,
        // os: std.fmt.FormatOptions,
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
            .class => {
                try writer.writeByte('[');
                try unescape(e, writer);
                try writer.writeByte(']');
            },
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
        }
    }
};

// TODO move into peg-parsers.zig
pub const Peg = struct {
    pub const eol = ps.choice(.{ ps.str("\r\n"), ps.str("\n"), ps.str("\r") });
    pub const space = ps.choice(.{ ps.anycharIn(" \t").asStr(), eol });
    pub const comment = ps.char('#')
        .discardL(ps.until(ps.takeWhile(ps.anychar, .{}), eol).discardR(eol));
    pub const spacing = ps.takeWhile(ps.choice(.{ space, comment }), .{});

    pub const ident_str = ps.scanString(usize, 0, struct {
        fn func(i: usize, c: u8) ?usize {
            const cont = if (i == 0)
                std.ascii.isAlphabetic(c)
            else
                std.ascii.isAlphabetic(c) or std.ascii.isDigit(c) or c == '_';
            // std.debug.print("ident i={} c={c} cont={}\n", .{ i, c, cont });
            return if (cont) i + 1 else null;
        }
    }.func)
        .discardR(spacing);

    pub const ident = ident_str.map(Expr.initFn(.ident));

    pub const group = ps.seq(.{
        ps.discardSeq(.{ ps.char('('), spacing }),
        ps.ref(exprRef).discardR(spacing),
        ps.discardSeq(.{ ps.char(')'), spacing }),
    })
        .mapAlloc(Expr.group);

    pub const escape: pk.ByteParser = .{
        .runFn = struct {
            const P = pk.ByteParser;
            fn run(_: P, i: pk.Input, _: pk.Options) P.Result {
                const c = i.get(0) orelse return P.err(i, .{});
                // std.debug.print("esc c={c}\n", .{c});
                return if (Expr.escape(c)) |e|
                    P.ok(i.advanceBy(1), e, .{})
                else
                    P.err(i, .{});
            }
        }.run,
        .fail_handler = pk.default_fail_handler,
        .type = .char,
    };

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

    pub const ExprP = pk.ParserWithErrorSet(
        pk.Input,
        Expr,
        std.fmt.ParseIntError || pk.ParseError,
    );

    fn litStr(comptime c: u8, tag: Expr.Tag) ExprP {
        const cp = ps.char(c);
        return cp
            .discardL(ps.manyUntil(chr_c, cp))
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
    pub const range = ps.choice(.{ range1, chr_c.map(Charset.one) });

    pub const class = ps.char('[')
        .discardL(ps.manyUntil(range, ps.char(']')))
        .map(Expr.initFn(.class))
        .discardR(ps.char(']'))
        .discardR(spacing);

    pub const primary = ps.choice(.{ ident, group, literal, class, dot });

    fn exprTag(comptime t: ?Expr.Tag) fn (u8) ?Expr.Tag {
        return struct {
            fn func(_: u8) ?Expr.Tag {
                return t;
            }
        }.func;
    }

    fn suffixFn(e: Expr, mt: ?Expr.Tag, mallocator: ?mem.Allocator) !Expr {
        const t = mt orelse return e;
        const allocator = mallocator orelse return error.AllocatorRequired;
        return switch (t) {
            inline .opt, .star, .plus => |tag| blk: {
                const o = try allocator.create(Expr);
                o.* = e;
                break :blk @unionInit(Expr, @tagName(tag), o);
            },
            else => error.ParseFailure,
        };
    }

    pub const suffix = ps.seqMapAlloc(.{ primary, ps.choice(.{
        ps.char('?').discardR(spacing).map(exprTag(.opt)),
        ps.char('*').discardR(spacing).map(exprTag(.star)),
        ps.char('+').discardR(spacing).map(exprTag(.plus)),
        ps.constant(pk.Input, @as(?Expr.Tag, null)),
    }) }, suffixFn);

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

    pub const prefix = ps.seqMapAlloc(.{
        ps.choice(.{
            ps.char('&').discardR(spacing).map(exprTag(.amp)),
            ps.char('!').discardR(spacing).map(exprTag(.not)),
            ps.constant(pk.Input, @as(?Expr.Tag, null)),
        }),
        suffix,
    }, prefixFn);

    pub const sequence = ps.many1(prefix)
        .mapAlloc(Expr.initFnAlloc(.seq));

    pub const expression = sequence
        .sepBy1(ps.char('/').discardR(spacing))
        .mapAlloc(Expr.initFnAlloc(.alt));

    fn exprRef() ExprP {
        return expression;
    }

    pub const left_arrow = ps.discardSeq(.{ ps.str("<-"), spacing });
    pub const ident_arrow = ident_str.discardR(left_arrow);
    pub const def = ps.seq(.{ ident_arrow, expression.until(ident_arrow) });
    pub const grammar = spacing
        .discardL(def.many1())
        .discardR(ps.eos)
        .map(Expr.initFn(.grammar));
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
