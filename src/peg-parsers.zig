const std = @import("std");
const mem = std.mem;
const pk = @import("parakeet");
const ps = pk.parsers;
const peg = pk.peg;
const Expr = peg.Expr;
const Charset = peg.Charset;

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
