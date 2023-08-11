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

// zig fmt: off
pub const ident_str = ps.seq(.{
        ps.satisfy(std.ascii.isAlphabetic), 
        ps.choice(.{ ps.satisfy(std.ascii.isAlphanumeric), ps.char('_') })
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

fn litStr(comptime c: u8, tag: Expr.Tag) ExprP(error{}) {
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

pub const memo = ps.seqMapAlloc(.{
    ps.discardSeq(.{ ps.str("{{"), spacing }),
    ps.ref(exprRef),
    ps.discardSeq(.{ ps.str("}}"), spacing }),
}, Expr.memo);

pub const primary = ps.choice(.{ ident, group, literal, class, memo, dot });

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

/// Sequence <- Prefix (Prefix)* /
pub const sequence = ps.choice(.{
    ps.seqMap(.{ prefix, ps.many(prefix, .{}) }, Expr.initPlusRes),
    ps.discardSeq(.{ spacing, ps.eos })
        .discardL(ps.constant(pk.Input, @as(Expr.PlusRes, .{ Expr.empty, &.{} }))),
})
    .mapAlloc(Expr.initFnAlloc(.seq));

/// Expression <- Sequence (SLASH Sequence)*
pub const expression = ps.seqMap(.{
    sequence,
    ps.char('/').discardR(spacing).discardL(sequence).many(.{}),
}, Expr.initPlusRes)
    .mapAlloc(Expr.initFnAlloc(.alt));

fn exprRef() ExprP(error{InvalidCharacterClass}) {
    return expression;
}

pub const left_arrow = ps.discardSeq(.{ ps.str("<-"), spacing });
pub const ident_arrow = ident_str.discardR(left_arrow);
pub const def = ps.seq(.{ ident_arrow, expression.until(ident_arrow) });
pub const grammar = spacing
    .discardL(def.many1())
    .discardR(ps.eos)
    .map(Expr.initFn(.grammar));
