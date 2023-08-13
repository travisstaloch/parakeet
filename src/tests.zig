const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const pk = @import("parakeet");
const ps = pk.parsers;
const input = pk.input;
const char = ps.char;
const satisfy = ps.satisfy;
const charRange = ps.charRange;
const str = ps.str;
const takeWhileFn = ps.takeWhileFn;
const takeWhile = ps.takeWhile;
const takeUntilFn = ps.takeUntilFn;
const takeUntil = ps.takeUntil;
const seq = ps.seq;
const anychar = ps.anychar;
const choice = ps.choice;
const discardR = ps.discardR;
const discardL = ps.discardL;
const any = ps.any;
const many = ps.many;

test {
    _ = @import("peg-tests.zig");
    _ = @import("pattern-tests.zig");
}

/// runs 'p' and checks for end of stream afterward, succeeds when input is at end of stream
pub fn eosAssert(comptime p: anytype) pk.ParserType(p) {
    const P = pk.ParserType(p);
    return .{
        .runFn = struct {
            fn run(_: P, i: P.Input, opts: pk.Options) P.Result {
                const r = p.run(i, opts);
                std.debug.assert(r.output == .ok and r.input.eos());
                return r;
            }
        }.run,
        .fail_handler = p.fail_handler,
        .type = .eosAssert,
    };
}

fn expectResultStr(
    expected: pk.StringParser.Err!pk.StringParser.Ok,
    actual: pk.StringParser.Result,
    rest: []const u8,
) !void {
    if (expected) |r| {
        try testing.expect(actual.output == .ok);
        // try testing.expectEqual(r, actual.output.ok);
        try testing.expectEqualStrings(r, if (actual.output == .ok) actual.output.ok else {
            std.debug.print("error in expectResultStr(): {s}\n", .{@errorName(actual.output.err)});
            return actual.output.err;
        });
    } else |e| {
        try testing.expect(actual.output == .err);
        try testing.expectEqual(e, actual.output.err);
    }
    try testing.expectEqualStrings(rest, actual.input.rest());
}

fn expectResultChar(
    expected: pk.ByteParser.Err!pk.ByteParser.Ok,
    actual: pk.ByteParser.Result,
    rest: []const u8,
) !void {
    if (expected) |r| {
        try testing.expect(actual.output == .ok);
        try testing.expectEqual(r, actual.output.ok);
    } else |e| {
        try testing.expect(actual.output == .err);
        try testing.expectEqual(e, actual.output.err);
    }
    try testing.expectEqualStrings(rest, actual.input.rest());
}

const foobar = input("foobar");
const empty = input("");

pub fn firstTo(comptime T: type) fn ([]const u8) T {
    return struct {
        fn func(s: []const u8) T {
            return s[0];
        }
    }.func;
}
const parse_failure = pk.ParseError.ParseFailure;

test "constant" {
    try expectResultChar('z', ps.constant(pk.Input, @as(u8, 'z')).run(empty, .{}), "");
    try expectResultStr("bar", ps.constant(pk.Input, @as([]const u8, "bar")).run(empty, .{}), "");
}

test "fail" {
    {
        const r = ps.fail("oops").run(empty, .{});
        try testing.expectEqual(parse_failure, r.output.err);
        try testing.expectEqualStrings("oops", r.message);
    }
    { // err input index points to error
        const r = seq(.{ str("foo"), char('z') }).run(foobar, .{});
        try testing.expectEqual(parse_failure, r.output.err);
        try testing.expectEqual(@as(usize, 3), r.input.index);
    }
    { // withMessage() concatenates messages
        const r = (comptime char('a').withMessage("a").withMessage("b")).run(empty, .{});
        try testing.expectEqual(parse_failure, r.output.err);
        try testing.expectEqualStrings("ab", r.message);
    }
}

test "eos" {
    const r = ps.eos.run(foobar, .{});
    try testing.expectEqual(parse_failure, r.output.err);
    try testing.expectEqualStrings(foobar.rest(), r.input.rest());
    try testing.expectEqual(false, ps.iseos.run(foobar, .{}).output.ok);
    try testing.expectEqual({}, ps.eos.run(empty, .{}).output.ok);
    try testing.expectEqual(true, ps.iseos.run(empty, .{}).output.ok);
}

test "forward" {
    try testing.expectEqual(@as(usize, 1), ps.forward(1).run(foobar, .{}).input.index);
    try testing.expectEqual(parse_failure, ps.forward(7).run(foobar, .{}).output.err);
}

test "backward" {
    const in = pk.Input{ .s = "abc", .index = 1, .len = 3 };
    try testing.expectEqual(@as(usize, 0), ps.backward(1).run(in, .{}).input.index);
    try testing.expectEqual(parse_failure, ps.backward(2).run(in, .{}).output.err);
}

test "index" {
    try testing.expectEqual(@as(usize, 0), ps.index.run(foobar, .{}).output.ok);
}

test "length" {
    try testing.expectEqual(@as(usize, 6), ps.length.run(foobar, .{}).output.ok);
}

test "char" {
    try expectResultChar(error.ParseFailure, char('a').run(foobar, .{}), foobar.rest());
    try expectResultChar(error.ParseFailure, char('a').run(empty, .{}), "");
    try expectResultChar('f', char('f').run(input("f"), .{}), "");
    try expectResultChar('f', char('f').run(foobar, .{}), "oobar");
}

test "notChar" {
    try expectResultChar('f', ps.notchar('z').run(input("f"), .{}), "");
    try expectResultChar('f', ps.notchar('z').run(foobar, .{}), "oobar");
}

const isalpha = std.ascii.isAlphabetic;
const isdigit = std.ascii.isDigit;

test "satisfy" {
    try expectResultChar(error.ParseFailure, satisfy(isdigit).run(foobar, .{}), foobar.rest());
    try expectResultChar(error.ParseFailure, satisfy(isdigit).run(empty, .{}), "");
    try expectResultChar('f', satisfy(isalpha).run(input("f"), .{}), "");
    try expectResultChar('f', satisfy(isalpha).run(foobar, .{}), "oobar");
}

test "charRange" {
    try expectResultChar(error.ParseFailure, charRange('0', '9').run(foobar, .{}), foobar.rest());
    try expectResultChar(error.ParseFailure, charRange('0', '9').run(empty, .{}), "");
    try expectResultChar('f', charRange('a', 'z').run(input("f"), .{}), "");
    try expectResultChar('f', charRange('a', 'z').run(foobar, .{}), "oobar");
}

test "anycharIn" {
    try expectResultChar(error.ParseFailure, ps.anycharIn(&.{}).run(foobar, .{}), foobar.rest());
    try expectResultChar(error.ParseFailure, ps.anycharIn(&.{'0'}).run(empty, .{}), "");
    try expectResultChar('f', ps.anycharIn(&.{ 'f', 'z' }).run(input("f"), .{}), "");
    try expectResultChar('f', ps.anycharIn(&.{ 'f', 'z' }).run(foobar, .{}), "oobar");
}

test "anycharNotIn" {
    try expectResultChar(error.ParseFailure, ps.anycharNotIn(&.{'f'}).run(foobar, .{}), foobar.rest());
    try expectResultChar(error.ParseFailure, ps.anycharNotIn(&.{}).run(empty, .{}), "");
    try expectResultChar('f', ps.anycharNotIn(&.{ 'a', 'b' }).run(input("f"), .{}), "");
    try expectResultChar('f', ps.anycharNotIn(&.{ 'a', 'b' }).run(foobar, .{}), "oobar");
}

test "str" {
    try expectResultStr(error.ParseFailure, str("a").run(foobar, .{}), foobar.rest());
    try expectResultStr(error.ParseFailure, str("a").run(empty, .{}), "");
    try expectResultStr("f", str("f").run(input("f"), .{}), "");
    try expectResultStr("f", str("f").run(foobar, .{}), "oobar");
}

test "takeWhileFn" {
    try expectResultStr("", takeWhileFn(isdigit, .{}).run(foobar, .{}), foobar.rest());
    try expectResultStr(foobar.rest(), takeWhileFn(isalpha, .{}).run(foobar, .{}), "");
    try expectResultStr("foo", takeWhileFn(isalpha, .{ .max = 3 }).run(foobar, .{}), "bar");
    try expectResultStr(foobar.rest(), takeWhileFn(isalpha, .{ .max = 7 }).run(foobar, .{}), "");
    {
        const s = "01ab";
        try expectResultStr(error.ParseFailure, takeWhileFn(isdigit, .{ .min = 3 }).run(input(s), .{}), "ab");
        try expectResultStr("01", takeWhileFn(isdigit, .{ .min = 2 }).run(input(s), .{}), "ab");
    }
}

test "takeWhile" {
    try expectResultStr("", (comptime satisfy(isdigit).takeWhile(.{})).run(foobar, .{}), foobar.rest());
    try expectResultStr(foobar.rest(), takeWhile(any(2), .{}).run(foobar, .{}), "");
    try expectResultStr("foo", takeWhile(satisfy(isalpha), .{ .max = 3 }).run(foobar, .{}), "bar");
    try expectResultStr(foobar.rest(), takeWhile(satisfy(isalpha), .{ .max = 7 }).run(foobar, .{}), "");
    {
        const s = "01ab";
        try expectResultStr(error.ParseFailure, takeWhile(satisfy(isdigit), .{ .min = 3 }).run(input(s), .{}), "ab");
        try expectResultStr("01", takeWhile(satisfy(isdigit), .{ .min = 2 }).run(input(s), .{}), "ab");
    }
}

test "takeUntilFn" {
    try expectResultStr(foobar.rest(), takeUntilFn(isdigit, .{}).run(foobar, .{}), "");
    try expectResultStr("", takeUntilFn(isalpha, .{}).run(foobar, .{}), foobar.rest());
    try expectResultStr("foo", takeUntilFn(isdigit, .{ .max = 3 }).run(foobar, .{}), "bar");
    try expectResultStr(foobar.rest(), takeUntilFn(isdigit, .{ .max = 7 }).run(foobar, .{}), "");
    {
        const s = "01ab";
        try expectResultStr(error.ParseFailure, takeUntilFn(isalpha, .{ .min = 3 }).run(input(s), .{}), "ab");
        try expectResultStr("01", takeUntilFn(isalpha, .{ .min = 2 }).run(input(s), .{}), "ab");
    }
}

test "takeUntil" {
    try expectResultStr(foobar.rest(), (comptime satisfy(isdigit).takeUntil(.{})).run(foobar, .{}), "");
    try expectResultStr("", takeUntil(satisfy(isalpha), .{}).run(foobar, .{}), foobar.rest());
    try expectResultStr("foo", takeUntil(satisfy(isdigit), .{ .max = 3 }).run(foobar, .{}), "bar");
    try expectResultStr(foobar.rest(), takeUntil(satisfy(isdigit), .{ .max = 7 }).run(foobar, .{}), "");
    {
        const s = "01ab";
        try expectResultStr(error.ParseFailure, takeUntil(satisfy(isalpha), .{ .min = 3 }).run(input(s), .{}), "ab");
        try expectResultStr("01", takeUntil(satisfy(isalpha), .{ .min = 2 }).run(input(s), .{}), "ab");
    }
}

test "seq" {
    {
        const p = comptime seq(.{ char('a'), char('b') });
        const r = p.run(foobar, .{});
        try testing.expectEqual(parse_failure, r.output.err);
        try testing.expectEqualStrings(foobar.rest(), r.input.rest());
        try testing.expectEqual(parse_failure, p.run(empty, .{}).output.err);
    }
    {
        const p = seq(.{ char('f'), char('o') });
        const r = p.run(foobar, .{});
        try testing.expectEqualStrings("fo", &r.output.ok);
        try testing.expectEqualStrings("obar", r.input.rest());
        try testing.expectEqual(parse_failure, p.run(empty, .{}).output.err);
    }
    {
        const p = seq(.{ char('f'), char('o'), char('o') });
        const r = p.run(foobar, .{});
        const output = r.output.ok;
        try testing.expectEqualStrings("foo", &output);
        try testing.expectEqual(parse_failure, p.run(empty, .{}).output.err);
    }
    {
        const p = seq(.{ str("foo"), str("bar") });
        const r = p.run(foobar, .{});
        const output = r.output.ok;
        try testing.expectEqual(@as(usize, 2), output.len);
        try testing.expectEqualStrings("foo", output[0]);
        try testing.expectEqualStrings("bar", output[1]);
        try testing.expectEqual(parse_failure, p.run(empty, .{}).output.err);
    }
    {
        const p = seq(.{ anychar, anychar });
        const r = p.run(foobar, .{});
        try testing.expectEqualStrings("fo", &r.output.ok);
        try testing.expectEqualStrings("obar", r.input.rest());
    }
    { // mixed output types
        const p = seq(.{ any(2), anychar });
        const r = p.run(foobar, .{});
        const output = r.output.ok;
        try testing.expectEqualStrings("fo", output[0]);
        try testing.expectEqual(@as(u8, 'o'), output[1]);
        try testing.expectEqualStrings("bar", r.input.rest());
    }
}

test "choice" {
    {
        const p = choice(.{ char('a'), char('b') });
        try expectResultChar(error.ParseFailure, p.run(foobar, .{}), foobar.rest());
        try testing.expectEqual(parse_failure, p.run(empty, .{}).output.err);
    }
    {
        const p = choice(.{ char('a'), char('f') });
        try expectResultChar('f', p.run(foobar, .{}), "oobar");
        try testing.expectEqual(parse_failure, p.run(empty, .{}).output.err);
    }
    {
        const p = choice(.{ char('f'), char('a') });
        try expectResultChar('f', p.run(foobar, .{}), "oobar");
        try testing.expectEqual(parse_failure, p.run(empty, .{}).output.err);
    }
}

test "discardR / <*" {
    {
        const p = comptime str("a").@"<*"(str("b"));
        try expectResultStr(error.ParseFailure, p.run(foobar, .{}), foobar.rest());
        try expectResultStr(error.ParseFailure, p.run(empty, .{}), "");
    }
    {
        const p = comptime str("foo").@"<*"(str("a"));
        try expectResultStr(error.ParseFailure, p.run(foobar, .{}), "bar");
        try expectResultStr(error.ParseFailure, p.run(empty, .{}), "");
    }
    {
        const p = comptime str("foo").@"<*"(str("b"));
        try expectResultStr("foo", p.run(foobar, .{}), "ar");
        try expectResultStr(error.ParseFailure, p.run(empty, .{}), "");
    }
    {
        const p = anychar.discardR(str("oo"));
        try expectResultChar('f', p.run(foobar, .{}), "bar");
    }
}

test "discardL / *>" {
    {
        const p = comptime str("a").@"*>"(str("b"));
        try expectResultStr(error.ParseFailure, p.run(foobar, .{}), foobar.rest());
        try expectResultStr(error.ParseFailure, p.run(empty, .{}), "");
    }
    {
        const p = comptime str("foo").discardL(str("a"));
        try expectResultStr(error.ParseFailure, p.run(foobar, .{}), "bar");
        try expectResultStr(error.ParseFailure, p.run(empty, .{}), "");
    }
    {
        const p = comptime str("foo").@"*>"(str("b"));
        try expectResultStr("b", p.run(foobar, .{}), "ar");
        try expectResultStr(error.ParseFailure, p.run(empty, .{}), "");
    }
    {
        const p = comptime str("foo").@"*>"(anychar);
        try expectResultChar('b', p.run(foobar, .{}), "ar");
    }
}

test "map" {
    {
        const p = comptime str("a")
            .map(firstTo(u8));
        try testing.expectEqual(parse_failure, p.run(foobar, .{}).output.err);
        try testing.expectEqual(parse_failure, p.run(empty, .{}).output.err);
    }
    {
        const p = comptime str("f")
            .map(firstTo(usize));
        try testing.expectEqual(@as(usize, 'f'), p.run(foobar, .{}).output.ok);
        try testing.expectEqualStrings("oobar", p.run(foobar, .{}).input.rest());
    }
    {
        const p = comptime any(2)
            .map(struct {
            pub fn func(s: []const u8) [2]u8 {
                return s[0..2].*;
            }
        }.func)
            .map(struct {
            pub fn func(ab: [2]u8) u16 {
                return @bitCast(ab);
            }
        }.func);
        try testing.expectEqual(mem.readIntLittle(u16, "fo"), p.run(foobar, .{}).output.ok);
    }
    {
        const p = comptime takeWhileFn(isdigit, .{ .min = 3 })
            .map(pk.toInt(usize, 10));
        const r = p.run(input("123foo"), .{});
        const output = r.output.ok;
        try testing.expectEqual(@as(usize, 123), output);
        try testing.expectEqualStrings("foo", r.input.rest());
    }
    {
        const p = comptime choice(.{ satisfy(isdigit), char('.') })
            .takeWhile(.{ .min = 3 })
            .map(pk.toFloat(f32));
        const r = p.run(input("123.45foo"), .{});
        const output = r.output.ok;
        try testing.expectApproxEqAbs(@as(f32, 123.45), output, std.math.floatEps(f32));
        try testing.expectEqualStrings("foo", r.input.rest());
    }
    {
        const p = comptime any(1)
            .map(pk.toChar)
            .discardR(ps.eos);
        const r = p.run(input("a"), .{});
        try testing.expectEqual(@as(u21, 'a'), r.output.ok);
    }
    {
        const s = "Āā";
        const p = comptime str(s)
            .map(pk.toChar)
            .discardR(ps.eos);
        const r = p.run(input(s), .{});
        try testing.expectEqual(@as(u21, 0x100), r.output.ok);
    }
    {
        const E = enum { a, b };
        const p = comptime any(1)
            .map(pk.toEnum(E));
        {
            const r = p.run(input("a"), .{});
            try testing.expectEqual(E.a, r.output.ok);
        }
        {
            const r = p.run(input("c"), .{});
            try testing.expectEqual(parse_failure, r.output.err);
            try testing.expectEqualStrings("c", r.input.rest());
        }
    }
    {
        const p = comptime choice(.{ str("true"), str("false") })
            .map(pk.toBool);

        {
            const r = p.run(input("true"), .{});
            try testing.expectEqual(true, r.output.ok);
        }
        {
            const r = p.run(input("false"), .{});
            try testing.expectEqual(false, r.output.ok);
        }
        {
            const r = p.run(input("foo"), .{});
            try testing.expectEqual(parse_failure, r.output.err);
            try testing.expectEqualStrings("foo", r.input.rest());
        }
    }
    {
        const s = "\x0b\x0a\x0b\x0e";
        {
            const p = comptime str(s)
                .map(pk.toIntLittle(u32))
                .discardR(ps.eos);

            const r = p.run(input(s), .{});
            try testing.expectEqual(mem.readIntLittle(u32, s), r.output.ok);
        }
        {
            const p = comptime str(s)
                .map(pk.toIntBig(u32));
            const r = p.run(input(s), .{});
            try testing.expectEqual(mem.readIntBig(u32, s), r.output.ok);
        }
    }
    {
        const p = comptime ps.all
            .discard()
            .discardR(ps.eos);
        const r = p.run(foobar, .{});
        try testing.expectEqual({}, r.output.ok);
    }
}

test "intToken" {
    const p = comptime ps.intToken(i16, .{}, 10);
    {
        const r = p.run(input("-137-"), .{});
        try testing.expectEqualStrings("-137", r.output.ok);
        try testing.expectEqualStrings("-", r.input.rest());
    }
    {
        const r = p.run(input("137-"), .{});
        try testing.expectEqualStrings("137", r.output.ok);
        try testing.expectEqualStrings("-", r.input.rest());
    }
}

test "int" {
    inline for (.{ 2, 8, 10, 16 }) |base| {
        inline for (.{ 8, 16, 32, 64, 128 }) |bits| {
            inline for (.{ .signed, .unsigned }) |signedness| {
                const I = std.meta.Int(signedness, bits);
                const p = comptime ps.int(I, .{}, base);
                const min = std.math.minInt(I);
                const max = std.math.maxInt(I);
                const mid = (min + max) / 2;
                inline for (.{ min - 1, min, mid, max, max + 1 }) |i| {
                    const fmt = switch (base) {
                        2 => "b",
                        8 => "o",
                        10 => "",
                        16 => "x",
                        else => unreachable,
                    };
                    const s = std.fmt.comptimePrint("{" ++ fmt ++ "}-", .{i});
                    const in = input(s);
                    const r = p.run(in, .{});
                    const mcasted = std.math.cast(I, i);
                    if (mcasted) |casted| {
                        try testing.expectEqual(casted, r.output.ok);
                        try testing.expectEqualStrings("-", r.input.rest());
                    } else {
                        if (r.output == .ok) {
                            return error.UnexpectedResult;
                        } else switch (r.output.err) {
                            error.Overflow => try testing.expect(i == min - 1 or i == max + 1),
                            error.ParseFailure => try testing.expect(i == -1 and signedness == .unsigned),
                            else => return error.UnexpectedResult,
                        }
                        try testing.expectEqualStrings(in.rest(), r.input.rest());
                    }
                }
            }
        }
    }
    try testing.expect(
        ps.int(u8, .{}, 2).run(input("2"), .{}).output.err == error.ParseFailure,
    );
}

test "enumeration" {
    const E = enum { foo, foobar, foobarbaz };
    const p = ps.enumeration(E);
    try testing.expectEqual(parse_failure, p.run(input("boo"), .{}).output.err);
    try testing.expectEqual(E.foo, p.run(input("foo"), .{}).output.ok);
    try testing.expectEqual(E.foo, p.run(input("foo123"), .{}).output.ok);
    try testing.expectEqual(E.foobar, p.run(input("foobar"), .{}).output.ok);
    try testing.expectEqual(E.foobar, p.run(input("foobarba"), .{}).output.ok);
    try testing.expectEqual(E.foobarbaz, p.run(input("foobarbaz"), .{}).output.ok);
}

test "toStruct" {
    {
        const T = i16;
        const V = struct { x: T, y: T };

        const int = comptime ps.int(T, .{}, 10);
        const p = comptime seq(.{ int, char(' ').discard(), int })
            .map(pk.toStruct(V))
            .@"<*"(ps.eos);
        const r = p.run(input("137 142"), .{});
        try testing.expectEqual(V{ .x = 137, .y = 142 }, r.output.ok);
    }
    {
        const T = u16;
        const V = struct { x: T, y: T };

        const int = comptime ps.int(T, .{}, 10);
        const p = comptime seq(.{ int, char(' ').discard(), int })
            .map(pk.toStruct(V))
            .@"<*"(ps.eos);
        const r = p.run(input("137 142"), .{});
        try testing.expectEqual(V{ .x = 137, .y = 142 }, r.output.ok);
    }
}

const talloc = testing.allocator;
test "many" {
    {
        const p = comptime str("a")
            .many(.{});
        const r = p.run(foobar, .{}).output.ok;
        try testing.expectEqual(@as(usize, 0), r.len);
    }
    {
        const p = many(str("f"), .{});
        const r = p.run(foobar, .{ .allocator = talloc });
        const output = r.output.ok;
        defer talloc.free(output);
        try testing.expectEqual(@as(usize, 1), output.len);
        try testing.expectEqualStrings("f", output[0]);
        try testing.expectEqualStrings(r.input.rest(), "oobar");
    }
    {
        const p = many(str("f"), .{ .min = 2 });
        try testing.expectEqual(parse_failure, p.run(foobar, .{ .allocator = talloc }).output.err);
    }
    {
        const p = many(discardL(str("f"), str("oo")), .{});
        const r = p.run(foobar, .{ .allocator = talloc });
        const output = r.output.ok;
        defer talloc.free(output);
        try testing.expectEqual(@as(usize, 1), output.len);
        try testing.expectEqualStrings("oo", output[0]);
        try testing.expectEqualStrings(r.input.rest(), "bar");
    }
    {
        const p = anychar
            .many(.{ .max = 4 });
        const r = p.run(foobar, .{ .allocator = talloc });
        const output = r.output.ok;
        defer talloc.free(output);
        try testing.expectEqual(@as(usize, 4), output.len);
        for (foobar.s[0..4], 0..) |c, i|
            try testing.expectEqual(c, output[i]);
        try testing.expectEqualStrings(r.input.rest(), "ar");
    }
    {
        const p = many(anychar.map(struct {
            pub fn func(c: u8) u8 {
                return c;
            }
        }.func), .{});
        const r = p.run(foobar, .{ .allocator = talloc });
        const output = r.output.ok;
        defer talloc.free(output);
        try testing.expectEqualStrings(foobar.rest(), output);
    }
}

test "until" {
    const p = ps.until(str("foo"), str("bar"));
    try expectResultStr("foo", p.run(foobar, .{}), "bar");
    {
        const r = p.run(foobar, .{});
        try testing.expectEqual(@as(usize, 3), r.input.index);
    }

    const comment = comptime char('#')
        .@"*>"(ps.all)
        .until(char('\n'))
        .@"<*"(char('\n'));
    {
        const r = comment.run(input("# comment text\nnext line"), .{ .allocator = talloc });
        try expectResultStr(" comment text", r, "next line");
        try testing.expectEqual(@as(usize, 15), r.input.index);
    }
}

test "output" {
    try expectResultStr("foo", ps.option(str("foo")).run(foobar, .{}), "bar");
    try expectResultStr("", ps.option(str("bar")).run(foobar, .{}), foobar.rest());
    try expectResultStr("f", ps.option(char('f')).run(foobar, .{}), "oobar");
    try expectResultStr("", ps.option(char('b')).run(foobar, .{}), foobar.rest());
}

test "sepBy" {
    {
        const p = comptime charRange('0', '9')
            .sepBy(char(','), .{})
            .discardR(ps.eos);
        const r = p.run(empty, .{});
        const output = r.output.ok;
        try testing.expectEqual(@as(usize, 0), output.len);
    }
    {
        const p = ps.sepBy(charRange('0', '9'), char(','), .{ .min = 2 });
        const r = p.run(input("1"), .{ .allocator = talloc });
        try testing.expectEqual(parse_failure, r.output.err);
        try testing.expectEqualStrings("", r.input.rest());
    }
    {
        const p = ps.sepBy(charRange('0', '9'), char(','), .{});
        const r = p.run(input("1"), .{ .allocator = talloc });
        const output = r.output.ok;
        defer talloc.free(output);
        try testing.expectEqualStrings("1", output);
    }
    {
        const p = ps.sepBy(charRange('0', '9'), char(','), .{});
        const r = p.run(input("1,2foo"), .{ .allocator = talloc });
        const output = r.output.ok;
        defer talloc.free(output);
        try testing.expectEqualStrings("12", output);
        try testing.expectEqualStrings("foo", r.input.rest());
    }
    {
        const ident = comptime ps.takeWhile1(satisfy(isalpha));
        const spaces = comptime ps.skipMany(char(' '), .{});
        const p = comptime ps.sepBy1(ident, char('/').discardR(spaces));
        const r = p.run(input("foo"), .{ .allocator = talloc });
        const output = r.output.ok;
        defer talloc.free(output);
        try testing.expectEqualStrings("foo", output[0]);
    }
}

test "peekChar" {
    {
        const r = ps.peekChar.run(foobar, .{});
        const output = r.output.ok;
        try testing.expectEqual(@as(?u8, 'f'), output);
        try testing.expectEqualStrings("foobar", r.input.rest());
    }
    {
        const r = ps.peekChar.run(empty, .{});
        const output = r.output.ok;
        try testing.expectEqual(@as(?u8, null), output);
    }
}

test "peekCharFail" {
    try expectResultChar('f', ps.peekCharFail.run(foobar, .{}), foobar.rest());
    try expectResultChar(error.ParseFailure, ps.peekCharFail.run(empty, .{}), "");
}

test "peekString" {
    try expectResultStr("f", ps.peekString(1).run(foobar, .{}), foobar.rest());
    try expectResultStr(error.ParseFailure, ps.peekString(7).run(foobar, .{}), foobar.rest());
    try expectResultStr(error.ParseFailure, ps.peekString(1).run(empty, .{}), "");
}

test "peek" {
    try expectResultStr("foo", ps.peek(any(3)).run(foobar, .{}), foobar.rest());
    try expectResultStr(foobar.rest(), ps.peek(any(6)).run(foobar, .{}), foobar.rest());
    try expectResultStr(error.ParseFailure, ps.peek(any(7)).run(foobar, .{}), foobar.rest());
    try expectResultChar(error.ParseFailure, ps.peek(anychar).run(empty, .{}), "");
}

test "skipMany" {
    try testing.expectEqualStrings(
        "",
        ps.skipMany(satisfy(isalpha), .{ .min = 6 }).run(foobar, .{}).input.rest(),
    );
    try testing.expectEqualStrings(
        "bar",
        ps.skipMany(satisfy(isalpha), .{ .max = 3 }).run(foobar, .{}).input.rest(),
    );
    try testing.expectEqual(
        parse_failure,
        ps.skipMany(satisfy(isalpha), .{ .min = 7 }).run(foobar, .{}).output.err,
    );
}

test "asStr" {
    try expectResultStr("a", anychar
        .asStr()
        .run(input("a"), .{}), "");
    try expectResultStr("ab", (comptime seq(.{ char('a'), char('b') })
        .asStr())
        .run(input("ab"), .{}), "");
}

test "ref" {
    const Scope = struct {
        const digit = charRange('0', '9').discard();
        const digits = choice(.{
            seq(.{ digit, ps.ref(digitsRef) }),
            digit,
        });
        fn digitsRef() pk.Parser(pk.Input, void) {
            return digits;
        }
    };

    const r = Scope.digits
        .run(input("00000-"), .{});
    try testing.expectEqual({}, r.output.ok);
    try testing.expectEqualStrings("-", r.input.rest());
}

const Peg = struct {
    const Expr = union(enum) {
        id: []const u8,
        group: []const Expr,
        seq: []const Expr,

        fn id(s: []const u8) Expr {
            return .{ .id = s };
        }
        fn group(es: []const Expr) Expr {
            return if (es.len == 1) es[0] else .{ .group = es };
        }
        fn seq(es: []const Expr) Expr {
            return if (es.len == 1) es[0] else .{ .seq = es };
        }
    };

    const spaces = ps.anycharIn(&.{ ' ', '\n' })
        .skipMany(.{});

    const ident = satisfy(isalpha)
        .takeWhile1()
        .@"<*"(spaces)
        .map(Expr.id);

    const group = seq(.{
        ps.discardSeq(.{ char('('), spaces }),
        ps.ref(exprRef),
        ps.discardSeq(.{ char(')'), spaces }),
    })
        .map(Expr.group);

    const primary = choice(.{ ident, group });

    const seq_ = ps.many1(primary)
        .map(Expr.seq);

    const expr = seq_
        .sepBy1(char('/').discardR(spaces));

    fn exprRef() pk.Parser(pk.Input, []const Expr) {
        return expr;
    }

    const larrow = seq(.{ str("<-"), spaces });

    const ident_larrow = ident
        .@"<*"(larrow);

    const def = seq(.{
        ident_larrow, (expr.many1()
            .discardR(ps.eos))
            .until(ident_larrow),
    });

    const grammar = def
        .many1()
        .discardR(ps.eos);
};

test "simple recursive peg parser" {
    var arena = std.heap.ArenaAllocator.init(talloc);
    defer arena.deinit();
    const r = Peg.grammar.run(input(
        \\a <- b c
        \\d <- e
        \\f <- g (h / (i / j))
    ), .{ .allocator = arena.allocator() });
    try testing.expect(r.output == .ok);
    const ok = r.output.ok;
    try testing.expectEqual(@as(usize, 3), ok.len);
    try testing.expectEqualStrings("a", ok[0][0].id);
    try testing.expectEqualStrings("b", ok[0][1][0][0].seq[0].id);
    try testing.expectEqualStrings("c", ok[0][1][0][0].seq[1].id);
    try testing.expectEqualStrings("d", ok[1][0].id);
    try testing.expectEqualStrings("e", ok[1][1][0][0].id);
    try testing.expectEqualStrings("f", ok[2][0].id);
    try testing.expectEqualStrings("g", ok[2][1][0][0].seq[0].id);
    try testing.expectEqualStrings("h", ok[2][1][0][0].seq[1].group[0].id);
    try testing.expectEqualStrings("i", ok[2][1][0][0].seq[1].group[1].group[0].id);
    try testing.expectEqualStrings("j", ok[2][1][0][0].seq[1].group[1].group[1].id);

    const r2 = Peg.grammar.run(input(
        \\a <- b1
    ), .{ .allocator = arena.allocator() });
    try testing.expect(r2.output == .err);
    try testing.expectEqual(@as(usize, 6), r2.input.index);
}

test "scan" {
    const ident = comptime ps.scan(usize, 0, struct {
        fn func(i: usize, c: u8) ?usize {
            const cont = if (i == 0)
                'a' <= c and c <= 'z'
            else
                ('a' <= c and c <= 'z') or c == '_';
            return if (cont) i + 1 else null;
        }
    }.func);
    {
        const ok = ident.run(input("abc"), .{}).output.ok;
        try testing.expectEqualStrings("abc", ok[0]);
        try testing.expectEqual(@as(?usize, 3), ok[1]);
    }
    {
        const ok = ident.run(input("a_b_c"), .{}).output.ok;
        try testing.expectEqualStrings("a_b_c", ok[0]);
        try testing.expectEqual(@as(?usize, 5), ok[1]);
    }
    {
        const ok = ident.run(input("abc123"), .{}).output.ok;
        try testing.expectEqualStrings("abc", ok[0]);
        try testing.expectEqual(@as(?usize, null), ok[1]);
    }
    {
        const r = ident.run(input("_abc"), .{});
        try testing.expect(r.output == .err);
        try testing.expectEqualStrings(r.input.rest(), "_abc");
    }
}

fn tupArgsWithError(c: u8, s: []const u8) error{Foo}!bool {
    return c == 'f' and mem.eql(u8, s, "oo");
}
fn tupArgsSimple(c: u8, s: []const u8) bool {
    return c == 'f' and mem.eql(u8, s, "oo");
}
fn tupArgsSingle(s: []const u8) bool {
    return mem.eql(u8, s, "oo");
}
test "seqMap" {
    {
        const p = comptime ps.seqMap(.{ char('f'), str("oo") }, tupArgsWithError);
        try testing.expect(p.run(foobar, .{}).output.ok);
    }
    {
        const p = comptime ps.seqMap(.{ char('f'), str("oo") }, tupArgsSimple);
        try testing.expect(p.run(foobar, .{}).output.ok);
    }
    {
        const p = comptime ps.seqMap(.{ char('f').discard(), str("oo") }, tupArgsSingle);
        try testing.expect(p.run(foobar, .{}).output.ok);
    }
}

const Data = struct { file_name: []const u8 };
fn WriteFail(comptime T: type) pk.FailHandler.WriteFn {
    return &struct {
        fn writeFail(
            i: pk.Input,
            typ: pk.Type,
            message: []const u8,
            writer: ?*const anyopaque,
            data: ?*const anyopaque,
        ) void {
            const w = @as(
                *const T,
                @alignCast(@ptrCast(writer)),
            );
            const ud = @as(*const Data, @alignCast(@ptrCast(data)));
            if (message.len > 0)
                w.print(
                    "{s}::{} in {s}: {s}\n",
                    .{ ud.file_name, i.index, @tagName(typ), message },
                ) catch unreachable
            else
                w.print(
                    "{s}::{} in {s}\n",
                    .{ ud.file_name, i.index, @tagName(typ) },
                ) catch unreachable;
        }
    }.writeFail;
}

test "onFail at runtime" {
    var buf: [100]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();
    const data = Data{ .file_name = "file.zig" };
    const writeFn = WriteFail(std.io.FixedBufferStream([]u8).Writer);
    const fail_handler = pk.FailHandler.init(&writer, writeFn, &data);
    // note how the comptime portion of the parser is separated from
    // onFail() which is a runtime operation. this can be changed by declaring
    // 'pub const runtime = .@"comptime";'
    const p = char('a').onFail(fail_handler);
    const r = p.run(empty, .{});
    try testing.expectEqual(parse_failure, r.output.err);
    try testing.expectEqualStrings("file.zig::0 in char\n", fbs.getWritten());
}
