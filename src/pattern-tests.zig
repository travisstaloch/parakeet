const std = @import("std");
const testing = std.testing;
const pk = @import("parakeet");
const peg = pk.peg;
const Expr = peg.Expr;
const talloc = testing.allocator;

test "pattern with negated character classes" {
    var arena = std.heap.ArenaAllocator.init(talloc);
    defer arena.deinit();
    const input =
        \\line_comment <- '//' ![!/][^\n]* / '////' [^\n]*
        \\skip <- ([ \n] / line_comment)*
        \\hex <- [0-9a-fA-F]
        \\char_escape
        \\    <- "\\x" hex hex
        \\     / "\\u{" hex+ "}"
        \\     / "\\" [nr\\t'"]
        \\string_char
        \\    <- char_escape
        \\     / [^\\"\n]
        \\STRINGLITERALSINGLE <- "\"" string_char* "\"" skip
    ;
    const g = try pk.peg.parseString(pk.peg.parsers.grammar, input, arena.allocator());
    const Ctx = pk.pattern.ParseContext(void);
    var ctx = try Ctx.init(.{ .allocator = arena.allocator() }, g);
    const r = pk.pattern.parse(Ctx, &ctx, 5,
        \\"str"
    );
    try testing.expect(r.output == .ok);
    try testing.expectEqualStrings(
        \\"str"
    , r.input.s[r.output.ok[0]..r.output.ok[1]]);
}

test "negated char class matches not char class" {
    const input =
        \\a <- [A-Za-z0-9_]
        \\b <- [^A-Za-z0-9_]
        \\c <- ![A-Za-z0-9_]
    ;

    const expecteds = .{
        .{ "a", .err },
        .{ "z", .err },
        .{ "A", .err },
        .{ "Z", .err },
        .{ "_", .err },
        .{ ".", .ok },
        .{ "\x00", .ok },
        .{ "\xff", .ok },
    };

    var arena = std.heap.ArenaAllocator.init(talloc);
    defer arena.deinit();

    const g = try pk.peg.parseString(pk.peg.parsers.grammar, input, arena.allocator());
    const Ctx = pk.pattern.ParseContext(void);
    var ctx = try Ctx.init(.{ .allocator = arena.allocator() }, g);

    inline for (expecteds) |expected| {
        {
            var ra: pk.pattern.Result = undefined;
            ctx.input = pk.input(expected[0]);
            ctx.rules[0].pattern.run(Ctx, &ctx, &ra);
            // std.debug.print("negated={} r={} expected=({s},{})\n", .{ negated, r, expected[0], expected[1] });
            try testing.expect((ra.output != expected[1]));
        }
        {
            var rb: pk.pattern.Result = undefined;
            ctx.input = pk.input(expected[0]);
            ctx.rules[1].pattern.run(Ctx, &ctx, &rb);
            try testing.expect((rb.output == expected[1]));
        }
        {
            var rc: pk.pattern.Result = undefined;
            ctx.input = pk.input(expected[0]);
            ctx.rules[2].pattern.run(Ctx, &ctx, &rc);
            try testing.expect((rc.output == expected[1]));
        }
    }
}

fn expectFormat(expected: []const u8, comptime fmt: []const u8, args: anytype) !void {
    const actual = try std.fmt.allocPrint(talloc, fmt, args);
    defer talloc.free(actual);
    try testing.expectEqualStrings(expected, actual);
}

test "invalid char class" {
    const maybeNegate = peg.parsers.maybeNegate;
    // should error when over 1/2 or 0 bits are set
    var bitset = Expr.Class.Set.initFull();
    try testing.expectError(error.InvalidCharacterClass, maybeNegate(false, bitset));
    try testing.expectError(error.InvalidCharacterClass, maybeNegate(true, bitset));
    bitset.masks[0] = 0;
    bitset.masks[1] = 1;
    try testing.expectError(error.InvalidCharacterClass, maybeNegate(false, bitset));
    try testing.expectError(error.InvalidCharacterClass, maybeNegate(true, bitset));
    bitset.masks[1] = 0;
    _ = try maybeNegate(false, bitset);
    _ = try maybeNegate(true, bitset);
    bitset.masks[2] = 0;
    bitset.masks[3] = 1;
    _ = try maybeNegate(false, bitset);
    _ = try maybeNegate(true, bitset);
    bitset.masks[3] = 0;
    try testing.expectError(error.InvalidCharacterClass, maybeNegate(false, bitset));
    try testing.expectError(error.InvalidCharacterClass, maybeNegate(true, bitset));
}

test "pattern optimizations" {
    {
        const input =
            \\eos <- !.             # => .eos
            \\a   <- "a" / [bc-e]   # => [a-e]
            \\b   <- b c / b d      # => b (c / d)
            \\c   <- 'c'
            \\d   <- 'd'
        ;
        var arena = std.heap.ArenaAllocator.init(talloc);
        defer arena.deinit();
        const g = try pk.peg.parseString(pk.peg.parsers.grammar, input, arena.allocator());
        const Ctx = pk.pattern.ParseContext(void);
        var ctx = try Ctx.init(.{ .allocator = arena.allocator() }, g);

        try testing.expectEqual(pk.pattern.Pattern.Tag.eos, ctx.rules[0].pattern);

        {
            const p = ctx.rules[1].pattern;
            try testing.expect(p == .class);
            try expectFormat("[a-e]", "{}", .{p.class});
        }
        {
            const p = ctx.rules[2].pattern;
            try testing.expect(p == .seq);
            try expectFormat("2 ( 3 / 4 )", "{}", .{p});
        }
    }
}

test "first sets and nullability" {
    // example is from https://holub.com/goodies/compiler/compilerDesignInC.pdf
    // section 4.7.1
    const input =
        \\stmt <- expr ';'
        \\expr <- term expr2 /
        \\expr2 <- '+' term expr2 /
        \\term <- factor term2
        \\term2 <- '*' factor term2 /
        \\factor <- '(' expr ')' / [0-9]
    ;

    var arena = std.heap.ArenaAllocator.init(talloc);
    defer arena.deinit();
    const g = try pk.peg.parseString(pk.peg.parsers.grammar, input, arena.allocator());
    const Ctx = pk.pattern.ParseContext(void);
    var ctx = try Ctx.init(.{ .allocator = arena.allocator() }, g);
    const rules = ctx.rules;
    try expectFormat("[(0-9;]", "{}", .{rules[0].first_set}); // stmt
    try testing.expect(rules[0].nullability == .non_nullable);
    try expectFormat("[(0-9]", "{}", .{rules[1].first_set}); // expr
    try testing.expect(rules[1].nullability == .nullable);
    try expectFormat("[+]", "{}", .{rules[2].first_set}); // expr2
    try testing.expect(rules[2].nullability == .nullable);
    try expectFormat("[(0-9]", "{}", .{rules[3].first_set}); // term
    try testing.expect(rules[3].nullability == .non_nullable);
    try expectFormat("[*]", "{}", .{rules[4].first_set}); // term2
    try testing.expect(rules[4].nullability == .nullable);
    try expectFormat("[(0-9]", "{}", .{rules[5].first_set}); // factor
    try testing.expect(rules[5].nullability == .non_nullable);
}

test "basic captures" {
    const input =
        \\S   <- foo bar
        \\foo <- { "foo" }
        \\bar <- { "bar" }
    ;
    var arena = std.heap.ArenaAllocator.init(talloc);
    defer arena.deinit();
    const CaptureHandler = struct {
        captures: std.ArrayListUnmanaged([]const u8) = .{},
        allocator: std.mem.Allocator,
        pub fn onCapture(self: *@This(), capid: u32, cap: []const u8) !void {
            _ = capid;
            // std.debug.print("text={s}\n", .{cap});
            try self.captures.append(self.allocator, cap);
        }
    };
    var handler = CaptureHandler{ .allocator = arena.allocator() };
    const Ctx = pk.pattern.ParseContext(CaptureHandler);
    const g = try pk.peg.parseString(pk.peg.parsers.grammar, input, arena.allocator());
    var ctx = try Ctx.init(.{
        .allocator = arena.allocator(),
        .capture_handler = &handler,
    }, g);

    const r = pk.pattern.parse(Ctx, &ctx, 0, "foobar");
    try testing.expect(r.output == .ok);
    try testing.expectEqualStrings("foo", handler.captures.items[0]);
    try testing.expectEqualStrings("bar", handler.captures.items[1]);
}
