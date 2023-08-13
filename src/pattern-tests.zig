const std = @import("std");
const testing = std.testing;
const pk = @import("parakeet");
const Pattern = pk.pattern.Pattern;
const peg = pk.peg;
const Expr = peg.Expr;
const talloc = testing.allocator;

// TODO move to pattern-test.zig
test "pattern with negated character classes" {
    const Class = Expr.Class;
    // zig fmt: off
    const G = struct{
        pub const NonTerminal = enum { line_comment, skip, hex, char_escape, string_char, STRINGLITERALSINGLE };
        pub const Rule = pk.pattern.Rule(NonTerminal, Pattern);
        pub const rules = [_]Rule{
            .{ .line_comment, Pattern.alt(&.{Pattern.seq(&.{Pattern.literal("//"), Pattern.not(&Pattern.class(&Class.init(&.{.{.one='!'}, .{.one='/'}, }))), Pattern.many(&Pattern.class(&Class.init(&.{.{.one = '^'},.{.one='\n'}, }))), }), Pattern.seq(&.{Pattern.literal("////"), Pattern.many(&Pattern.class(&Class.init(&.{.{.one = '^'},.{.one='\n'}, }))), }), })},
            .{ .skip, Pattern.many(&Pattern.group(&Pattern.alt(&.{Pattern.class(&Class.init(&.{.{.one='\n'}, .{.one=' '}, })), Pattern.nonterm(@intFromEnum(NonTerminal.line_comment)), })))},
            .{ .hex, Pattern.class(&Class.init(&.{.{.range=.{'0', '9'}}, }))},
            .{ .char_escape, Pattern.alt(&.{Pattern.seq(&.{Pattern.literal("\\x"), Pattern.nonterm(@intFromEnum(NonTerminal.hex)), Pattern.nonterm(@intFromEnum(NonTerminal.hex)), }), Pattern.seq(&.{Pattern.literal("\\u{"), Pattern.plus(&Pattern.nonterm(@intFromEnum(NonTerminal.hex))), Pattern.literal("}"), }), Pattern.seq(&.{Pattern.literal("\\"), Pattern.class(&Class.init(&.{.{.one='"'}, .{.one='\''}, })), }), })},
            .{ .string_char, Pattern.alt(&.{Pattern.nonterm(@intFromEnum(NonTerminal.char_escape)), Pattern.class(&Class.init(&.{.{.one = '^'},.{.one='\n'}, .{.one='"'}, })), })},
            .{ .STRINGLITERALSINGLE, Pattern.seq(&.{Pattern.literal("\""), Pattern.many(&Pattern.nonterm(@intFromEnum(NonTerminal.string_char))), Pattern.literal("\""), Pattern.nonterm(@intFromEnum(NonTerminal.skip)), })},
        };
    };
    // zig fmt: on
    const r = Pattern.parse(G, @intFromEnum(G.NonTerminal.STRINGLITERALSINGLE),
        \\"str"
    , .{ .allocator = talloc }, .optimized);
    try testing.expect(r.output == .ok);
    try testing.expectEqualStrings(
        \\"str"
    , r.input.s[r.output.ok[0]..r.output.ok[1]]);
}

test "negated char class matches not char class" {
    const _pat = comptime Pattern.class(&Expr.Class.init(&.{
        .{ .range = .{ 'a', 'z' } },
        .{ .range = .{ 'A', 'Z' } },
        .{ .range = .{ '0', '9' } },
        .{ .one = '_' },
    }));
    inline for (.{ true, false }) |negated| {
        const p = comptime Pattern.class(&.{
            .bitset = if (negated)
                _pat.class.bitset.complement()
            else
                _pat.class.bitset,
        });
        const not_pat = if (negated)
            comptime Pattern.not(&_pat)
        else
            _pat;

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
        const G = struct {
            pub const NonTerminal = enum { c, d };
            pub const Rule = pk.pattern.Rule(NonTerminal, Pattern);
            pub const rules = [_]Rule{ .{ .c, p }, .{ .d, not_pat } };
        };

        var arena = std.heap.ArenaAllocator.init(talloc);
        defer arena.deinit();
        const rules = try Pattern.optimize(G, arena.allocator(), .optimized);

        inline for (expecteds) |expected| {
            const Ctx = pk.pattern.RunCtx;
            var ctx = Ctx.init(pk.input(expected[0]), 0, talloc);
            var r: pk.pattern.Result = undefined;
            rules[0][1].run(G, rules, &ctx, &r);
            // std.debug.print("negated={} r={} expected=({s},{})\n", .{ negated, r, expected[0], expected[1] });
            try testing.expect((r.output == expected[1]) == negated);
            var ctx2 = Ctx.init(pk.input(expected[0]), 0, talloc);
            rules[1][1].run(G, rules, &ctx2, &r);
            try testing.expect((r.output == expected[1]) == negated);
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
    // !. => .eos
    try testing.expectEqual(Pattern.Tag.eos, comptime Pattern.not(&Pattern.dot()));
    { // "a" / [bc-e] => [a-e]
        const G = struct {
            pub const NonTerminal = enum { a };
            pub const Rule = pk.pattern.Rule(NonTerminal, Pattern);
            pub const rules = [_]Rule{.{ .a, Pattern.alt(&.{
                Pattern.literal("a"),
                Pattern.class(&Expr.Class.init(&.{ .{ .one = 'b' }, .{ .range = .{ 'c', 'e' } } })),
            }) }};
        };
        var arena = std.heap.ArenaAllocator.init(talloc);
        defer arena.deinit();
        const rules = try Pattern.optimize(G, arena.allocator(), .optimized);
        const p = rules[0][1];
        try testing.expect(p == .class);
        try expectFormat("[a-e]", "{}", .{p.class});
    }
    { // a c / b c => (a / b) c
        const G = struct {
            pub const NonTerminal = enum { a, b, c };
            pub const Rule = pk.pattern.Rule(NonTerminal, Pattern);
            pub const rules = [_]Rule{.{ .a, Pattern.alt(&.{
                Pattern.seq(&.{ Pattern.nonterm(@intFromEnum(NonTerminal.a)), Pattern.nonterm(@intFromEnum(NonTerminal.c)) }),
                Pattern.seq(&.{ Pattern.nonterm(@intFromEnum(NonTerminal.b)), Pattern.nonterm(@intFromEnum(NonTerminal.c)) }),
            }) }};
        };
        var arena = std.heap.ArenaAllocator.init(talloc);
        defer arena.deinit();
        const rules = try Pattern.optimize(G, arena.allocator(), .optimized);
        const p = rules[0][1];
        try testing.expect(p == .seq);
        try expectFormat("( 0 / 1 ) 2", "{}", .{p});
    }
}
