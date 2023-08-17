const std = @import("std");
const testing = std.testing;
const pk = @import("parakeet");
const Pattern = pk.pattern.Pattern;
const peg = pk.peg;
const Expr = peg.Expr;
const talloc = testing.allocator;

test "pattern with negated character classes" {
    const Class = Expr.Class;
    // zig fmt: off
    const G = struct{
        pub const NonTerminal = enum { line_comment, skip, hex, char_escape, string_char, STRINGLITERALSINGLE };
        pub const Rule = pk.pattern.Rule(NonTerminal, Pattern);
        pub const rules = [_]Rule{
            Rule.init(.line_comment, Pattern.alt(&.{Pattern.seq(&.{Pattern.literal("//"), Pattern.not(&Pattern.class(&Class.init(&.{.{.one='!'}, .{.one='/'}, }))), Pattern.many(&Pattern.class(&Class.init(&.{.{.one = '^'},.{.one='\n'}, }))), }), Pattern.seq(&.{Pattern.literal("////"), Pattern.many(&Pattern.class(&Class.init(&.{.{.one = '^'},.{.one='\n'}, }))), }), })),
            Rule.init(.skip, Pattern.many(&Pattern.alt(&.{Pattern.class(&Class.init(&.{.{.one='\n'}, .{.one=' '}, })), Rule.nonterm(.line_comment), }))),
            Rule.init(.hex, Pattern.class(&Class.init(&.{.{.range=.{'0', '9'}}, }))),
            Rule.init(.char_escape, Pattern.alt(&.{Pattern.seq(&.{Pattern.literal("\\x"), Rule.nonterm(.hex), Rule.nonterm(.hex), }), Pattern.seq(&.{Pattern.literal("\\u{"), Pattern.seq(&.{Rule.nonterm(.hex), Pattern.many(&Rule.nonterm(.hex))}), Pattern.literal("}"), }), Pattern.seq(&.{Pattern.literal("\\"), Pattern.class(&Class.init(&.{.{.one='"'}, .{.one='\''}, })), }), })),
            Rule.init(.string_char, Pattern.alt(&.{Rule.nonterm(.char_escape), Pattern.class(&Class.init(&.{.{.one = '^'},.{.one='\n'}, .{.one='"'}, })), })),
            Rule.init(.STRINGLITERALSINGLE, Pattern.seq(&.{Pattern.literal("\""), Pattern.many(&Rule.nonterm(.string_char)), Pattern.literal("\""), Rule.nonterm(.skip), })),
        };
    };
    // zig fmt: on
    var arena = std.heap.ArenaAllocator.init(talloc);
    defer arena.deinit();
    const Ctx = pk.pattern.ParseContext(G, void);
    var ctx = try Ctx.init(.{ .allocator = arena.allocator() });
    const r = Pattern.parse(Ctx, &ctx, @intFromEnum(G.NonTerminal.STRINGLITERALSINGLE),
        \\"str"
    );
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
            pub const rules = [_]Rule{ Rule.init(.c, p), Rule.init(.d, not_pat) };
        };

        var arena = std.heap.ArenaAllocator.init(talloc);
        defer arena.deinit();
        const Ctx = pk.pattern.ParseContext(G, void);
        var ctx = try Ctx.init(.{ .allocator = arena.allocator() });
        inline for (expecteds) |expected| {
            var r: pk.pattern.Result = undefined;
            ctx.input = pk.input(expected[0]);
            ctx.rule_id = 0;
            ctx.rules[0].pattern.run(Ctx, &ctx, &r);
            // std.debug.print("negated={} r={} expected=({s},{})\n", .{ negated, r, expected[0], expected[1] });
            try testing.expect((r.output == expected[1]) == negated);
            ctx.input = pk.input(expected[0]);
            ctx.rule_id = 0;
            ctx.rules[1].pattern.run(Ctx, &ctx, &r);
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
            pub const rules = [_]Rule{Rule.init(.a, Pattern.alt(&.{
                Pattern.literal("a"),
                Pattern.class(&Expr.Class.init(&.{ .{ .one = 'b' }, .{ .range = .{ 'c', 'e' } } })),
            }))};
        };
        var arena = std.heap.ArenaAllocator.init(talloc);
        defer arena.deinit();
        const rules = try Pattern.optimize(G, arena.allocator(), .optimized);
        const p = rules[0].pattern;
        try testing.expect(p == .class);
        try expectFormat("[a-e]", "{}", .{p.class});
    }
    { // a b / a c => a (b / c)
        const G = struct {
            pub const NonTerminal = enum { a, b, c };
            pub const Rule = pk.pattern.Rule(NonTerminal, Pattern);
            pub const rules = [_]Rule{
                Rule.init(.a, Pattern.alt(&.{
                    Pattern.seq(&.{ Rule.nonterm(.a), Rule.nonterm(.b) }),
                    Pattern.seq(&.{ Rule.nonterm(.a), Rule.nonterm(.c) }),
                })),
                Rule.init(.b, .empty),
                Rule.init(.c, .empty),
            };
        };
        var arena = std.heap.ArenaAllocator.init(talloc);
        defer arena.deinit();
        const rules = try Pattern.optimize(G, arena.allocator(), .optimized);
        const p = rules[0].pattern;
        try testing.expect(p == .seq);
        try expectFormat("0 ( 1 / 2 )", "{}", .{p});
    }
}

test "first sets and nullability" {
    // example is from https://holub.com/goodies/compiler/compilerDesignInC.pdf
    // section 4.7.1
    const G = struct {
        pub const NonTerminal = enum { stmt, expr, expr2, term, term2, factor };
        pub const Rule = pk.pattern.Rule(NonTerminal, Pattern);
        // zig fmt: off
        pub const rules = [_]Rule{
            // stmt <- expr ';'
            Rule.init(.stmt,  Pattern.seq(&.{  Rule.nonterm(.expr), Pattern.literal(";") })),
            // expr <- term expr2 /
            Rule.init(.expr, Pattern.alt(&.{ Pattern.seq(&.{  Rule.nonterm(.term), Rule.nonterm(.expr2) }), .empty })),
            // expr2 <- '+' term expr2 /
            Rule.init(.expr2, Pattern.alt(&.{ Pattern.seq(&.{ Pattern.literal("+"),  Rule.nonterm(.term), Rule.nonterm(.expr2) }), .empty })),
            // term <- factor term2
            Rule.init(.term, Pattern.seq(&.{  Rule.nonterm(.factor), Rule.nonterm(.term2) })),
            // term2 <- '*' factor term2 /
            Rule.init(.term2, Pattern.alt(&.{ Pattern.seq(&.{ Pattern.literal("*"),  Rule.nonterm(.factor), Rule.nonterm(.term2) }), .empty })),
            // factor <- '(' expr ')' / [0-9]
            Rule.init(.factor, Pattern.alt(&.{ Pattern.seq(&.{  Pattern.literal("("), Rule.nonterm(.expr), Pattern.literal(")") }), Pattern.class(&Expr.Class.init( &.{.{.range = .{'0', '9' }}})) })),
        };
        // zig fmt: on
    };
    var arena = std.heap.ArenaAllocator.init(talloc);
    defer arena.deinit();
    const rules = try Pattern.optimize(G, arena.allocator(), .optimized);
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
    const G = struct {
        pub const NonTerminal = enum { S, foo, bar };
        pub const Rule = pk.pattern.Rule(NonTerminal, Pattern);
        pub const rules = [_]Rule{
            Rule.init(.S, Pattern.seq(&.{ Rule.nonterm(.foo), Rule.nonterm(.bar) })),
            Rule.init(.foo, Pattern.capture(&Pattern.literal("foo"), 0)),
            Rule.init(.bar, Pattern.capture(&Pattern.literal("bar"), 1)),
        };
    };
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
    const Ctx = pk.pattern.ParseContext(G, CaptureHandler);
    var ctx = try Ctx.init(.{
        .allocator = arena.allocator(),
        .capture_handler = &handler,
    });
    const r = Pattern.parse(Ctx, &ctx, @intFromEnum(G.NonTerminal.S), "foobar");
    try testing.expect(r.output == .ok);
    try testing.expectEqualStrings("foo", handler.captures.items[0]);
    try testing.expectEqualStrings("bar", handler.captures.items[1]);
}
