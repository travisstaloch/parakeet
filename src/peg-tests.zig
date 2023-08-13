const std = @import("std");
const testing = std.testing;
const pk = @import("parakeet");
const peg = pk.peg;
const parseString = peg.parseString;
const Peg = @import("peg-parsers.zig");
const Pattern = peg.Pattern;

const talloc = testing.allocator;
// var gpa = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 40 }){};
// const talloc = gpa.allocator();

fn checkStr(p: anytype, in: []const u8, expected: []const u8) !void {
    const e = try parseString(p, in, talloc);
    try testing.expectEqualStrings(expected, e);
}

fn check(p: anytype, in: []const u8, expected: []const u8) !void {
    // std.debug.print("check in={s} expected={s}\n", .{ in, expected });
    const e = try parseString(p, in, talloc);
    defer e.deinit(talloc);
    var buf: [0x100]u8 = undefined;
    try testing.expectEqualStrings(
        expected,
        try std.fmt.bufPrint(&buf, "{}", .{e}),
    );
}

fn checkSame(p: anytype, in: []const u8) !void {
    return check(p, in, in);
}

test "peg expression" {
    try testing.expectError(error.ParseFailure, checkSame(Peg.ident, "_"));
    try testing.expectError(error.ParseFailure, checkSame(Peg.ident, ""));
    try checkSame(Peg.expression, "id1");
    try checkSame(Peg.expression, "id1?");
    try checkSame(Peg.expression, "id1*");
    try checkSame(Peg.expression, "id1+");
    try checkSame(Peg.expression, "&id1");
    try checkSame(Peg.expression, "!id1");
    try checkSame(Peg.expression, "&id1?");
    try check(Peg.expression, "( id1 )", "id1");
    try check(Peg.expression, "( id1 )*", "id1*");
    try checkSame(Peg.expression, "id1 ( id1 / id3 )*");
    try check(Peg.expression, "( &id1? )", "&id1?");
    try checkSame(Peg.expression, "id1 id2");
    try checkSame(Peg.expression, "id1\n    / id2");
    try checkSame(Peg.expression, "id1\n    / id2 id3");
    try checkSame(Peg.expression, "id1\n    / ( id2 / id3 )");
    try checkSame(Peg.expression, ".");
    try checkSame(Peg.expression, "[a] F");
    try checkSame(Peg.expression,
        \\"\\x" hex hex
        \\    / "\\u{" hex+ "}"
        \\    / "\\" ["'\\nrt]
    );
    // group with a single child doesn't need to be grouped
    try check(Peg.expression, "( !Prefix )*", "!Prefix*");
    // memo nodes
    try checkSame(Peg.expression, "{{ a }}");
    try checkSame(Peg.expression, "{{ a }}*");
    try check(Peg.expression, "( {{ a }} )*", "{{ a }}*");
}

test "peg string literal" {
    try checkSame(Peg.expression,
        \\"s"
    );
    try checkSame(Peg.expression,
        \\"\""
    );
    try checkSame(Peg.expression,
        \\"\n"
    );
    try checkSame(Peg.expression,
        \\'s'
    );
    try checkSame(Peg.expression,
        \\'\''
    );
    try checkSame(Peg.expression,
        \\'\n'
    );
    try checkSame(Peg.expression,
        \\'\\'
    );
    try testing.expectError(error.ParseFailure, checkSame(Peg.expression,
        \\""
    ));
    try testing.expectError(error.ParseFailure, checkSame(Peg.expression,
        \\''
    ));
    try testing.expectError(error.ParseFailure, checkSame(Peg.expression,
        \\'a
    ));
    try testing.expectError(error.ParseFailure, checkSame(Peg.expression,
        \\"a
    ));
    try testing.expectError(error.ParseFailure, checkSame(Peg.expression,
        \\[a
    ));
}

test "peg character class" {
    try checkSame(Peg.expression, "[a]");
    try checkSame(Peg.expression, "[a-z]");
    try checkSame(Peg.expression, "[A-Za-z]");
    try checkSame(Peg.expression, "[\\-]");
    try checkSame(Peg.expression, "[\\t]");
    try checkSame(Peg.expression,
        \\[+\-]
    );
    try check(Peg.expression,
        \\[\010]
    , "[\\b]");
    try checkSame(Peg.expression, "[\\\\]");
    try checkSame(Peg.expression, "[\\[\\]]");
    try checkSame(Peg.expression, "[0-9]+");
    try checkSame(Peg.expression,
        \\[\200-\277]
    );
    try testing.expectError(
        error.ParseFailure,
        checkSame(Peg.expression, "[]"),
    );
    try checkSame(Peg.expression,
        \\["'\\nrt]
    );
    try checkSame(Peg.expression, "[0-9A-Z_a-z]");
    try checkSame(Peg.expression,
        \\[^\n"\\]
    );
    try checkSame(Peg.expression, "[\\^a-z]");
}

test "peg misc" {
    try checkStr(Peg.comment, "# comment \n", " comment ");
}

test "peg def" {
    const d = try parseString(Peg.def, "a <- b c", talloc);
    defer d[1].deinit(talloc);
    try testing.expectEqualStrings("a", d[0]);
    try testing.expectEqual(@as(usize, 2), d[1].seq.len);
    try testing.expectEqualStrings("b", d[1].seq[0].ident);
    try testing.expectEqualStrings("c", d[1].seq[1].ident);
}

test "peg grammar" {
    const g = try parseString(Peg.grammar, "a <- b c d <- e", talloc);
    defer g.deinit(talloc);
    try testing.expectEqual(@as(usize, 2), g.grammar.len);
    try testing.expectEqualStrings("a", g.grammar[0][0]);
    try testing.expectEqualStrings("d", g.grammar[1][0]);

    try checkSame(Peg.grammar, "a <- b c\nd <- e");
    try checkSame(Peg.grammar, "Expr <- Factor ( [+\\-] Factor )*");
    try checkSame(Peg.grammar,
        \\Expr <- Factor ( [+\-] Factor )*
        \\Factor <- Term ( [*/] Term )*
    );
    try check(Peg.grammar,
        \\Sequence <-
        \\      Prefix ( Prefix )*
        \\    / 
    ,
        \\Sequence <-
        \\      Prefix Prefix*
        \\    / 
    );
    try checkSame(Peg.grammar,
        \\char_escape <-
        \\      "\\x" hex hex
        \\    / "\\u{" hex+ "}"
        \\    / "\\" ["'\\nrt]
        \\char_char <-
        \\      mb_utf8_literal
        \\    / char_escape
        \\    / ascii_char_not_nl_slash_squote
    );
}

// TODO move to pattern-test.zig
test "pattern with negated character classes" {
    const Class = pk.peg.Expr.Class;
    // zig fmt: off
    const G = struct{
        pub const NonTerminal = enum { line_comment, skip, hex, char_escape, string_char, STRINGLITERALSINGLE };
        pub const Rule = pk.peg.Rule(NonTerminal, Pattern);
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
    const _pat = comptime Pattern.class(&pk.peg.Expr.Class.init(&.{
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
            pub const Rule = pk.peg.Rule(NonTerminal, Pattern);
            pub const rules = [_]Rule{ .{ .c, p }, .{ .d, not_pat } };
        };

        var arena = std.heap.ArenaAllocator.init(talloc);
        defer arena.deinit();
        const rules = try Pattern.optimize(G, arena.allocator(), .optimized);

        inline for (expecteds) |expected| {
            const Ctx = pk.peg.RunCtx;
            var ctx = Ctx.init(pk.input(expected[0]), 0, talloc);
            var r: pk.peg.Result = undefined;
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
    // should error when over 1/2 or 0 bits are set
    var bitset = peg.Expr.Class.Set.initFull();
    try testing.expectError(error.InvalidCharacterClass, Peg.maybeNegate(false, bitset));
    try testing.expectError(error.InvalidCharacterClass, Peg.maybeNegate(true, bitset));
    bitset.masks[0] = 0;
    bitset.masks[1] = 1;
    try testing.expectError(error.InvalidCharacterClass, Peg.maybeNegate(false, bitset));
    try testing.expectError(error.InvalidCharacterClass, Peg.maybeNegate(true, bitset));
    bitset.masks[1] = 0;
    _ = try Peg.maybeNegate(false, bitset);
    _ = try Peg.maybeNegate(true, bitset);
    bitset.masks[2] = 0;
    bitset.masks[3] = 1;
    _ = try Peg.maybeNegate(false, bitset);
    _ = try Peg.maybeNegate(true, bitset);
    bitset.masks[3] = 0;
    try testing.expectError(error.InvalidCharacterClass, Peg.maybeNegate(false, bitset));
    try testing.expectError(error.InvalidCharacterClass, Peg.maybeNegate(true, bitset));
}

test "pattern optimizations" {
    // !. => .eos
    try testing.expectEqual(Pattern.Tag.eos, comptime Pattern.not(&Pattern.dot()));
    { // "a" / [bc-e] => [a-e]
        const G = struct {
            pub const NonTerminal = enum { a };
            pub const Rule = pk.peg.Rule(NonTerminal, Pattern);
            pub const rules = [_]Rule{.{ .a, Pattern.alt(&.{
                Pattern.literal("a"),
                Pattern.class(&peg.Expr.Class.init(&.{ .{ .one = 'b' }, .{ .range = .{ 'c', 'e' } } })),
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
            pub const Rule = pk.peg.Rule(NonTerminal, Pattern);
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
