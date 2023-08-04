const std = @import("std");
const testing = std.testing;
const pk = @import("parakeet");
const peg = pk.peg;
const parseString = peg.parseString;
const Peg = @import("peg-parsers.zig");

const talloc = testing.allocator;

fn checkStr(p: anytype, in: []const u8, expected: []const u8) !void {
    const e = try parseString(p, in, talloc);
    try testing.expectEqualStrings(expected, e);
}

fn check(p: anytype, in: []const u8, expected: []const u8) !void {
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
    try checkSame(Peg.expression, "( id1 )");
    try checkSame(Peg.expression, "( id1 )*");
    try checkSame(Peg.expression, "id1 ( id1 / id3 )*");
    try checkSame(Peg.expression, "( &id1? )");
    try checkSame(Peg.expression, "id1 id2");
    try checkSame(Peg.expression, "id1\n    / id2");
    try checkSame(Peg.expression, "id1\n    / id2 id3");
    try checkSame(Peg.expression, "id1\n    / ( id2 / id3 )");
    try checkSame(Peg.expression, ".");
    try checkSame(Peg.expression, "[a] F");
    try checkSame(Peg.expression,
        \\"\\x" hex hex
        \\    / "\\u{" hex+ "}"
        \\    / "\\" [nr\\t'"]
    );
    // groups with a single child don't need to be grouped
    try check(Peg.expression, "( !Prefix )*", "!Prefix*");
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
    try checkSame(Peg.expression, "[a-zA-Z]");
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
        \\    / "\\" [nr\\t'"]
        \\char_char <-
        \\      mb_utf8_literal
        \\    / char_escape
        \\    / ascii_char_not_nl_slash_squote
    );
}

// TODO move to pattern-test.zig
test "pattern with negated character classes" {
    const pat = pk.peg.Pattern;
    const rules_ast = comptime &.{
        .{ "line_comment", pat.alt(&.{
            pat.seq(&.{
                pat.literal("//"),
                pat.not(&pat.class(.{ .sets = &.{
                    .{ .one = '!' },
                    .{ .one = '/' },
                } })),
                pat.many(&pat.class(.{ .sets = &.{
                    .{ .one = '\n' },
                }, .negated = true })),
            }),
            pat.seq(&.{
                pat.literal("////"),
                pat.many(&pat.class(.{ .sets = &.{
                    .{ .one = '\n' },
                }, .negated = true })),
            }),
        }) },
        .{ "skip", pat.many(&pat.group(&pat.alt(&.{
            pat.class(.{ .sets = &.{
                .{ .one = ' ' },
                .{ .one = '\n' },
            } }),
            pat.nonterm("line_comment"),
        }))) },
        .{ "hex", pat.class(.{ .sets = &.{
            .{ .range = .{ '0', '9' } },
            .{ .range = .{ 'a', 'f' } },
            .{ .range = .{ 'A', 'F' } },
        } }) },
        .{ "char_escape", pat.alt(&.{
            pat.seq(&.{
                pat.literal("\\x"),
                pat.nonterm("hex"),
                pat.nonterm("hex"),
            }),
            pat.seq(&.{
                pat.literal("\\u{"),
                pat.plus(&pat.nonterm("hex")),
                pat.literal("}"),
            }),
            pat.seq(&.{
                pat.literal("\\"),
                pat.class(.{ .sets = &.{
                    .{ .one = 'n' },
                    .{ .one = 'r' },
                    .{ .one = '\\' },
                    .{ .one = 't' },
                    .{ .one = '\'' },
                    .{ .one = '"' },
                } }),
            }),
        }) },
        .{ "string_char", pat.alt(&.{
            pat.nonterm("char_escape"),
            pat.class(.{ .sets = &.{
                .{ .one = '\\' },
                .{ .one = '"' },
                .{ .one = '\n' },
            }, .negated = true }),
        }) },
        .{ "STRINGLITERALSINGLE", pat.seq(&.{
            pat.literal("\""),
            pat.many(&pat.nonterm("string_char")),
            pat.literal("\""),
            pat.nonterm("skip"),
        }) },
    };

    const rules = std.ComptimeStringMap(pk.peg.Pattern, rules_ast);
    const r = pk.peg.Pattern.parse(&rules, "STRINGLITERALSINGLE",
        \\"str"
    , .{});
    try testing.expect(r.output == .ok);
    try testing.expectEqualStrings(
        \\"str"
    , r.output.ok);
}

test "negated char class matches not char class" {
    const _pat = comptime pk.peg.Pattern.class(.{
        .sets = &.{
            .{ .range = .{ 'a', 'z' } },
            .{ .range = .{ 'A', 'Z' } },
            .{ .range = .{ '0', '9' } },
            .{ .one = '_' },
        },
    });
    inline for (.{ true, false }) |negated| {
        const pat = comptime pk.peg.Pattern.class(.{
            .negated = negated,
            .sets = _pat.class.sets,
        });
        const not_pat = if (negated)
            comptime pk.peg.Pattern.not(&_pat)
        else
            _pat;

        const rules = std.ComptimeStringMap(pk.peg.Pattern, .{.{ "c", pat }});
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
        inline for (expecteds) |expected| {
            const r = pat.run(rules, "", pk.input(expected[0]), .{});
            // std.debug.print("negated={} r={} expected={}\n", .{ negated, r, expected });
            try testing.expect((r.output == expected[1]) == negated);
            const r2 = not_pat.run(rules, "", pk.input(expected[0]), .{});
            try testing.expect((r2.output == expected[1]) == negated);
        }
    }
}
