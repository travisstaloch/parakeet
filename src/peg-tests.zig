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
    try check(
        Peg.grammar,
        "Sequence <- Prefix ( Prefix )* /",
        "Sequence <- Prefix ( Prefix )*",
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
