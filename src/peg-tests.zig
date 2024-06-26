const std = @import("std");
const testing = std.testing;
const pk = @import("parakeet");
const peg = pk.peg;
const parseString = peg.parseString;
const pegps = peg.parsers; // @import("peg-parsers.zig");

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
    try testing.expectError(error.ParseFailure, checkSame(pegps.ident, "1"));
    try testing.expectError(error.ParseFailure, checkSame(pegps.ident, ""));
    try checkSame(pegps.expression, "id1");
    try checkSame(pegps.expression, "id1?");
    try checkSame(pegps.expression, "id1*");
    try checkSame(pegps.expression, "id1+");
    try checkSame(pegps.expression, "&id1");
    try checkSame(pegps.expression, "!id1");
    try checkSame(pegps.expression, "&id1?");
    try check(pegps.expression, "( id1 )", "id1");
    try check(pegps.expression, "( id1 )*", "id1*");
    try checkSame(pegps.expression, "id1 ( id1 / id3 )*");
    try check(pegps.expression, "( &id1? )", "&id1?");
    try checkSame(pegps.expression, "id1 id2");
    try checkSame(pegps.expression, "id1\n    / id2");
    try checkSame(pegps.expression, "id1\n    / id2 id3");
    try checkSame(pegps.expression, "id1\n    / ( id2 / id3 )");
    try checkSame(pegps.expression, ".");
    try checkSame(pegps.expression, "[a] F");
    try checkSame(pegps.expression,
        \\"\\x" hex hex
        \\    / "\\u{" hex+ "}"
        \\    / "\\" ["'\\nrt]
    );
    // group with a single child doesn't need to be grouped
    try check(pegps.expression, "( !Prefix )*", "!Prefix*");
    // memo nodes
    try checkSame(pegps.expression, "{{ a }}");
    try checkSame(pegps.expression, "{{ a }}*");
    try check(pegps.expression, "( {{ a }} )*", "{{ a }}*");
    try checkSame(pegps.expression,
        \\a b
        \\    / 
    );
    try checkSame(pegps.expression, "Expr'");
}

test "peg string literal" {
    try checkSame(pegps.expression,
        \\"s"
    );
    try checkSame(pegps.expression,
        \\"\""
    );
    try checkSame(pegps.expression,
        \\"\n"
    );
    try checkSame(pegps.expression,
        \\'s'
    );
    try checkSame(pegps.expression,
        \\'\''
    );
    try checkSame(pegps.expression,
        \\'\n'
    );
    try checkSame(pegps.expression,
        \\'\\'
    );
    try testing.expectError(error.ParseFailure, checkSame(pegps.expression,
        \\""
    ));
    try testing.expectError(error.ParseFailure, checkSame(pegps.expression,
        \\''
    ));
    try testing.expectError(error.ParseFailure, checkSame(pegps.expression,
        \\'a
    ));
    try testing.expectError(error.ParseFailure, checkSame(pegps.expression,
        \\"a
    ));
    try testing.expectError(error.ParseFailure, checkSame(pegps.expression,
        \\[a
    ));
}

test "peg character class" {
    try checkSame(pegps.expression, "[a]");
    try checkSame(pegps.expression, "[a-z]");
    try checkSame(pegps.expression, "[A-Za-z]");
    try checkSame(pegps.expression, "[\\-]");
    try checkSame(pegps.expression, "[\\t]");
    try checkSame(pegps.expression,
        \\[+\-]
    );
    try check(pegps.expression,
        \\[\010]
    , "[\\b]");
    try checkSame(pegps.expression, "[\\\\]");
    try checkSame(pegps.expression, "[\\[\\]]");
    try checkSame(pegps.expression, "[0-9]+");
    try checkSame(pegps.expression,
        \\[\200-\277]
    );
    try testing.expectError(
        error.ParseFailure,
        checkSame(pegps.expression, "[]"),
    );
    try checkSame(pegps.expression,
        \\["'\\nrt]
    );
    try checkSame(pegps.expression, "[0-9A-Z_a-z]");
    try checkSame(pegps.expression,
        \\[^\n"\\]
    );
    try checkSame(pegps.expression, "[\\^a-z]");
}

test "peg misc" {
    try checkStr(pegps.comment, "# comment \n", " comment ");
    try checkStr(pegps.comment, "# comment", " comment");
}

test "peg def" {
    const d = try parseString(pegps.def, "a <- b c", talloc);
    defer d[1].deinit(talloc);
    try testing.expectEqualStrings("a", d[0]);
    try testing.expectEqual(@as(usize, 2), d[1].seq.len);
    try testing.expectEqualStrings("b", d[1].seq[0].ident);
    try testing.expectEqualStrings("c", d[1].seq[1].ident);
}

test "peg grammar" {
    const g = try parseString(pegps.grammar, "a <- b c d <- e", talloc);
    defer g.deinit(talloc);
    try testing.expectEqual(@as(usize, 2), g.grammar.len);
    try testing.expectEqualStrings("a", g.grammar[0][0]);
    try testing.expectEqualStrings("d", g.grammar[1][0]);

    try checkSame(pegps.grammar, "a <- b c\nd <- e");
    try checkSame(pegps.grammar, "Expr <- Factor ( [+\\-] Factor )*");
    try checkSame(pegps.grammar,
        \\Expr <- Factor ( [+\-] Factor )*
        \\Factor <- Term ( [*/] Term )*
    );
    try check(pegps.grammar, "Sequence <- Prefix ( Prefix )* /",
        \\Sequence <-
        \\      Prefix Prefix*
        \\    / 
    );
    try checkSame(pegps.grammar,
        \\char_escape <-
        \\      "\\x" hex hex
        \\    / "\\u{" hex+ "}"
        \\    / "\\" ["'\\nrt]
        \\char_char <-
        \\      mb_utf8_literal
        \\    / char_escape
        \\    / ascii_char_not_nl_slash_squote
    );
    try check(pegps.grammar, "expr <- term expr2 /",
        \\expr <-
        \\      term expr2
        \\    / 
    );
}

test "peg capture" {
    try checkSame(pegps.grammar, "a <- 'a':0");
}

test "ContainerField" {
    // TODO look into this further:
    // $ zig build && zig-out/bin/main examples/zig-grammar.y examples/AstGen.zig
    // parse error examples/AstGen.zig at 578/558501 '/// The se'
    if (true) return;
    const in =
        \\ContainerField <- doc_comment? !KEYWORD_fn (IDENTIFIER COLON)? TypeExpr
        \\doc_comment <- ('///' [^\n]* [ \n]* skip)+
        \\KEYWORD_fn          <- 'fn'          end_of_word
        \\end_of_word <- ![a-zA-Z0-9_] skip
        \\skip <- ([ \n])*
        \\IDENTIFIER
        \\<- [A-Za-z_] [A-Za-z0-9_]* skip
        \\ / "@" STRINGLITERALSINGLE
        \\COLON                <- ':'                skip
        \\TypeExpr <- PrefixTypeOp*
        \\PrefixTypeOp <- '*'? "const"? IDENTIFIER ('.' IDENTIFIER)*
        \\STRINGLITERALSINGLE <- "\"" string_char* "\"" skip
        \\string_char
        \\ <- char_escape
        \\  / [^\\"\n]
        \\char_escape
        \\  <- "\\x" hex hex
        \\   / "\\u{" hex+ "}"
        \\   / "\\" [nr\\t'"]
        \\ hex <- [0-9a-fA-F]
        \\
    ;
    var arena = std.heap.ArenaAllocator.init(talloc);
    defer _ = arena.deinit();
    const g = try parseString(pegps.grammar, in, arena.allocator());
    const Ctx = pk.pattern.ParseContext(void);
    var ctx = try Ctx.init(.{ .allocator = arena.allocator() }, g);
    const r = pk.pattern.parse(
        Ctx,
        &ctx,
        0,
        \\/// The set of nodes which, given the choice, must expose a result pointer to
        \\/// sub-expressions. See `AstRlAnnotate` for details.
        \\nodes_need_rl: *const AstRlAnnotate.RlNeededSet,
        \\
        ,
    );
    std.debug.print("{}\n", .{r});
}
