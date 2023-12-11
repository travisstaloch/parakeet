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
            var ra: Ctx.Result = undefined;
            ctx.input = pk.input(expected[0]);
            ctx.rules[0].pattern.run(Ctx, &ctx, &ra);
            // std.debug.print("negated={} r={} expected=({s},{})\n", .{ negated, r, expected[0], expected[1] });
            try testing.expect((ra.output != expected[1]));
        }
        {
            var rb: Ctx.Result = undefined;
            ctx.input = pk.input(expected[0]);
            ctx.rules[1].pattern.run(Ctx, &ctx, &rb);
            try testing.expect((rb.output == expected[1]));
        }
        {
            var rc: Ctx.Result = undefined;
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
        const ctx = try Ctx.init(.{ .allocator = arena.allocator() }, g);

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

test "first sets, nullability, and follow sets" {
    // example is from https://holub.com/goodies/compiler/compilerDesignInC.pdf
    // section 4.7.1
    const input = @embedFile("../examples/stmt.peg");

    var arena = std.heap.ArenaAllocator.init(talloc);
    defer arena.deinit();
    const g = try pk.peg.parseString(pk.peg.parsers.grammar, input, arena.allocator());
    const Ctx = pk.pattern.ParseContext(void);
    const ctx = try Ctx.init(.{ .allocator = arena.allocator() }, g);
    const rules = ctx.rules;
    try expectFormat("[(0-9;]", "{}", .{rules[0].first_set}); // Stmt
    try testing.expect(rules[0].nullability == .non_nullable);
    try expectFormat("[(0-9]", "{}", .{rules[1].first_set}); // Expr
    try testing.expect(rules[1].nullability == .nullable);
    try expectFormat("[+]", "{}", .{rules[2].first_set}); // Expr'
    try testing.expect(rules[2].nullability == .nullable);
    try expectFormat("[(0-9]", "{}", .{rules[3].first_set}); // Term
    try testing.expect(rules[3].nullability == .non_nullable);
    try expectFormat("[*]", "{}", .{rules[4].first_set}); // Term'
    try testing.expect(rules[4].nullability == .nullable);
    try expectFormat("[(0-9]", "{}", .{rules[5].first_set}); // Factor
    try testing.expect(rules[5].nullability == .non_nullable);

    // for (rules[0..g.grammar.len]) |r| {
    //     std.debug.print("{s} {} {}\n", .{ r.rule_name, r.first_set, r.follow_set });
    // }
    try expectFormat("[]", "{}", .{rules[0].follow_set});
    try expectFormat("[);]", "{}", .{rules[1].follow_set});
    try expectFormat("[);]", "{}", .{rules[2].follow_set});
    try expectFormat("[)+;]", "{}", .{rules[3].follow_set});
    try expectFormat("[)+;]", "{}", .{rules[4].follow_set});
    // [)-+] is equivalent to [)*+]
    try expectFormat("[)-+;]", "{}", .{rules[5].follow_set});
}

test "basic captures" {
    const input =
        \\S   <- foo bar
        \\foo <- "foo" : 123
        \\bar <- "bar":
    ;
    var arena = std.heap.ArenaAllocator.init(talloc);
    defer arena.deinit();
    const CaptureHandler = struct {
        captures: std.ArrayListUnmanaged([]const u8) = .{},
        allocator: std.mem.Allocator,
        pub fn onCapture(self: *@This(), cap: pk.pattern.CaptureInfo) !void {
            try self.captures.append(self.allocator, cap.text());
        }
    };
    var handler = CaptureHandler{ .allocator = arena.allocator() };
    const Ctx = pk.pattern.ParseContext(CaptureHandler);
    const g = try pk.peg.parseString(pk.peg.parsers.grammar, input, arena.allocator());
    try testing.expectEqual(@as(usize, 3), g.grammar.len);
    try testing.expectEqual(@as(u32, 123), g.grammar[1][1].cap.id);
    try testing.expect(g.grammar[1][1] == .cap);

    var ctx = try Ctx.init(.{
        .allocator = arena.allocator(),
        .capture_handler = &handler,
    }, g);
    const r = pk.pattern.parse(Ctx, &ctx, 0, "foobar");
    try testing.expect(r.output == .ok);
    try testing.expectEqual(@as(usize, 2), handler.captures.items.len);
    try testing.expectEqualStrings("foo", handler.captures.items[0]);
    try testing.expectEqualStrings("bar", handler.captures.items[1]);
}

test "json parser with captures" {
    const input =
        \\doc           <- JSON !.
        \\JSON          <- S_ (Number:0 / Object / Array / String / True / False / Null) S_
        \\Object        <- '{' (String:0 ':' JSON (',' String ':' JSON)* / S_) '}':1
        \\Array         <- '[' (JSON (',' JSON)* / S_) ']'
        \\StringBody    <- Escape? ((!["\\\00-\37] .)+ Escape*)*
        \\String        <- S_ '"' StringBody '"' S_
        \\Escape        <- '\\' (["{|\\bfnrt] / UnicodeEscape)
        \\UnicodeEscape <- 'u' [0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]
        \\Number        <- Minus? IntPart FractPart? ExpPart?
        \\Minus         <- '-'
        \\IntPart       <- '0' / [1-9][0-9]*
        \\FractPart     <- '.' [0-9]+
        \\ExpPart       <- [eE] [+\-]? [0-9]+
        \\True          <- 'true'
        \\False         <- 'false'
        \\Null          <- 'null'
        \\S_            <- [\11-\15\40]*
    ;
    var arena = std.heap.ArenaAllocator.init(talloc);
    defer arena.deinit();
    const CaptureHandler = struct {
        allocator: std.mem.Allocator,
        state: State = .init,
        as: std.ArrayListUnmanaged(A) = .{},
        a: A = undefined,

        const A = struct { b: u8 };
        const State = enum { init, a, a_end, b, b_end };
        pub fn onCapture(self: *@This(), cap: pk.pattern.CaptureInfo) !void {
            // std.debug.print("capture {s}:{}:{}:'{s}' state={s}\n", .{
            //     cap.rule_name,
            //     cap.id.rule,
            //     cap.id.cap,
            //     cap.text(),
            //     @tagName(self.state),
            // });
            const Id = pk.pattern.CaptureInfo.Id;

            switch (cap.id.asInt()) {
                Id.int(2, 0) => { // String - json key
                    const text = cap.text();
                    if (text.len < 2) return error.ParseFailure;
                    const Field = enum { a, b };
                    switch (std.meta.stringToEnum(
                        Field,
                        text[1 .. text.len - 1],
                    ) orelse
                        return error.ParseFailure) {
                        .a => self.state = .a,
                        .b => self.state = .b,
                    }
                },
                Id.int(1, 0) => { // Number
                    if (self.state != .b) return error.ParseFailure;
                    self.a.b = try std.fmt.parseInt(u8, cap.text(), 10);
                },
                Id.int(2, 1) => { // '}'
                    switch (self.state) {
                        .b => self.state = .b_end,
                        .b_end => {
                            self.state = .a_end;
                            try self.as.append(self.allocator, self.a);
                            self.a = undefined;
                        },
                        else => {},
                    }
                },
                else => {},
            }
        }
    };
    var handler = CaptureHandler{ .allocator = arena.allocator() };
    const Ctx = pk.pattern.ParseContext(CaptureHandler);
    const g = try pk.peg.parseString(pk.peg.parsers.grammar, input, arena.allocator());
    var ctx = try Ctx.init(.{
        .allocator = arena.allocator(),
        .capture_handler = &handler,
    }, g);

    // std.debug.print("{s} <- {}\n", .{ g.grammar[3][0], g.grammar[3][1] });
    const r = pk.pattern.parse(Ctx, &ctx, 0,
        \\[
        \\{"a": {"b": 0}},
        \\{"a": {"b": 1}},
        \\{"a": {"b": 2}}
        \\]
    );
    // std.debug.print("{}\n", .{r.input});
    try testing.expect(r.output == .ok);
    try testing.expectEqual(@as(usize, 3), ctx.capture_handler.as.items.len);
    try testing.expectEqual(@as(u8, 0), ctx.capture_handler.as.items[0].b);
    try testing.expectEqual(@as(u8, 1), ctx.capture_handler.as.items[1].b);
    try testing.expectEqual(@as(u8, 2), ctx.capture_handler.as.items[2].b);
}
