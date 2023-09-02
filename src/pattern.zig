const std = @import("std");
const mem = std.mem;
const pk = @import("lib.zig");
const Expr = pk.peg.Expr;
const builtin = @import("builtin");
const is_debug_mode = builtin.mode == .Debug;

pub const Ok = [2]u32;

pub const CaptureInfo = struct {
    rule_name: []const u8,
    text_ptr: [*]const u8,
    text_span: Ok,
    id: Id,

    pub const Id = packed struct {
        rule: u32,
        cap: u32,
        pub fn init(rule: u32, cap: u32) Id {
            return .{
                .rule = rule,
                .cap = cap,
            };
        }
        pub fn asInt(ids: Id) usize {
            return @bitCast(ids);
        }
        pub fn int(rule: u32, cap: u32) usize {
            return @bitCast(init(rule, cap));
        }
    };

    pub fn text(self: CaptureInfo) []const u8 {
        return self.text_ptr[self.text_span[0]..self.text_span[1]];
    }
};

pub fn ParseContext(comptime CaptureHandler: type) type {
    return struct {
        input: pk.Input,
        rule_id: u32,
        rules: [*]const Rule,
        memo: MemoTable = .{},
        allocator: mem.Allocator,
        capture_handler: if (C == void) void else *CaptureHandler,
        /// for debugging. a trail of nonterminal names
        nonterm_trail: if (is_debug_mode)
            std.BoundedArray(u8, 512)
        else
            void = if (is_debug_mode) .{} else {},

        pub const Ctx = @This();
        pub const C = CaptureHandler;
        pub const MemoTable = std.AutoHashMapUnmanaged(Ok, Result);
        pub const Options = struct {
            allocator: mem.Allocator = pk.failing_allocator,
            mode: Pattern.OptimizeMode = .optimized,
            capture_handler: if (C == void) void else *C =
                if (C == void) {} else undefined,
        };

        pub const Error = pk.ParseError || if (CaptureHandler == void)
            error{}
        else
            pk.RetErrorSet(CaptureHandler.onCapture);

        pub const Result = struct {
            input: pk.Input,
            output: Output,

            const Output = union(enum) {
                err: Error,
                // TODO perhaps change ok back to []const u8 now that run()
                // 'returns' by out pointer
                /// start and end indices for input.s
                ok: Ok,
            };

            pub fn err(i: pk.Input) Result {
                return .{ .input = i, .output = .{ .err = error.ParseFailure } };
            }
            pub fn errWith(i: pk.Input, e: Error) Result {
                return .{ .input = i, .output = .{ .err = e } };
            }
            pub fn ok(i: pk.Input, s: [2]u32) Result {
                return .{ .input = i, .output = .{ .ok = s } };
            }

            pub fn format(r: Result, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
                _ = options;
                _ = fmt;
                try writer.print("{s}", .{@tagName(r.output)});
                switch (r.output) {
                    .err => {},
                    .ok => |o| try writer.print(" {}..{}={s}", .{ o[0], o[1], r.input.s[o[0]..o[1]] }),
                }
                try writer.print(" {}..", .{r.input.index});
            }
        };

        /// initializes 'rules' and 'allocator' fields. 'input' and 'rule_id'
        /// will be set in Pattern.parse
        pub fn init(options: Options, grammar: Expr) !Ctx {
            const rules = try Pattern.optimize(
                grammar,
                options.allocator,
                options.mode,
            );
            return .{
                .rules = rules.ptr,
                .input = undefined,
                .rule_id = undefined,
                .allocator = options.allocator,
                .capture_handler = options.capture_handler,
            };
        }

        pub fn onCapture(ctx: *Ctx, rule_name: []const u8, id: CaptureInfo.Id, ok: Ok) !void {
            const info = @typeInfo(CaptureHandler);
            if (info == .Struct and @hasDecl(CaptureHandler, "onCapture")) {
                // verify capture_handler.onCapture first param is a self pointer
                const fninfo = @typeInfo(@TypeOf(CaptureHandler.onCapture));
                const Param1 = fninfo.Fn.params[0].type.?;
                if (Param1 != *CaptureHandler)
                    @compileError("expected first parameter of " ++
                        "CaptureHandler.onCapture() to be \n'*" ++
                        @typeName(CaptureHandler) ++ "'.  found \n' " ++
                        @typeName(Param1) ++ "'");

                // debug("ok={},{}/{} rule={s}\n", .{ ok[0], ok[1], ctx.input.len, rule_name });
                std.debug.assert(ok[0] <= ok[1]);
                std.debug.assert(ok[1] <= ctx.input.len);
                try ctx.capture_handler.onCapture(.{
                    .rule_name = rule_name,
                    .id = id,
                    .text_ptr = ctx.input.s,
                    .text_span = ok,
                });
            }
        }
    };
}

pub fn parse(
    comptime Ctx: type,
    ctx: *Ctx,
    start_rule_id: u32,
    input: []const u8,
) !Ctx.Result {
    ctx.input = pk.input(input);
    ctx.rule_id = start_rule_id;
    ctx.memo.clearRetainingCapacity();

    const pat = ctx.rules[ctx.rule_id].pattern;
    return pat.run(Ctx, ctx);
}

pub const Literal = struct { ptr: [*]const u8, len: u32 };

pub const Nullability = enum { unknown, non_nullable, nullable };

pub const Rule = struct {
    rule_id: u32,
    rule_name: []const u8,
    pattern: Pattern,
    /// set of possible first characters
    first_set: Expr.Class = .{ .bitset = Expr.Class.Set.initEmpty() },
    /// set of possible following characters
    follow_set: Expr.Class = .{ .bitset = Expr.Class.Set.initEmpty() },
    /// 'nullable' means that the rule may succeed without consuming any input
    nullability: Nullability,

    pub fn init(rule_id: u32, pattern: Pattern) Rule {
        return .{
            .rule_id = rule_id,
            .pattern = pattern,
            .first_set = .{ .bitset = Expr.Class.Set.initEmpty() },
            .nullability = .unknown,
        };
    }
};

const debug = std.debug.print;

/// a data format similar to Expr for optimizing and running parsers
pub const Pattern = union(enum) {
    literal: Literal,
    class: *const Expr.Class,
    alt: []Pattern,
    seq: []Pattern,
    many: *Pattern,
    opt: *Pattern,
    not: *Pattern,
    amp: *Pattern,
    memo: Memo,
    cap: Capture,
    nonterm: u32,
    dot,
    eos,
    empty,

    comptime {
        std.debug.assert(24 == @sizeOf(Pattern));
    }
    pub const Tag = std.meta.Tag(Pattern);
    pub const Memo = struct { pat: *Pattern, id: u32 };
    pub const Capture = struct { pat: *Pattern, id: CaptureInfo.Id };

    /// if all choices are charsets or single chars, return a class of the union
    fn combineAlt(pats: []const Pattern) ?Expr.Class.Set {
        for (pats) |pat| {
            if (!(pat == .class or
                (pat == .literal and pat.literal.len == 1)))
                return null;
        }
        var bitset = Expr.Class.Set.initEmpty();
        for (pats) |pat| {
            switch (pat) {
                .class => |other| bitset.setUnion(other.bitset),
                .literal => |lit| {
                    std.debug.assert(lit.len == 1);
                    bitset.set(lit.ptr[0]);
                },
                else => unreachable,
            }
        }
        return bitset;
    }

    fn firstOfSeq(pat: Pattern) ?Pattern {
        if (pat != .seq) return null;
        std.debug.assert(pat.seq.len > 0);
        return pat.seq[0];
    }

    pub fn eql(p: Pattern, other: Pattern) bool {
        return @as(Pattern.Tag, p) == @as(Pattern.Tag, other) and
            switch (p) {
            .literal => |lit| lit.len == other.literal.len and pk.util.eql(
                lit.ptr[0..lit.len],
                other.literal.ptr[0..other.literal.len],
            ),
            .class => |klass| klass.bitset.eql(other.class.bitset),
            .alt => |pats| pats.len == other.alt.len and for (pats, 0..) |subp, i| {
                if (!eql(subp, other.alt[i])) break false;
            } else true,
            .seq => |pats| pats.len == other.seq.len and for (pats, 0..) |subp, i| {
                if (!eql(subp, other.seq[i])) break false;
            } else true,
            inline .many,
            .opt,
            .not,
            .amp,
            => |ip, tag| eql(ip.*, @field(other, @tagName(tag)).*),
            .memo => |m| m.id == other.memo.id and eql(m.pat.*, other.memo.pat.*),
            .cap => |m| m.id.cap == other.cap.id.cap and eql(m.pat.*, other.cap.pat.*),
            .nonterm => |id| id == other.nonterm,
            .dot,
            .eos,
            .empty,
            => true,
        };
    }

    /// ----
    /// sequence operators can be distributed into choice operators on the left
    /// ----
    /// when all alt patterns start with a common pattern, it may be distributed
    /// out.  this results in less duplicated parsing work.
    /// A <- (e1 e2) / (e1 e3)
    /// B <- e1 (e2 / e3)
    /// A and B are equivalent. all patterns receive the same input in each.
    ///
    /// NOTE: this does not apply when all alt patterns _end_ with a common
    /// pattern
    /// A <- (e1 e3) / (e2 e3)
    /// B <- (e1 / e2) e3
    /// from https://bford.info/pub/lang/peg.pdf
    /// In the expression (e1 / e2) e3, the failure of e3 causes the whole
    /// expression to fail. In (e1 e3) / (e2 e3), however, the first instance of
    /// e3 only causes the first alternative to fail; the second alternative
    /// will then be tried, in which the e3 might succeed if e2 consumes a
    /// different amount of input than e1 did.
    fn reduceAlt(pats: []Pattern, arena: mem.Allocator) !?Pattern {
        // TODO hoist longest common sequence
        std.debug.assert(pats.len > 1);
        const e1 = firstOfSeq(pats[0]) orelse return null;
        for (pats[1..]) |p| {
            const e1b = firstOfSeq(p) orelse return null;
            if (!eql(e1, e1b)) return null;
        }
        // reduce by removing first pattern from all seqs
        for (0..pats.len) |i| {
            const tmp = pats[i].seq;
            pats[i] = if (tmp.len == 2)
                tmp[1]
            else
                .{ .seq = tmp[1..] };
        }

        const newseq = try arena.alloc(Pattern, 2);
        newseq[0] = e1;
        newseq[1] = .{ .alt = pats };

        return .{ .seq = newseq };
    }

    /// combine sequences of literals into a single literal
    fn combineSeq(pats: []const Pattern, arena: mem.Allocator) !?Pattern {
        if (pats.len == 1) return pats[0];
        const ok = for (pats) |pat| {
            if (!(pat == .literal or pat == .empty)) break false;
        } else true;
        if (!ok) return null;

        var s = std.ArrayList(u8).init(arena);
        defer s.deinit();
        for (pats) |pat| {
            if (pat != .empty) try s.appendSlice(pat.literal.ptr[0..pat.literal.len]);
        }
        const r = try s.toOwnedSlice();
        return .{ .literal = .{ .ptr = r.ptr, .len = @intCast(r.len) } };
    }

    fn optimizeImpl(
        gexpr: Expr,
        pat: Pattern,
        map: Expr.NonTerminalIdMap,
        depth: u8,
        arena: mem.Allocator,
        mode: OptimizeMode,
    ) !Pattern {
        return switch (pat) {
            .alt => |pats| {
                if (mode == .optimized) {
                    if (combineAlt(pats)) |bitset| {
                        const klass = try arena.create(Expr.Class);
                        klass.* = .{ .bitset = bitset };
                        return .{ .class = klass };
                    }
                }
                for (0..pats.len) |i|
                    pats[i] = try optimizeImpl(gexpr, pats[i], map, depth + 1, arena, mode);

                if (mode == .optimized) {
                    return if (try reduceAlt(pats, arena)) |reduced|
                        reduced
                    else
                        .{ .alt = pats };
                } else return .{ .alt = pats };
            },
            .seq => |pats| {
                if (mode == .optimized)
                    if (try combineSeq(pats, arena)) |r| return r;
                for (0..pats.len) |i|
                    pats[i] = try optimizeImpl(gexpr, pats[i], map, depth + 1, arena, mode);
                return .{ .seq = pats };
            },
            .not, .amp, .opt, .many => |p| {
                p.* = try optimizeImpl(gexpr, p.*, map, depth, arena, mode);
                return pat;
            },
            .literal => |lit| return .{ .literal = lit },
            .class => |klass| return .{ .class = klass },
            // inline nonterminals up to 2 levels deep. 2 levels was an arbitrary decision
            // TODO consider dealying inlining to a later pass
            .nonterm => |id| return if (depth < 2) blk: {
                const p = try fromExpr(arena, gexpr.grammar[id][1], id, map);
                break :blk try optimizeImpl(gexpr, p, map, depth + 1, arena, mode);
            } else .{ .nonterm = id },
            .dot => return .dot,
            .empty => return .empty,
            .eos => return .eos,
            inline .memo, .cap => |m| {
                m.pat.* = try optimizeImpl(gexpr, m.pat.*, map, depth, arena, mode);
                return pat;
            },
        };
    }

    pub const OptimizeMode = enum { optimized, unoptimized };

    /// convert 'e' to a Pattern
    pub fn fromExpr(
        arena: mem.Allocator,
        e: Expr,
        rule_id: u32,
        map: Expr.NonTerminalIdMap,
    ) !Pattern {
        return switch (e) {
            .ident => |s| .{ .nonterm = map.get(s) orelse {
                std.log.err("grammar error: invalid nonterminal '{s}'\n", .{s});
                return error.InvalidNonTerminal;
            } },
            .litS, .litD => |s| .{ .literal = .{ .ptr = s.ptr, .len = @intCast(s.len) } },
            .class => |c| blk: {
                const ptr = try arena.create(Expr.Class);
                ptr.* = c;
                break :blk .{ .class = ptr };
            },
            .dot => .dot,
            inline .amp, .opt => |ie, tag| blk: {
                const ptr = try arena.create(Pattern);
                ptr.* = try fromExpr(arena, ie.*, rule_id, map);
                break :blk @unionInit(Pattern, @tagName(tag), ptr);
            },
            .not => |ie| if (ie.* == .dot) .eos else blk: {
                const ptr = try arena.create(Pattern);
                ptr.* = try fromExpr(arena, ie.*, rule_id, map);
                break :blk .{ .not = ptr };
            },
            .star => |ie| blk: {
                const ptr = try arena.create(Pattern);
                ptr.* = try fromExpr(arena, ie.*, rule_id, map);
                break :blk .{ .many = ptr };
            },
            .plus => |ie| blk: {
                const ptr = try arena.create(Pattern);
                const pat = try fromExpr(arena, ie.*, rule_id, map);
                ptr.* = pat;
                const items = try arena.alloc(Pattern, 2);
                items[0] = pat;
                items[1] = .{ .many = ptr };
                break :blk .{ .seq = items };
            },
            .group => |ie| try fromExpr(arena, ie.*, rule_id, map),
            .memo => |m| blk: {
                const ptr = try arena.create(Pattern);
                ptr.* = try fromExpr(arena, m.expr.*, rule_id, map);
                break :blk .{ .memo = .{ .pat = ptr, .id = m.id } };
            },
            .cap => |m| blk: {
                const ptr = try arena.create(Pattern);
                ptr.* = try fromExpr(arena, m.expr.*, rule_id, map);
                break :blk .{ .cap = .{ .pat = ptr, .id = .{
                    .rule = rule_id,
                    .cap = m.id,
                } } };
            },
            .alt => |es| blk: {
                const ps = try arena.alloc(Pattern, es.len);
                for (0..es.len) |i| ps[i] = try fromExpr(arena, es[i], rule_id, map);
                break :blk .{ .alt = ps };
            },
            .seq => |es| blk: {
                const ps = try arena.alloc(Pattern, es.len);
                for (0..es.len) |i| ps[i] = try fromExpr(arena, es[i], rule_id, map);
                break :blk .{ .seq = ps };
            },
            .empty => .empty,
            .grammar => {
                unreachable;
            },
        };
    }

    pub const Visited = std.BoundedArray(u32, 16);

    /// convert the rules from the grammar 'g' to an optimized format
    pub fn optimize(
        gexpr: Expr,
        arena: mem.Allocator,
        mode: OptimizeMode,
    ) ![]const Rule {
        var map = Expr.NonTerminalIdMap.init(arena);
        defer map.deinit();
        // 1. populate nonterm id map
        for (gexpr.grammar, 0..) |r, i| {
            const gop = try map.getOrPut(r[0]);
            if (gop.found_existing) {
                std.log.err("grammar error: nonterminal with name '{s}' already exists\n", .{r[0]});
                return error.InvalidNonTerminal;
            }
            gop.value_ptr.* = @truncate(i);
        }

        const rules = try arena.alloc(Rule, gexpr.grammar.len);
        // 2. convert Expr grammar to Pattern
        for (0..gexpr.grammar.len) |i| {
            const rule_id: u32 = @truncate(i);
            rules[i] = .{
                .rule_id = rule_id,
                .rule_name = gexpr.grammar[i][0],
                .pattern = try fromExpr(arena, gexpr.grammar[i][1], rule_id, map),
                .nullability = .unknown,
            };
        }

        // 3. calculate nullability and first sets
        for (rules) |*rule| {
            rule.nullability = nullability(rule.pattern, rules, rule.rule_id);
            var visited: Visited = .{};
            try visited.append(rule.rule_id);
            calcFirstSet(rule.pattern, rules, &rule.first_set, rule.rule_id, &visited);
        }

        // 4. calcuate follow sets
        for (rules) |*a| {
            for (rules) |b| {
                if (a.rule_id == b.rule_id) continue;
                var visited: Visited = .{};
                try visited.append(a.rule_id);
                calcFollowSet(b.pattern, rules, &a.follow_set, a.rule_id, b.rule_id, &visited, .no_accumulate);
            }
        }

        // 5. optimize
        if (mode == .optimized) {
            for (rules) |*rule|
                rule.pattern = try optimizeImpl(gexpr, rule.pattern, map, 0, arena, mode);
        }
        return rules;
    }

    /// calculate whether 'pat' must consume some input (non-nullable) or if its
    /// possible for it to succeed consuming no input (nullable).  returns .unknown
    /// if a cycle is detected.
    pub fn nullability(
        pat: Pattern,
        rules: []const Rule,
        start_rule_id: u32,
    ) Nullability {
        return switch (pat) {
            .literal, .class, .dot => .non_nullable,
            .alt => |ps| for (ps) |p| {
                if (nullability(p, rules, start_rule_id) == .nullable) break .nullable;
            } else .non_nullable,
            .seq => |ps| for (ps) |p| {
                if (nullability(p, rules, start_rule_id) == .non_nullable) break .non_nullable;
            } else .nullable,
            .many, .opt, .not, .amp => .nullable,
            .eos, .empty => .nullable,
            inline .memo, .cap => |m| nullability(m.pat.*, rules, start_rule_id),
            .nonterm => |id| if (id == start_rule_id)
                .unknown
            else
                nullability(rules[id].pattern, rules, start_rule_id),
        };
    }

    /// calculate the 'first set' for 'pat'.  this is a set of valid next
    /// input characters for the pattern.
    pub fn calcFirstSet(
        pat: Pattern,
        rules: []const Rule,
        first_set: *Expr.Class,
        start_rule_id: u32,
        visited: *Visited,
    ) void {
        // debug("calcFirstSet {s}={} first_set={}\n", .{ @tagName(pat), pat, first_set.* });
        switch (pat) {
            .literal => |lit| first_set.bitset.set(lit.ptr[0]),
            .class => |c| {
                // my intuition was that negated bitsets (over 1/2 bits set),
                // need to be inverted.  but this leads to incorrect parsing
                // results with a few zig files in the std lib.
                first_set.bitset.setUnion(c.bitset);
            },
            .alt => |ps| {
                for (ps) |p| {
                    var c = Expr.Class{ .bitset = Expr.Class.Set.initEmpty() };
                    calcFirstSet(p, rules, &c, start_rule_id, visited);
                    first_set.bitset.setUnion(c.bitset);
                }
            },
            .seq => |ps| {
                for (ps) |p| {
                    calcFirstSet(p, rules, first_set, start_rule_id, visited);
                    // debug("seq c={}\n", .{Expr{ .class = c }});
                    if (nullability(p, rules, start_rule_id) == .non_nullable)
                        break;
                }
            },
            .many, .opt => |p| {
                calcFirstSet(p.*, rules, first_set, start_rule_id, visited);
            },
            .amp => |p| {
                var c = Expr.Class{ .bitset = Expr.Class.Set.initEmpty() };
                calcFirstSet(p.*, rules, &c, start_rule_id, visited);
                first_set.bitset.setIntersection(c.bitset);
            },
            .not => |p| {
                if (p.* == .class) {
                    calcFirstSet(p.*, rules, first_set, start_rule_id, visited);
                    first_set.bitset.toggleAll();
                } else {
                    var c = Expr.Class{ .bitset = Expr.Class.Set.initEmpty() };
                    calcFirstSet(p.*, rules, &c, start_rule_id, visited);
                    first_set.bitset = c.bitset;
                }
            },
            inline .memo, .cap => |m| calcFirstSet(m.pat.*, rules, first_set, start_rule_id, visited),
            .nonterm => |id| {
                if (id != start_rule_id and
                    mem.indexOfScalar(u32, visited.constSlice(), id) == null)
                {
                    calcFirstSet(rules[id].pattern, rules, first_set, start_rule_id, visited);
                }
            },
            .dot => first_set.bitset = Expr.Class.Set.initFull(),
            .eos, .empty => {},
        }
        // debug("calcFirstSet end {s}={} first_set={}\n", .{ @tagName(pat), pat, first_set.* });
    }

    /// accumulate first_sets of things which follow A in a seq into
    /// 'follow_set' until a non-nullable or end of seq.
    /// if A is rightmost in the seq, also add B's follows to A.  A is rightmost
    /// when it is the last non-nullable in a sequence.
    pub fn calcFollowSet(
        pat: Pattern,
        rules: []Rule,
        follow_set: *Expr.Class,
        /// the rule_id of this rule and follow_set, aka A
        a_id: u32,
        /// the rule_id being visited, aka B
        b_id: u32,
        visited: *Visited,
        /// .accumulate if we've previously matched an A in sequence
        mode: enum { accumulate, no_accumulate },
    ) void {
        switch (pat) {
            .seq => |ps| {
                // let A = rules[a_id]
                // * not rightmost
                //   when R <- ... A nullables B... =>
                //     add FIRST(nullables) | FIRST(B) to follow_set
                // * rightmost
                //   when R <- ... A nullables      =>
                //     add FOLLOW(R) to follow_set
                //
                // search the sequence for nonterm entries w/ id == a_id
                std.debug.assert(b_id != a_id);
                var i: usize = 0;
                while (i < ps.len) : (i += 1) {
                    const curr = ps[i];
                    const is_a = curr == .nonterm and curr.nonterm == a_id;

                    if (is_a) {
                        // found A, collect first_sets into follow_set while nullable
                        i += 1;
                        while (i < ps.len) : (i += 1) {
                            const pat_b = ps[i];
                            const b_nullability = if (pat_b == .nonterm) blk: {
                                follow_set.bitset.setUnion(rules[pat_b.nonterm].first_set.bitset);
                                break :blk rules[pat_b.nonterm].nullability;
                            } else blk: {
                                calcFollowSet(pat_b, rules, follow_set, a_id, b_id, visited, .accumulate);
                                break :blk nullability(pat_b, rules, a_id);
                            };
                            if (b_nullability != .nullable) break;
                        }

                        if (i == ps.len) {
                            // rightmost
                            follow_set.bitset.setUnion(rules[b_id].follow_set.bitset);
                        } else {
                            // not rightmost. already accumulated
                        }
                    }
                }
            },
            .alt => |ps| {
                for (ps) |p|
                    calcFollowSet(p, rules, follow_set, a_id, b_id, visited, mode);
            },
            .nonterm => |id| {
                if (id != a_id and
                    mem.indexOfScalar(u32, visited.constSlice(), id) == null)
                {
                    visited.append(id) catch return;
                    calcFollowSet(rules[id].pattern, rules, follow_set, a_id, id, visited, mode);
                }
            },
            .empty, .eos => {},
            .class => |c| if (mode == .accumulate) follow_set.bitset.setUnion(c.bitset),
            .literal => |l| if (mode == .accumulate) follow_set.bitset.set(l.ptr[0]),
            .dot => if (mode == .accumulate) {
                follow_set.bitset = Expr.Class.Set.initFull();
            },
            .many, .not, .amp, .opt => |ip| calcFollowSet(ip.*, rules, follow_set, a_id, b_id, visited, mode),
            inline .memo, .cap => |x| calcFollowSet(x.pat.*, rules, follow_set, a_id, b_id, visited, mode),
        }
    }

    // run() is recursive so it is optimized to reduce fn call overhead by
    // passing 'ctx' and 'res' as pointers. because of this, they are often
    //  reused below and some control flow may be sligntly non-intuitive.
    pub fn run2(
        pat: Pattern,
        comptime Ctx: type,
        ctx: *Ctx,
        res: *Ctx.Result,
    ) void {
        const Result = Ctx.Result;
        const in = ctx.input;
        const debugthis = false;
        if (debugthis) {
            debug("{} ", .{in});
            if (pat != .nonterm) debug("{} {s}\n", .{ pat, @tagName(pat) });
        }
        switch (pat) {
            .nonterm => |id| {
                const rule = ctx.rules[id];
                // if the rule is non-nullable and must consume some input,
                // do a fast check of the first character to see if its
                // in this rule's 'first_set'
                if (rule.nullability == .non_nullable) blk: {
                    const mc = in.get(0);
                    if (mc) |c| if (rule.first_set.bitset.isSet(c))
                        break :blk;

                    if (debugthis)
                        debug("{s} first_set {} doesn't include '{?c}'\n", .{ ctx.rules[id].rule_name, rule.first_set, mc });
                    res.* = Result.err(in);
                    return;
                }
                const traillen = if (is_debug_mode) ctx.nonterm_trail.len else {};
                defer {
                    if (is_debug_mode) ctx.nonterm_trail.len = traillen;
                }
                if (is_debug_mode) {
                    const rulename = ctx.rules[id].rule_name; //@tagName(rule.rule_id);
                    const len = @min(ctx.nonterm_trail.buffer.len - ctx.nonterm_trail.len, rulename.len);
                    ctx.nonterm_trail.appendSlice(rulename[0..len]) catch unreachable;
                    ctx.nonterm_trail.append(',') catch {};
                }

                const prev_id = ctx.rule_id;
                defer ctx.rule_id = prev_id;
                ctx.rule_id = id;
                const p = rule.pattern;
                if (debugthis) {
                    if (is_debug_mode)
                        debug("{s} {s}\n", .{ ctx.nonterm_trail.constSlice(), @tagName(p) })
                    else
                        debug("{s}\n", .{@tagName(p)});
                }
                @call(.always_tail, run, .{ p, Ctx, ctx, res });
            },
            .literal => |lit| {
                res.* = if (in.startsWith(lit.ptr[0..lit.len]))
                    Result.ok(in.advanceBy(lit.len), in.range(lit.len))
                else
                    Result.err(in);
            },
            .class => |klass| {
                const ic = in.get(0) orelse {
                    res.* = Result.err(in);
                    return;
                };
                res.* = if (klass.bitset.isSet(ic))
                    Result.ok(in.advanceBy(1), in.range(1))
                else
                    Result.err(in);
            },
            .dot => res.* = if (in.hasCount(1))
                Result.ok(in.advanceBy(1), in.range(1))
            else
                Result.err(in),
            .empty => res.* = Result.ok(in, in.range(0)),
            .seq => |pats| {
                for (pats) |p| {
                    p.run(Ctx, ctx, res);
                    if (res.output == .err) return;
                    ctx.input.index = res.input.index;
                }
                res.* = Result.ok(ctx.input, in.rangeTo(ctx.input.index));
            },
            .alt => |pats| {
                for (pats) |*p| {
                    ctx.input.index = in.index;

                    const traillen = if (is_debug_mode) ctx.nonterm_trail.len else {};
                    defer {
                        if (is_debug_mode) ctx.nonterm_trail.len = traillen;
                    }
                    p.run(Ctx, ctx, res);
                    if (res.output == .ok) return;
                }
                res.* = Result.err(in);
            },
            .many => |p| {
                while (true) {
                    p.run(Ctx, ctx, res);
                    ctx.input.index = res.input.index;
                    if (res.output == .err) break;
                }
                res.* = Result.ok(ctx.input, in.rangeTo(ctx.input.index));
            },
            .not => |p| {
                p.run(Ctx, ctx, res);
                ctx.input.index = in.index;
                res.* = if (res.output == .ok)
                    Result.err(in)
                else
                    Result.ok(in, in.rangeTo(res.input.index));
            },
            .amp => |p| {
                p.run(Ctx, ctx, res);
                ctx.input.index = in.index;
                res.* = .{ .input = in, .output = res.output };
            },
            .eos => res.* = if (in.eos())
                Result.ok(in, in.restRange())
            else
                Result.err(in),
            .opt => |p| {
                p.run(Ctx, ctx, res);
                if (res.output == .ok) return;
                ctx.input.index = in.index;
                res.* = Result.ok(in, in.range(0));
            },
            .memo => |m| {
                const gop = ctx.memo.getOrPut(
                    ctx.allocator,
                    .{ m.id, in.index },
                ) catch |e| {
                    res.* = Result.errWith(in, e);
                    return;
                };
                // if (gop.found_existing)
                //     debug("found existing memo entry\n", .{});
                if (gop.found_existing) {
                    res.* = gop.value_ptr.*;
                    return;
                }
                m.pat.run(Ctx, ctx, res);
                gop.value_ptr.* = res.*;
            },
            .cap => |cap| {
                cap.pat.run(Ctx, ctx, res);
                if (res.output == .ok) {
                    ctx.onCapture(
                        ctx.rules[ctx.rule_id].rule_name,
                        cap.id,
                        res.output.ok,
                    ) catch |e| {
                        res.* = Result.errWith(in, e);
                    };
                }
            },
        }
    }

    pub fn StackItem(comptime Ctx: type) type {
        return struct {
            pat: Pattern,
            visits: usize,
            res: Ctx.Result,
            pub fn init(pat: Pattern, res: Ctx.Result) @This() {
                return .{
                    .pat = pat,
                    .res = res,
                    .visits = std.math.maxInt(usize),
                };
            }
        };
    }

    pub fn run(
        pat: Pattern,
        comptime Ctx: type,
        ctx: *Ctx,
    ) !Ctx.Result {
        const Result = Ctx.Result;

        const debugthis = false;
        if (debugthis) {
            debug("{} ", .{ctx.input});
            if (pat != .nonterm) debug("{} {s}\n", .{ pat, @tagName(pat) });
        }

        const Item = StackItem(Ctx);
        var stack = try std.ArrayListUnmanaged(Item).initCapacity(ctx.allocator, 128);
        defer stack.deinit(ctx.allocator);
        stack.appendAssumeCapacity(Item.init(pat, Result.err(ctx.input)));

        while (true) {
            if (stack.items.len == 0) {
                stack.items.len += 1;
                return stack.items[0].res;
            }
            stack.items[stack.items.len - 1].visits +%= 1;
            const top = stack.pop();
            if (debugthis)
                debug("stack.len={: >3} {} {s: <3} {s: >7}:{} {}\n", .{
                    stack.items.len + 1,
                    ctx.input,
                    @tagName(top.res.output),
                    @tagName(top.pat),
                    @as(isize, @bitCast(top.visits)),
                    top.pat,
                });
            switch (top.pat) {
                .nonterm => |id| {
                    const rule = ctx.rules[id];
                    // if the rule is non-nullable and must consume some input,
                    // do a fast check of the first character to see if its
                    // in this rule's 'first_set'
                    if (rule.nullability == .non_nullable) blk: {
                        const mc = ctx.input.get(0);
                        if (mc) |c| if (rule.first_set.bitset.isSet(c))
                            break :blk;

                        if (debugthis)
                            debug("{s} first_set {} doesn't include '{?c}'\n", .{ ctx.rules[id].rule_name, rule.first_set, mc });
                        stack.items.ptr[stack.items.len].res = Result.err(ctx.input);
                        continue;
                    }
                    const traillen = if (is_debug_mode) ctx.nonterm_trail.len else {};
                    defer {
                        if (is_debug_mode) ctx.nonterm_trail.len = traillen;
                    }
                    if (is_debug_mode) {
                        const rulename = ctx.rules[id].rule_name;
                        const len = @min(ctx.nonterm_trail.buffer.len - ctx.nonterm_trail.len, rulename.len);
                        try ctx.nonterm_trail.appendSlice(rulename[0..len]);
                        try ctx.nonterm_trail.append(',');
                    }

                    ctx.rule_id = id;
                    try stack.append(ctx.allocator, Item.init(
                        rule.pattern,
                        Result.ok(ctx.input, ctx.input.restRange()),
                    ));
                },
                .literal => |lit| {
                    stack.items.ptr[stack.items.len].res =
                        if (ctx.input.startsWith(lit.ptr[0..lit.len]))
                        Result.ok(
                            ctx.input.advanceBy(lit.len),
                            ctx.input.range(lit.len),
                        )
                    else
                        Result.err(ctx.input);
                },
                .class => |klass| {
                    const ic = ctx.input.get(0) orelse {
                        stack.items.ptr[stack.items.len].res = Result.err(ctx.input);
                        continue;
                    };
                    stack.items.ptr[stack.items.len].res = if (klass.bitset.isSet(ic))
                        Result.ok(ctx.input.advanceBy(1), ctx.input.range(1))
                    else
                        Result.err(ctx.input);
                },
                .dot => stack.items.ptr[stack.items.len].res = if (ctx.input.hasCount(1))
                    Result.ok(ctx.input.advanceBy(1), ctx.input.range(1))
                else
                    Result.err(ctx.input),
                .eos => stack.items.ptr[stack.items.len].res = if (ctx.input.eos())
                    Result.ok(ctx.input, ctx.input.restRange())
                else
                    Result.err(ctx.input),
                .empty => stack.items.ptr[stack.items.len].res = Result.ok(ctx.input, ctx.input.range(0)),
                .seq => |pats| {
                    if (top.visits < pats.len) {
                        if (top.visits == 0)
                            stack.items.ptr[stack.items.len].res = Result.err(ctx.input)
                        else {
                            const prev = stack.items.ptr[stack.items.len + 1];
                            // std.log.debug("seq prev={s}", .{@tagName(prev.res.output)});
                            if (prev.res.output == .err) continue;
                            ctx.input.index = prev.res.input.index;
                        }
                        stack.items.len += 1;
                        try stack.append(ctx.allocator, Item.init(
                            pats[top.visits],
                            Result.err(ctx.input),
                        ));
                    } else if (top.visits == pats.len) {
                        const prev = stack.items.ptr[stack.items.len + 1];
                        // debug("seq done \nprev={} \ntop={}\n", .{ prev.res, top.res });
                        stack.items.ptr[stack.items.len].res = Result.ok(
                            prev.res.input,
                            top.res.input.rangeTo(prev.res.input.index),
                        );
                        ctx.input.index = prev.res.input.index;
                        stack.items.ptr[stack.items.len].visits = std.math.maxInt(usize);
                    } else @panic("unreachable");
                },
                .alt => |pats| {
                    if (top.visits < pats.len) {
                        if (top.visits != 0) {
                            const prev = stack.items.ptr[stack.items.len + 1];
                            if (prev.res.output == .ok) {
                                // debug("alt ok prev.input={}\n", .{prev.res.input});
                                stack.items.ptr[stack.items.len].res = prev.res;
                                ctx.input.index = prev.res.input.index;
                                continue;
                            }
                        }
                        stack.items.len += 1;
                        ctx.input.index = top.res.input.index;
                        try stack.append(ctx.allocator, Item.init(
                            pats[top.visits],
                            Result.err(ctx.input),
                        ));
                    } else if (top.visits == pats.len) {
                        const prev = stack.items.ptr[stack.items.len + 1];
                        // debug("alt done prev.input={}\n", .{prev.res.input});
                        stack.items.ptr[stack.items.len].res = prev.res;
                        ctx.input.index = prev.res.input.index;
                        stack.items.ptr[stack.items.len].visits = std.math.maxInt(usize);
                    } else @panic("unreachable");
                },
                .many => |p| {
                    // debug("many top.visits={}\n", .{top.visits});
                    if (top.visits == 0) {
                        // first time
                        stack.items.ptr[stack.items.len].res =
                            Result.err(ctx.input);
                        stack.items.len += 1;
                        try stack.append(ctx.allocator, Item.init(
                            p.*,
                            Result.err(ctx.input),
                        ));
                    } else {
                        const prev = stack.items.ptr[stack.items.len + 1];
                        // debug("many prev={s}:{} ctx={}\n", .{ @tagName(prev.res.output), prev.res.input, ctx.input });
                        if (prev.res.output == .ok) {
                            ctx.input.index = prev.res.input.index;
                            stack.items.len += 2;
                        } else {
                            stack.items.ptr[stack.items.len].res =
                                Result.ok(ctx.input, top.res.input.rangeTo(prev.res.input.index));
                        }
                    }
                },
                .opt => |p| {
                    if (top.visits == 0) {
                        stack.items.len += 1;
                        try stack.append(ctx.allocator, Item.init(
                            p.*,
                            Result.err(ctx.input),
                        ));
                    } else if (top.visits == 1) {
                        const prev = stack.items.ptr[stack.items.len + 1];
                        // debug("opt prev={} {s} top={} ctx={}\n", .{ prev.res.input, @tagName(prev.res.output), top.res.input, ctx.input });
                        stack.items.ptr[stack.items.len].res = if (prev.res.output == .ok)
                            prev.res
                        else
                            Result.ok(top.res.input, top.res.input.range(0));
                    } else @panic("unreachable");
                },
                .not => |p| {
                    if (top.visits == 0) {
                        stack.items.len += 1;
                        try stack.append(ctx.allocator, Item.init(
                            p.*,
                            Result.err(ctx.input),
                        ));
                    } else if (top.visits == 1) {
                        const prev = stack.items.ptr[stack.items.len + 1];
                        // debug("not input={} {s}\n", .{ ctx.input, @tagName(prev.res.output) });
                        ctx.input.index = top.res.input.index;
                        stack.items.ptr[stack.items.len].res = if (prev.res.output == .ok)
                            Result.err(top.res.input)
                        else
                            Result.ok(top.res.input, top.res.input.range(0));
                        // debug("not res={s}\n", .{@tagName(stack.items.ptr[stack.items.len].res.output)});
                    } else @panic("unreachable");
                },
                .amp => |p| {
                    _ = p;
                    unreachable;
                },
                .memo => |m| {
                    _ = m;
                    unreachable;
                },
                .cap => |cap| {
                    if (top.visits == 0) {
                        stack.items.len += 1;
                        try stack.append(ctx.allocator, Item.init(
                            cap.pat.*,
                            Result.err(ctx.input),
                        ));
                    } else if (top.visits == 1) {
                        const prev = stack.items.ptr[stack.items.len + 1];
                        // debug("cap prev={}\n", .{prev.res});
                        if (prev.res.output == .ok) {
                            ctx.onCapture(
                                ctx.rules[ctx.rule_id].rule_name,
                                cap.id,
                                prev.res.output.ok,
                            ) catch |e| {
                                stack.items.ptr[stack.items.len].res = Result.errWith(top.res.input, e);
                            };
                        }
                        stack.items.ptr[stack.items.len].res = prev.res;
                        ctx.input.index = top.res.input.index;
                    } else @panic("unreachable");
                },
            }
        }
    }

    pub fn format(
        p: Pattern,
        comptime fmt: []const u8,
        opts: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        return formatImpl(p, fmt, opts, writer, 0);
    }

    fn formatImpl(
        pat: Pattern,
        comptime fmt: []const u8,
        opts: std.fmt.FormatOptions,
        writer: anytype,
        depth: u8,
    ) !void {
        // try writer.print("{s}: ", .{@tagName(pat)});
        switch (pat) {
            .literal => |lit| {
                try writer.writeByte('"');
                try Expr.unescape(.{ .litD = lit.ptr[0..lit.len] }, writer);
                try writer.writeByte('"');
            },
            .nonterm => |id| _ = try writer.print("{}", .{id}),
            .class => |klass| try writer.print("{}", .{klass}),
            .alt => |pats| {
                if (depth != 0) _ = try writer.write("( ");
                for (pats, 0..) |p, i| {
                    if (i != 0) _ = try writer.write(" / ");
                    try formatImpl(p, fmt, opts, writer, depth + 1);
                }
                if (depth != 0) _ = try writer.write(" )");
            },
            .seq => |pats| for (pats, 0..) |p, i| {
                // if (depth > 1) _ = try writer.write("( ");
                if (i != 0) try writer.writeByte(' ');
                try formatImpl(p, fmt, opts, writer, depth + 1);
                // if (depth > 1) _ = try writer.write(" )");
            },
            .many => |ip| {
                try formatImpl(ip.*, fmt, opts, writer, depth);
                try writer.writeByte('*');
            },
            .opt => |ip| {
                try formatImpl(ip.*, fmt, opts, writer, depth);
                try writer.writeByte('?');
            },
            .memo => |patid| {
                _ = try writer.write("{{ ");
                try formatImpl(patid.pat.*, fmt, opts, writer, depth);
                _ = try writer.write(" }}");
            },
            .cap => |patid| {
                _ = try writer.write("{ ");
                try formatImpl(patid.pat.*, fmt, opts, writer, depth);
                _ = try writer.write(" }");
            },
            .eos => _ = try writer.write("!."),
            .empty => {},
            .not => |ip| {
                _ = try writer.writeByte('!');
                try formatImpl(ip.*, fmt, opts, writer, depth);
            },
            .amp => |ip| {
                _ = try writer.writeByte('&');
                try formatImpl(ip.*, fmt, opts, writer, depth);
            },
            .dot => _ = try writer.writeByte('.'),
        }
    }
};
