const std = @import("std");
const mem = std.mem;
const pk = @import("lib.zig");
const Expr = pk.peg.Expr;
const builtin = @import("builtin");
const is_debug_mode = builtin.mode == .Debug;

pub const Result = struct {
    input: pk.Input,
    output: Output,

    const Output = union(enum) {
        err: pk.ParseError,
        // TODO perhaps change ok back to []const u8 now that run()
        // 'returns' by out pointer
        /// start and end indices for input.s
        ok: Ok,
    };

    pub const Ok = [2]u32;

    pub fn err(i: pk.Input) Result {
        return .{ .input = i, .output = .{ .err = error.ParseFailure } };
    }
    pub fn errWith(i: pk.Input, e: pk.ParseError) Result {
        return .{ .input = i, .output = .{ .err = e } };
    }
    pub fn ok(i: pk.Input, s: [2]u32) Result {
        return .{ .input = i, .output = .{ .ok = s } };
    }
};

pub const MemoTable = std.AutoHashMapUnmanaged(Result.Ok, Result);

pub fn ParseContext(comptime CaptureHandler: type) type {
    return struct {
        input: pk.Input,
        rule_id: u32,
        rules: [*]const Rule(PatternMut),
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
        pub const Options = struct {
            allocator: mem.Allocator = pk.failing_allocator,
            mode: Pattern.OptimizeMode = .optimized,
            capture_handler: if (C == void) void else *C =
                if (C == void) {} else undefined,
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

        pub fn onCapture(ctx: *Ctx, capid: u32, ok: Result.Ok) !void {
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
                std.debug.assert(ok[0] <= ok[1]);
                std.debug.assert(ok[1] <= ctx.input.len);
                const s = ctx.input.s[ok[0]..ok[1]];
                // std.debug.print("ok={},{} s={}\n", .{ ok[0], ok[1], s });
                try ctx.capture_handler.onCapture(capid, s);
            }
        }
    };
}

pub fn parse(
    comptime Ctx: type,
    ctx: *Ctx,
    start_rule_id: u32,
    input: []const u8,
) Result {
    ctx.input = pk.input(input);
    ctx.rule_id = start_rule_id;
    ctx.memo.clearRetainingCapacity();

    var result: Result = undefined;
    const pat = ctx.rules[ctx.rule_id].pattern;
    pat.run(Ctx, ctx, &result);

    return result;
}

pub const Literal = struct { ptr: [*]const u8, len: u32 };

/// a data format similar to Expr for encoding parsers
pub const Pattern = union(enum) {
    literal: Literal,
    class: *const Expr.Class,
    alt: []const Pattern,
    seq: []const Pattern,
    many: *const Pattern,
    opt: *const Pattern,
    not: *const Pattern,
    amp: *const Pattern,
    memo: PatternId,
    cap: PatternId,
    nonterm: u32,
    dot,
    eos,
    empty,

    comptime {
        std.debug.assert(24 == @sizeOf(Pattern));
    }
    pub const Tag = std.meta.Tag(Pattern);
    pub const PatternId = struct { pat: *const Pattern, id: u32 };

    pub fn format(
        p: Pattern,
        comptime fmt: []const u8,
        opts: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        return formatImpl(Pattern, @TypeOf(writer).Error, p, fmt, opts, writer, 0);
    }

    pub fn literal(payload: []const u8) Pattern {
        return .{ .literal = .{
            .ptr = payload.ptr,
            .len = @intCast(payload.len),
        } };
    }
    pub fn class(payload: *const Expr.Class) Pattern {
        return .{ .class = payload };
    }
    pub fn alt(payload: []const Pattern) Pattern {
        return .{ .alt = payload };
    }
    pub fn seq(payload: []const Pattern) Pattern {
        return .{ .seq = payload };
    }
    pub fn many(payload: *const Pattern) Pattern {
        return .{ .many = payload };
    }
    pub fn opt(payload: *const Pattern) Pattern {
        return .{ .opt = payload };
    }
    pub fn not(payload: *const Pattern) Pattern {
        return switch (payload.*) {
            .dot => .eos,
            else => .{ .not = payload },
        };
    }
    pub fn amp(payload: *const Pattern) Pattern {
        return .{ .amp = payload };
    }
    pub fn nonterm(payload: u32) Pattern {
        return .{ .nonterm = payload };
    }
    pub fn nontermNamed(name: []const u8, payload: u32) Pattern {
        _ = name;
        return .{ .nonterm = payload };
    }
    pub fn dot() Pattern {
        return .dot;
    }
    pub fn empty() Pattern {
        return .empty;
    }
    pub fn memo(payload: *const Pattern, id: u32) Pattern {
        return .{ .memo = .{ .pat = payload, .id = id } };
    }
    pub fn capture(payload: *const Pattern, id: u32) Pattern {
        return .{ .cap = .{ .pat = payload, .id = id } };
    }

    /// if all choices are charsets or single chars, return a class of the union
    fn combineAlt(pats: []const PatternMut) ?Expr.Class.Set {
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

    fn firstOfSeq(pat: PatternMut) ?PatternMut {
        if (pat != .seq) return null;
        std.debug.assert(pat.seq.len > 0);
        return pat.seq[0];
    }

    pub fn eql(p: PatternMut, other: PatternMut) bool {
        return @as(PatternMut.Tag, p) == @as(PatternMut.Tag, other) and
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
            .memo, .cap => |m| m.id == other.memo.id and eql(m.pat.*, other.memo.pat.*),
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
    fn reduceAlt(pats: []PatternMut, arena: mem.Allocator) !?PatternMut {
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

        const newseq = try arena.alloc(PatternMut, 2);
        newseq[0] = e1;
        newseq[1] = .{ .alt = pats };

        return .{ .seq = newseq };
    }

    /// combine sequences of literals into a single literal
    fn combineSeq(pats: []const PatternMut, arena: mem.Allocator) !?PatternMut {
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
        pat: PatternMut,
        map: Expr.NonTerminalIdMap,
        depth: u8,
        arena: mem.Allocator,
        mode: OptimizeMode,
    ) !PatternMut {
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
            .nonterm => |id| return if (depth < 2)
                try optimizeImpl(gexpr, try fromExpr(arena, gexpr.grammar[id][1], map), map, depth + 1, arena, mode)
            else
                .{ .nonterm = id },
            .dot => return .dot,
            .empty => return .empty,
            .eos => return .eos,
            .memo, .cap => |m| {
                m.pat.* = try optimizeImpl(gexpr, m.pat.*, map, depth, arena, mode);
                return pat;
            },
        };
    }

    pub const OptimizeMode = enum { optimized, unoptimized };

    /// convert 'e' to a PatternMut
    pub fn fromExpr(
        arena: mem.Allocator,
        e: Expr,
        map: Expr.NonTerminalIdMap,
    ) !PatternMut {
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
            inline .amp, .not, .opt => |ie, tag| blk: {
                const ptr = try arena.create(PatternMut);
                ptr.* = try fromExpr(arena, ie.*, map);
                break :blk @unionInit(PatternMut, @tagName(tag), ptr);
            },
            .star => |ie| blk: {
                const ptr = try arena.create(PatternMut);
                ptr.* = try fromExpr(arena, ie.*, map);
                break :blk .{ .many = ptr };
            },
            .plus => |ie| blk: {
                const ptr = try arena.create(PatternMut);
                const pat = try fromExpr(arena, ie.*, map);
                ptr.* = pat;
                const items = try arena.alloc(PatternMut, 2);
                items[0] = pat;
                items[1] = .{ .many = ptr };
                break :blk .{ .seq = items };
            },
            .group => |ie| try fromExpr(arena, ie.*, map),
            .memo => |m| blk: {
                const ptr = try arena.create(PatternMut);
                ptr.* = try fromExpr(arena, m.expr.*, map);
                break :blk .{ .memo = .{ .pat = ptr, .id = m.id } };
            },
            .cap => |m| blk: {
                const ptr = try arena.create(PatternMut);
                ptr.* = try fromExpr(arena, m.expr.*, map);
                break :blk .{ .cap = .{ .pat = ptr, .id = m.id } };
            },
            .alt => |es| blk: {
                const ps = try arena.alloc(PatternMut, es.len);
                for (0..es.len) |i| ps[i] = try fromExpr(arena, es[i], map);
                break :blk .{ .alt = ps };
            },
            .seq => |es| blk: {
                const ps = try arena.alloc(PatternMut, es.len);
                for (0..es.len) |i| ps[i] = try fromExpr(arena, es[i], map);
                break :blk .{ .seq = ps };
            },
            .empty => .empty,
            .grammar => {
                unreachable;
            },
        };
    }

    /// convert the rules from the grammar 'g' to an optimized format
    pub fn optimize(
        gexpr: Expr,
        arena: mem.Allocator,
        mode: OptimizeMode,
    ) ![]const Rule(PatternMut) {
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

        const rules = try arena.alloc(Rule(PatternMut), gexpr.grammar.len);
        // 2. convert grammar to PatternMut and optimize
        for (0..gexpr.grammar.len) |i| {
            rules[i].rule_id = @truncate(i);
            rules[i].rule_name = gexpr.grammar[i][0];
            const pat = try fromExpr(arena, gexpr.grammar[i][1], map);
            rules[i].pattern = try optimizeImpl(gexpr, pat, map, 0, arena, mode);
            // debug("optimize() rule={s} nullability={}\n", .{ @tagName(G.rules[i].rule_id), rules[i].nullability });
        }

        // 3. calculate nullability and first sets
        for (rules) |*rule| {
            rule.nullability = nullability(rule.pattern, rules, rule.rule_id);
            rule.first_set = .{ .bitset = Expr.Class.Set.initEmpty() };
            calcFirstSet(rule.pattern, rules, &rule.first_set, rule.rule_id);
        }
        return rules;
    }

    /// calculate whether 'pat' must consume some input (non-nullable) or if its
    /// possible for it to succeed consuming no input (nullable).  returns .unknown
    /// if a cycle is detected.
    pub fn nullability(
        pat: PatternMut,
        rules: []const Rule(PatternMut),
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
            .memo, .cap => |m| nullability(m.pat.*, rules, start_rule_id),
            .nonterm => |id| if (id == start_rule_id)
                .unknown
            else
                nullability(rules[id].pattern, rules, start_rule_id),
        };
    }

    /// calculate the 'first set' for 'pat'.  this is a set of valid next
    /// input characters for the pattern.
    pub fn calcFirstSet(
        pat: PatternMut,
        rules: []const Rule(PatternMut),
        first_set: *Expr.Class,
        start_rule_id: u32,
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
                    calcFirstSet(p, rules, &c, start_rule_id);
                    first_set.bitset.setUnion(c.bitset);
                }
            },
            .seq => |ps| {
                for (ps) |p| {
                    var c = Expr.Class{ .bitset = Expr.Class.Set.initEmpty() };
                    calcFirstSet(p, rules, &c, start_rule_id);
                    // debug("seq c={}\n", .{Expr{ .class = c }});
                    first_set.bitset.setUnion(c.bitset);
                    if (nullability(p, rules, start_rule_id) == .non_nullable)
                        break;
                }
            },
            .many, .opt => |p| {
                var c = Expr.Class{ .bitset = Expr.Class.Set.initEmpty() };
                calcFirstSet(p.*, rules, &c, start_rule_id);
                first_set.bitset.setUnion(c.bitset);
            },
            .amp => |p| {
                var c = Expr.Class{ .bitset = Expr.Class.Set.initEmpty() };
                calcFirstSet(p.*, rules, &c, start_rule_id);
                first_set.bitset.setIntersection(c.bitset);
            },
            .not => |p| {
                if (p.* == .class) {
                    calcFirstSet(p.*, rules, first_set, start_rule_id);
                    first_set.bitset.toggleAll();
                } else {
                    var c = Expr.Class{ .bitset = Expr.Class.Set.initEmpty() };
                    calcFirstSet(p.*, rules, &c, start_rule_id);
                    first_set.bitset = c.bitset;
                }
            },
            .memo, .cap => |m| calcFirstSet(m.pat.*, rules, first_set, start_rule_id),
            .nonterm => |id| {
                if (id != start_rule_id) {
                    var c = Expr.Class{ .bitset = Expr.Class.Set.initEmpty() };
                    calcFirstSet(rules[id].pattern, rules, &c, start_rule_id);
                    first_set.bitset.setUnion(c.bitset);
                }
            },
            .dot => first_set.bitset = Expr.Class.Set.initFull(),
            .eos, .empty => {},
        }
        // debug("calcFirstSet end {s}={} first_set={}\n", .{ @tagName(pat), pat, first_set.* });
    }
};

pub const Nullability = enum { unknown, non_nullable, nullable };

pub fn Rule(comptime Pat: type) type {
    return struct {
        rule_id: u32,
        rule_name: []const u8,
        pattern: Pat,
        /// set of possible first characters
        first_set: Expr.Class = .{ .bitset = Expr.Class.Set.initEmpty() },
        /// 'nullable' means that the rule may succeed without consuming any input
        nullability: Nullability,

        pub fn init(rule_id: u32, pattern: Pat) @This() {
            return .{
                .rule_id = rule_id,
                .pattern = pattern,
                .first_set = .{ .bitset = Expr.Class.Set.initEmpty() },
                .nullability = .unknown,
            };
        }
    };
}

const debug = std.debug.print;

/// a data format similar to Expr for running parsers
pub const PatternMut = union(enum) {
    literal: Literal,
    class: *const Expr.Class,
    alt: []PatternMut,
    seq: []PatternMut,
    many: *PatternMut,
    opt: *PatternMut,
    not: *PatternMut,
    amp: *PatternMut,
    memo: PatternId,
    cap: PatternId,
    nonterm: u32,
    dot,
    eos,
    empty,

    comptime {
        std.debug.assert(24 == @sizeOf(PatternMut));
    }
    pub const Tag = std.meta.Tag(PatternMut);
    pub const PatternId = struct { pat: *PatternMut, id: u32 };

    pub fn format(
        p: PatternMut,
        comptime fmt: []const u8,
        opts: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        return formatImpl(PatternMut, @TypeOf(writer).Error, p, fmt, opts, writer, 0);
    }

    // run() is recursive so it is optimized to reduce fn call overhead by
    // passing 'ctx' and 'res' as pointers. because of this, they are often
    //  reused below and some control flow may be sligntly non-intuitive.
    pub fn run(
        pat: PatternMut,
        comptime Ctx: type,
        ctx: *Ctx,
        res: *Result,
    ) void {
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
                        debug("{s} first_set {} missing '{?c}'\n", .{ ctx.rules[id].rule_name, rule.first_set, mc });
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
            .cap => |patid| {
                patid.pat.run(Ctx, ctx, res);
                if (res.output == .ok) {
                    ctx.onCapture(patid.id, res.output.ok) catch |e| {
                        res.* = Result.errWith(in, e);
                    };
                }
            },
        }
    }
};

fn formatImpl(
    comptime Pat: type,
    comptime E: type,
    pat: Pat,
    comptime fmt: []const u8,
    opts: std.fmt.FormatOptions,
    writer: anytype,
    depth: u8,
) E!void {
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
                try formatImpl(Pat, E, p, fmt, opts, writer, depth + 1);
            }
            if (depth != 0) _ = try writer.write(" )");
        },
        .seq => |pats| for (pats, 0..) |p, i| {
            if (i != 0) try writer.writeByte(' ');
            try formatImpl(Pat, E, p, fmt, opts, writer, depth + 1);
        },
        .many => |ip| {
            try formatImpl(Pat, E, ip.*, fmt, opts, writer, depth);
            try writer.writeByte('*');
        },
        .opt => |ip| {
            try formatImpl(Pat, E, ip.*, fmt, opts, writer, depth);
            try writer.writeByte('?');
        },
        .memo => |patid| {
            _ = try writer.write("{{ ");
            try formatImpl(Pat, E, patid.pat.*, fmt, opts, writer, depth);
            _ = try writer.write(" }}");
        },
        .cap => |patid| {
            _ = try writer.write("{ ");
            try formatImpl(Pat, E, patid.pat.*, fmt, opts, writer, depth);
            _ = try writer.write(" }");
        },
        .eos => _ = try writer.write("!."),
        .empty => {},
        .not => |ip| {
            _ = try writer.writeByte('!');
            try formatImpl(Pat, E, ip.*, fmt, opts, writer, depth);
        },
        .amp => |ip| {
            _ = try writer.writeByte('&');
            try formatImpl(Pat, E, ip.*, fmt, opts, writer, depth);
        },
        .dot => _ = try writer.writeByte('.'),
    }
}
