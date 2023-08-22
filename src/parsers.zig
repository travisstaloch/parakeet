const std = @import("std");
const mem = std.mem;
const lib = @import("lib.zig");
const Input = lib.Input;
const input = lib.input;
const FailHandler = lib.FailHandler;
const Parser = lib.Parser;
const ParserWithErrorSet = lib.ParserWithErrorSet;
const Options = lib.Options;
const ParseError = lib.ParseError;
const default_fail_handler = lib.default_fail_handler;
const failing_allocator = lib.failing_allocator;
const StringParser = lib.StringParser;
const ByteParser = lib.ByteParser;
const VoidParser = lib.VoidParser;
const BoolParser = lib.BoolParser;
const UsizeParser = lib.UsizeParser;
const Ret = lib.Ret;
const RetErrorSet = lib.RetErrorSet;
const Limits = lib.Limits;
const UpperLimit = lib.UpperLimit;
const Resource = lib.Resource;

/// a parser that always succeeds with output 'o'.  aka 'return' or 'pure'
pub fn constant(comptime I: type, comptime o: anytype) Parser(I, @TypeOf(o)) {
    const P = Parser(I, @TypeOf(o));
    return .{
        .runFn = struct {
            fn run(_: P, i: P.Input, _: Options) P.Result {
                return P.ok(i, o, .{});
            }
        }.run,
        .fail_handler = default_fail_handler,
        .type = .constant,
    };
}

/// a parser that always fails with 'message'.
pub fn fail(comptime message: []const u8) VoidParser {
    const P = VoidParser;
    return .{
        .runFn = struct {
            fn run(_: P, i: P.Input, _: Options) P.Result {
                return P.err(i, .{});
            }
        }.run,
        .fail_handler = default_fail_handler,
        .type = .fail,
        .message = message,
    };
}

// TODO remove
/// a parser which sets the 'fail_handler' field, allowing users to log parse
/// failures. note that the comptime portion of the parser must be separated
/// from onFail() when using runtime semantics (`runtime == .runtime`).
pub fn onFail(p: anytype, fail_handler: FailHandler) PType(@TypeOf(p)) {
    lib.checkRunTime("onFail()", "");
    return .{
        .runFn = p.runFn,
        .fail_handler = fail_handler,
        .type = p.type,
        .message = p.message,
    };
}

pub fn withMessage(comptime p: anytype, comptime message: []const u8) TypeOf(p) {
    return .{
        .runFn = p.runFn,
        .fail_handler = p.fail_handler,
        .type = p.type,
        .message = p.message ++ message,
    };
}

/// succeeds when input is at end of stream
pub const eos = VoidParser{
    .runFn = struct {
        fn run(_: VoidParser, i: Input, _: Options) VoidParser.Result {
            return if (i.eos())
                VoidParser.ok(i, {}, .{})
            else
                VoidParser.err(i, .{});
        }
    }.run,
    .fail_handler = default_fail_handler,
    .type = .eos,
};

/// always succeeds with bool.  true when input is at end of stream
pub const iseos = BoolParser{
    .runFn = struct {
        fn run(_: BoolParser, i: Input, _: Options) BoolParser.Result {
            return BoolParser.ok(i, i.eos(), .{});
        }
    }.run,
    .fail_handler = default_fail_handler,
    .type = .iseos,
};

/// a parser that always succeeds with the input index
pub const index = Parser(Input, usize){
    .runFn = struct {
        fn run(_: UsizeParser, i: Input, _: Options) UsizeParser.Result {
            return UsizeParser.ok(i, i.index, .{});
        }
    }.run,
    .fail_handler = default_fail_handler,
    .type = .index,
};

/// a parser that always succeeds with the number if remaining input bytes
pub const length = Parser(Input, usize){
    .runFn = struct {
        fn run(_: UsizeParser, i: Input, _: Options) UsizeParser.Result {
            return UsizeParser.ok(i, i.len - i.index, .{});
        }
    }.run,
    .fail_handler = default_fail_handler,
    .type = .length,
};

/// a parser that moves the input index forward by 'count' bytes.  fails if
/// input doesn't have 'count' bytes available.
pub fn forward(comptime count: usize) VoidParser {
    return .{
        .runFn = struct {
            fn run(_: VoidParser, i: Input, _: Options) VoidParser.Result {
                return if (i.hasCount(count))
                    VoidParser.ok(i.advanceBy(count), {}, .{})
                else
                    VoidParser.err(i, .{});
            }
        }.run,
        .fail_handler = default_fail_handler,
        .type = .forward,
    };
}

/// a parser that moves the input index backward by 'count' bytes.  fails if
/// input index is less than 'count'.
pub fn backward(comptime count: usize) VoidParser {
    return .{
        .runFn = struct {
            fn run(_: VoidParser, i: Input, _: Options) VoidParser.Result {
                return if (i.index >= count)
                    VoidParser.ok(.{
                        .s = i.s,
                        .index = i.index - @as(u32, @intCast(count)),
                        .len = i.len,
                    }, {}, .{})
                else
                    VoidParser.err(i, .{});
            }
        }.run,
        .fail_handler = default_fail_handler,
        .type = .backward,
    };
}

/// succeeds with next byte if it equals 'c'
pub fn char(comptime c: u8) ByteParser {
    return .{
        .runFn = struct {
            fn run(_: ByteParser, i: Input, _: Options) ByteParser.Result {
                if (i.get(0)) |ic| {
                    if (ic == c)
                        return ByteParser.ok(i.advanceBy(1), ic, .{});
                }
                return ByteParser.err(i, .{});
            }
        }.run,
        .fail_handler = default_fail_handler,
        .type = .char,
    };
}

/// succeeds with next byte if its not equal to 'c'
pub fn notchar(comptime c: u8) ByteParser {
    return .{
        .runFn = struct {
            fn run(_: ByteParser, i: Input, _: Options) ByteParser.Result {
                const ic = i.get(0) orelse
                    return ByteParser.err(i, .{});
                return if (ic != c)
                    ByteParser.ok(i.advanceBy(1), ic, .{})
                else
                    ByteParser.err(i, .{});
            }
        }.run,
        .fail_handler = default_fail_handler,
        .type = .notchar,
    };
}

/// succeeds with next byte if it satisfies 'f'
pub fn satisfy(comptime f: fn (u8) bool) ByteParser {
    return .{
        .runFn = struct {
            fn run(_: ByteParser, i: Input, _: Options) ByteParser.Result {
                const ic = i.get(0) orelse
                    return ByteParser.err(i, .{});
                return if (f(ic))
                    ByteParser.ok(i.advanceBy(1), ic, .{})
                else
                    ByteParser.err(i, .{});
            }
        }.run,
        .fail_handler = default_fail_handler,
        .type = .satisfy,
    };
}

/// succeeds with return value of 'f' when it is not null
pub fn satisfyOpt(comptime f: fn (u8) ?u8) ByteParser {
    return .{
        .runFn = struct {
            fn run(_: ByteParser, i: Input, _: Options) ByteParser.Result {
                const ic = i.get(0) orelse return ByteParser.err(i, .{});
                return if (f(ic)) |fc|
                    ByteParser.ok(i.advanceBy(1), fc, .{})
                else
                    ByteParser.err(i, .{});
            }
        }.run,
        .fail_handler = default_fail_handler,
        .type = .satisfyOpt,
    };
}

/// succeeds with next byte if within the inclusive range [a..b)
pub fn charRange(comptime a: u8, comptime b: u8) ByteParser {
    return .{
        .runFn = struct {
            fn run(_: ByteParser, i: Input, _: Options) ByteParser.Result {
                const c = i.get(0) orelse
                    return ByteParser.err(i, .{});
                return if (c -% a < b -% a + 1)
                    ByteParser.ok(i.advanceBy(1), c, .{})
                else
                    ByteParser.err(i, .{});
            }
        }.run,
        .fail_handler = default_fail_handler,
        .type = .charRange,
    };
}

/// succeeds with next byte when in 'cs'
pub fn anycharIn(comptime cs: []const u8) ByteParser {
    return .{
        .runFn = struct {
            fn run(_: ByteParser, i: Input, _: Options) ByteParser.Result {
                const ic = i.get(0) orelse
                    return ByteParser.err(i, .{});
                return if (mem.indexOfScalar(u8, cs, ic)) |_|
                    ByteParser.ok(i.advanceBy(1), ic, .{})
                else
                    ByteParser.err(i, .{});
            }
        }.run,
        .fail_handler = default_fail_handler,
        .type = .anycharIn,
    };
}

/// succeeds with next byte when not in 'cs'
pub fn anycharNotIn(comptime cs: []const u8) ByteParser {
    return .{
        .runFn = struct {
            fn run(_: ByteParser, i: Input, _: Options) ByteParser.Result {
                const ic = i.get(0) orelse
                    return ByteParser.err(i, .{});
                return if (mem.indexOfScalar(u8, cs, ic)) |_|
                    ByteParser.err(i, .{})
                else
                    ByteParser.ok(i.advanceBy(1), ic, .{});
            }
        }.run,
        .fail_handler = default_fail_handler,
        .type = .anycharNotIn,
    };
}

/// succeeds with next byte when available
pub const anychar = ByteParser{
    .runFn = struct {
        fn run(_: ByteParser, i: Input, _: Options) ByteParser.Result {
            const ic = i.get(0) orelse
                return ByteParser.err(i, .{});
            return ByteParser.ok(i.advanceBy(1), ic, .{});
        }
    }.run,
    .fail_handler = default_fail_handler,
    .type = .anychar,
};

/// succeeds with 'count' bytes if available
pub fn any(comptime count: usize) StringParser {
    return .{
        .runFn = struct {
            fn run(_: StringParser, i: Input, _: Options) StringParser.Result {
                return if (i.hasSliceCount(count))
                    StringParser.ok(i.advanceBy(count), i.sliceAssume(count), .{})
                else
                    StringParser.err(i, .{});
            }
        }.run,
        .fail_handler = default_fail_handler,
        .type = .any,
    };
}

/// always succeeds with all available bytes
pub const all = StringParser{
    .runFn = struct {
        fn run(_: StringParser, i: Input, _: Options) StringParser.Result {
            const rest = i.rest();
            return StringParser.ok(i.advanceBy(@intCast(rest.len)), rest, .{});
        }
    }.run,
    .fail_handler = default_fail_handler,
    .type = .all,
};

/// succeeds with next bytes if they're equal to 's'
pub fn str(comptime s: []const u8) StringParser {
    return .{
        .runFn = struct {
            fn run(_: StringParser, i: Input, _: Options) StringParser.Result {
                return if (i.startsWith(s))
                    StringParser.ok(i.advanceBy(s.len), i.sliceAssume(s.len), .{})
                else
                    StringParser.err(i, .{});
            }
        }.run,
        .fail_handler = default_fail_handler,
        .type = .str,
    };
}

/// take input while 'f' succeeds.  'byte_limits' limits how many bytes must be
/// returned.  returns a slice of input without allocating.
pub fn takeWhileFn(
    comptime f: fn (u8) bool,
    comptime byte_limits: Limits,
) StringParser {
    return .{
        .runFn = struct {
            fn run(_: StringParser, i: Input, _: Options) StringParser.Result {
                var count: u32 = 0;
                while (i.hasCount(count) and count < byte_limits.max) : (count += 1) {
                    const c = i.getAssume(count);
                    if (!f(c)) break;
                }
                return if (count >= byte_limits.min)
                    StringParser.ok(i.advanceBy(count), i.s[i.index..][0..count], .{})
                else
                    StringParser.err(i.advanceBy(count), .{});
            }
        }.run,
        .fail_handler = default_fail_handler,
        .type = .takeWhileFn,
    };
}

/// same as 'takeWhileFn' but with 'min = 1' and 'max = maxInt(usize)'
pub fn takeWhileFn1(
    comptime f: fn (u8) bool,
) StringParser {
    return takeWhileFn(f, .{ .min = 1 }).withType(.takeWhileFn1);
}

/// take input while 'p' succeeds.  'success_limits' limits how many times 'p'
/// must succeed.  returns a slice of input without allocating.
pub fn takeWhile(
    comptime p: anytype,
    comptime success_limits: Limits,
) StringParser {
    return .{
        .runFn = struct {
            fn run(_: StringParser, i: Input, opts: Options) StringParser.Result {
                var imut = i;
                var count: usize = 0;
                while (!imut.eos() and count < success_limits.max) : (count += 1) {
                    const r = p.run(imut, opts);
                    imut.index = r.input.index;
                    if (r.output == .err) break;
                }
                return if (count >= success_limits.min)
                    StringParser.ok(imut, i.s[i.index..imut.index], .{})
                else
                    StringParser.err(imut, .{});
            }
        }.run,
        .fail_handler = p.fail_handler,
        .type = .takeWhile,
    };
}

/// same as 'takeWhile' but with 'min = 1' and 'max = maxInt(usize)'
pub fn takeWhile1(
    comptime p: anytype,
) StringParser {
    return takeWhile(p, .{ .min = 1 }).withType(.takeWhile1);
}

/// take input until 'f' succeeds.  'byte_limits' limits how many bytes must be
/// returned.  returns a slice of input without allocating.
pub fn takeUntilFn(
    comptime f: fn (u8) bool,
    comptime byte_limits: Limits,
) StringParser {
    return .{
        .runFn = struct {
            fn run(_: StringParser, i: Input, _: Options) StringParser.Result {
                var count: u32 = 0;
                while (i.hasCount(count) and
                    count < byte_limits.max) : (count += 1)
                {
                    const c = i.getAssume(count);
                    if (f(c)) break;
                }
                return if (count >= byte_limits.min)
                    StringParser.ok(
                        i.advanceBy(count),
                        i.s[i.index..][0..count],
                        .{},
                    )
                else
                    StringParser.err(i.advanceBy(count), .{});
            }
        }.run,
        .fail_handler = default_fail_handler,
        .type = .takeUntilFn,
    };
}

/// same as 'takeUntilFn' but with 'min = 1' and 'max = maxInt(usize)'
pub fn takeUntilFn1(
    comptime f: fn (u8) bool,
) StringParser {
    return takeUntilFn(f, .{ .min = 1 }).withType(.takeUntilFn1);
}

/// take input until 'p' succeeds.  'byte_limits' limits how many bytes must be returned.
/// result ends at start of 'p'.  returns a slice of input without allocating.
pub fn takeUntil(
    comptime p: anytype,
    comptime byte_limits: Limits,
) StringParser {
    return .{
        .runFn = struct {
            fn run(_: StringParser, i: Input, opts: Options) StringParser.Result {
                var count: u32 = 0;
                while (i.hasCount(count) and
                    count < byte_limits.max) : (count += 1)
                {
                    const r = p.run(i.advanceBy(count), opts);
                    if (r.output == .ok) break;
                }
                return if (count >= byte_limits.min)
                    StringParser.ok(
                        i.advanceBy(count),
                        i.s[i.index .. i.index + count],
                        .{},
                    )
                else
                    StringParser.err(i.advanceBy(count), .{});
            }
        }.run,
        .fail_handler = p.fail_handler,
        .type = .takeUntil,
    };
}

/// same as 'takeUntil' but with 'min = 1' and 'max = maxInt(usize)'
pub fn takeUntil1(comptime p: anytype) StringParser {
    return takeUntil(p, .{ .min = 1 });
}

pub fn manyUntil(comptime p: anytype, comptime end: anytype) Many(p) {
    const P = Many(p);
    return .{
        .runFn = struct {
            fn run(_: P, i: Input, opts: Options) P.Result {
                var results = std.ArrayListUnmanaged(TypeOf(p).Ok){};
                const allocator = opts.allocator orelse failing_allocator;
                defer results.deinit(allocator);
                var imut = i;
                while (!i.eos()) {
                    const r = end.run(imut, opts);
                    if (r.output == .ok) break;
                    const r2 = p.run(imut, opts);
                    imut.index = r2.input.index;
                    if (r2.output == .err) break;
                    results.append(allocator, r2.output.ok) catch |e|
                        return P.errWith(imut, e, .{});
                }
                // TODO decide whether to return err here when no results
                const slice = results.toOwnedSlice(allocator) catch |e|
                    return P.errWith(imut, e, .{});
                const r = Resource.init(P.Ok, slice.ptr, slice.len);
                return if (imut.index != i.index)
                    P.ok(imut, slice, r)
                else
                    P.err(imut, r);
            }
        }.run,
        .fail_handler = p.fail_handler,
        .type = .manyUntil,
    };
}

pub fn Seq(comptime ps: anytype) type {
    // TODO verify that ps all have same input type?
    comptime {
        var len: usize = 0;
        for (ps) |p| len += @intFromBool(TypeOf(p).Ok != void);
        var fields: [len]std.builtin.Type.StructField = undefined;
        var i: usize = 0;
        var errset = error{};
        for (ps) |p| {
            if (TypeOf(p).Ok != void) {
                fields[i] = .{
                    .type = TypeOf(p).Ok,
                    .is_comptime = false,
                    .default_value = null,
                    .name = std.fmt.comptimePrint("{}", .{i}),
                    .alignment = 0, // TODO verify this is correct
                };
                i += 1;
            }
            errset = errset || TypeOf(p).Err;
        }
        const P = TypeOf(ps[0]);
        return ParserWithErrorSet(P.Input, if (len == 0)
            void
        else if (len == 1)
            fields[0].type
        else
            @Type(.{ .Struct = .{
                .is_tuple = true,
                .layout = .Auto,
                .fields = &fields,
                .decls = &.{},
            } }), errset);
    }
}

/// succeeds when all 'ps' succeed in order.  'ps' may have different output
/// types.  returns a tuple of outputs matching the output types of 'ps'.  void
/// parsers are run but their outputs are not included in the resulting tuple.
/// when there are less than 2 non-void parsers, the result is compacted to a
/// single value rather than a tuple.
pub fn seq(comptime ps: anytype) Seq(ps) {
    const P = Seq(ps);
    return .{
        .runFn = struct {
            fn run(_: P, i: P.Input, opts: Options) P.Result {
                var imut = i;
                var os: P.Ok = undefined;
                comptime var j: usize = 0;
                inline for (ps) |p| {
                    const r = p.run(imut, opts);
                    // std.log.debug("seq n={!}", .{r});
                    if (r.output == .err)
                        return P.errWith(r.input, r.output.err, r.resource);

                    if (TypeOf(p).Ok != void) {
                        if (@typeInfo(P.Ok) != .Struct)
                            os = r.output.ok
                        else
                            os[j] = r.output.ok;
                        j += 1;
                    }
                    // std.log.debug("seq ii={}+{}/{} r={}", .{ ii.index, ii.outer_index, ii.len, r });
                    imut = imut.advanceBy(r.input.index - imut.index);
                }
                return P.ok(imut, os, .{});
            }
        }.run,
        .fail_handler = ps[0].fail_handler,
        .type = .seq,
    };
}

pub fn SeqMap(comptime ps: anytype, comptime f: anytype) type {
    return Map(@as(Seq(ps), undefined), f);
}

/// a parser which maps a sequence of parsers to a function 'f'.  each
/// non-void output from 'ps' becomes an argument of 'f'.  the tuple fields
/// resulting from 'seq' are destructured into the args of 'f'.  for example:
/// `seqMap(.{ char('f'), str("oo") }, someFunc)` with
/// `fn someFunc(c: u8, s: []const u8) bool {...}`
pub fn seqMap(comptime ps: anytype, comptime f: anytype) SeqMap(ps, f) {
    return seq(ps)
        .map(struct {
        fn func(tup: anytype) Ret(f) {
            return if (@typeInfo(@TypeOf(tup)) == .Struct)
                @call(.auto, f, tup)
            else
                f(tup);
        }
    }.func).withType(.seqMap);
}

pub fn seqMapAlloc(comptime ps: anytype, comptime f: anytype) SeqMap(ps, f) {
    return seq(ps)
        .mapAlloc(struct {
        fn func(tup: anytype, mallocator: ?mem.Allocator) Ret(f) {
            return if (@typeInfo(@TypeOf(tup)) == .Struct)
                @call(.auto, f, tup ++ .{mallocator})
            else
                f(tup, mallocator);
        }
    }.func)
        .withType(.seqMapAlloc);
}

pub fn Choice(comptime ps: anytype) type {
    // TODO verify that ps all have same input type?
    comptime {
        var errset = error{};
        for (ps) |p| {
            errset = errset || TypeOf(p).Err;
        }
        const P = TypeOf(ps[0]);
        return ParserWithErrorSet(P.Input, P.Ok, errset);
    }
}

/// succeeds if any of 'ps' succeed with first success.  'ps' must all have the
/// same output type
pub fn choice(comptime ps: anytype) Choice(ps) {
    // TODO nicer compile error if ps don't have same Output
    const P = Choice(ps);
    return .{
        .runFn = struct {
            fn run(_: P, i: P.Input, opts: Options) P.Result {
                inline for (ps) |p| {
                    const r = p.run(i, opts);
                    if (r.output == .ok)
                        return P.ok(r.input, r.output.ok, r.resource);
                }
                return P.err(i, .{});
            }
        }.run,
        .fail_handler = ps[0].fail_handler,
        .type = .choice,
    };
}

/// discardRight. a parser that sequences 'p1' and 'p2' and then discards the
/// result of 'p2', returning the result of 'p1'.  succeeds when 'p1' and 'p2'
/// succeed in order.  aka '<*'.
pub fn discardR(comptime p1: anytype, comptime p2: anytype) TypeOf(p1) {
    const P = TypeOf(p1);
    return .{
        .runFn = struct {
            fn run(_: P, i: Input, opts: Options) P.Result {
                const r1 = p1.run(i, opts);
                // std.log.debug("discardR {s} r1={} i={}", .{ @tagName(p1.type), r1, i });
                if (r1.output == .err) return r1;
                const r2 = p2.run(r1.input, opts);
                // std.log.debug("discardR {s} r2={} i={}", .{ @tagName(p2.type), r2, i });
                if (r2.output == .err)
                    return P.errWith(r2.input, r2.output.err, r1.resource);
                return P.ok(r2.input, r1.output.ok, r1.resource);
            }
        }.run,
        .fail_handler = p1.fail_handler,
        .type = .discardR,
    };
}

/// discardLeft. a parser that sequences 'p1' and 'p2' and then discards the
/// result of 'p1', returning the result of 'p2'.  succeeds when 'p1' and 'p2'
/// succeed in order.  aka '*>'.
pub fn discardL(comptime p1: anytype, comptime p2: anytype) TypeOf(p2) {
    const P = TypeOf(p2);
    return .{
        .runFn = struct {
            fn run(_: P, i: Input, opts: Options) P.Result {
                const r1 = p1.run(i, opts);
                if (r1.output == .err)
                    return P.errWith(r1.input, error.ParseFailure, r1.resource);
                // std.debug.print("i={} r1={}\n", .{ i, r1 });
                const r2 = p2.run(r1.input, opts);
                // std.debug.print("r2={}\n", .{r2});
                return r2;
            }
        }.run,
        .fail_handler = p2.fail_handler,
        .type = .discardL,
    };
}

pub fn PType(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .Struct => T,
        .Pointer => |ptr| ptr.child,
        else => |x| @compileError("ParserType(): typeInfo '" ++ @tagName(x) ++
            "' not supported."),
    };
}

pub fn TypeOf(comptime p: anytype) type {
    return PType(@TypeOf(p));
}

pub fn Map(comptime p: anytype, comptime f: anytype) type {
    const ret_info = @typeInfo(Ret(f));
    const P = TypeOf(p);
    return if (ret_info == .ErrorUnion)
        ParserWithErrorSet(
            P.Input,
            ret_info.ErrorUnion.payload,
            ret_info.ErrorUnion.error_set || P.Err,
        )
    else
        ParserWithErrorSet(P.Input, Ret(f), P.Err);
}

/// p: Parser(A, B)
/// f: fn (B) C
/// returns: Parser(A, C)
/// a parser which converts output of 'p' with 'f'
pub fn map(comptime p: anytype, comptime f: anytype) Map(p, f) {
    const P = Map(p, f);
    return .{
        .runFn = struct {
            fn run(_: P, i: P.Input, opts: Options) P.Result {
                const r = p.run(i, opts);
                // std.debug.print("map r={}\n", .{r});
                if (r.output == .err)
                    return P.errWith(r.input, r.output.err, r.resource);
                const ret_info = @typeInfo(Ret(f));
                return if (ret_info == .ErrorUnion) blk: {
                    const x = f(r.output.ok) catch |e|
                        return P.errWith(i, e, r.resource);
                    break :blk P.ok(r.input, x, r.resource);
                } else P.ok(r.input, f(r.output.ok), r.resource);
            }
        }.run,
        .fail_handler = p.fail_handler,
        .type = .map,
    };
}

/// p: Parser(A, B)
/// f: fn (B, ?mem.Allocator) C
/// returns: Parser(A, C)
/// a parser which converts output of 'p' with 'f'. similar to map() but 'f'
/// has an additional 'allocator' param.
pub fn mapAlloc(comptime p: anytype, comptime f: anytype) Map(p, f) {
    const P = Map(p, f);
    return .{
        .runFn = struct {
            fn run(_: P, i: P.Input, opts: Options) P.Result {
                const r = p.run(i, opts);
                if (r.output == .err)
                    return P.errWith(i, r.output.err, r.resource);
                const ret_info = @typeInfo(Ret(f));
                return if (ret_info == .ErrorUnion) blk: {
                    const x = f(r.output.ok, opts.allocator) catch |e|
                        return P.errWith(i, e, r.resource);
                    break :blk P.ok(r.input, x, r.resource);
                } else P.ok(r.input, f(r.output.ok, opts.allocator), r.resource);
            }
        }.run,
        .fail_handler = p.fail_handler,
        .type = .mapAlloc,
    };
}

pub fn Many(comptime p: anytype) type {
    const P = TypeOf(p);
    return ParserWithErrorSet(P.Input, []const P.Ok, P.Err);
}

/// a parser that runs 'p' many times appending outputs to a list.
/// 'success_limits' limits how many times 'p' must succeed.
pub fn many(
    comptime p: anytype,
    comptime success_limits: Limits,
) Many(p) {
    const P = Many(p);
    return .{
        .runFn = struct {
            fn run(_: P, i: P.Input, opts: Options) P.Result {
                var results = std.ArrayListUnmanaged(TypeOf(p).Ok){};
                const allocator = opts.allocator orelse failing_allocator;
                defer results.deinit(allocator);
                var imut = i;
                while (results.items.len < success_limits.max) {
                    const r = p.run(imut, opts);
                    // std.debug.print("many() r={}\n", .{r});
                    imut.index = r.input.index;
                    if (r.output == .err) {
                        if (results.items.len < success_limits.min)
                            return P.err(imut, .{})
                        else
                            break;
                    }
                    // std.debug.print("many r={}\n", .{r});
                    results.append(allocator, r.output.ok) catch |e|
                        return P.errWith(imut, e, .{});
                }
                // std.debug.print("many results.len={}\n", .{results.items.len});
                const slice = results.toOwnedSlice(allocator) catch |e|
                    return P.errWith(imut, e, .{});

                return P.ok(
                    imut,
                    slice,
                    Resource.init(P.Ok, @ptrCast(slice.ptr), slice.len),
                );
            }
        }.run,
        .fail_handler = p.fail_handler,
        .type = .many,
    };
}

/// same as 'many' but with 'min = 1' and 'max = maxInt(usize)'
pub fn many1(
    comptime p: anytype,
) Many(p) {
    return many(p, .{ .min = 1 }).withType(.many1);
}

/// a parser that takes input until 'end' and feeds the result to 'p'.
/// 'end' is not consumed.
pub fn until(
    comptime p: anytype,
    comptime end: anytype,
) TypeOf(p) {
    const P = TypeOf(p);
    return .{
        .runFn = struct {
            fn run(_: P, i: P.Input, opts: Options) P.Result {
                const r1 = takeUntil(end, .{}).run(i, opts);
                if (r1.output == .err)
                    return P.errWith(r1.input, r1.output.err, r1.resource);
                const len = r1.input.index - i.index;
                const s = i.sliceAssume(len);
                var r2 = p.run(input(s), opts);
                // std.log.debug("until i={} r1={} r2={}", .{ i, r1, r2 });
                return .{
                    .input = if (r2.output == .ok)
                        r1.input
                    else
                        i.advanceBy(r2.input.index),
                    .output = r2.output,
                };
            }
        }.run,
        .fail_handler = p.fail_handler,
        .type = .until,
    };
}

pub fn Option(comptime p: anytype) type {
    const P = TypeOf(p);
    return ParserWithErrorSet(P.Input, []const u8, P.Err);
}

/// a parser that always succeeds with the result of 'p'.  'p's output type is
/// converted to string.  when 'p' fails, no output is consumed and an empty
/// string is output.
pub fn option(comptime p: anytype) Option(p) {
    const P = Option(p);
    return .{
        .runFn = struct {
            fn run(_: P, i: P.Input, opts: Options) P.Result {
                const q = if (TypeOf(p).Ok == []const u8)
                    p
                else
                    p.asStr();
                const r = q.run(i, opts);
                if (r.output == .err) return P.ok(i, i.s[0..0], r.resource);
                return r;
            }
        }.run,
        .fail_handler = p.fail_handler,
        .type = .option,
    };
}

pub fn Optional(comptime p: anytype) type {
    const P = TypeOf(p);
    return ParserWithErrorSet(P.Input, ?P.Ok, P.Err);
}

/// a parser that always succeeds with either the result of 'p' or null.  when
/// 'p' fails, no output is consumed.
pub fn optional(comptime p: anytype) Optional(p) {
    const P = Optional(p);
    return .{
        .runFn = struct {
            fn run(_: P, i: P.Input, opts: Options) P.Result {
                const r = p.run(i, opts);
                if (r.output == .err) return P.ok(i, null, r.resource);
                return P.ok(r.input, r.output.ok, r.resource);
            }
        }.run,
        .fail_handler = p.fail_handler,
        .type = .optional,
    };
}

/// a parser that runs 'p' interspersed with 'sep' many times appending 'p's
/// output to a list until 'p' fails.  'sep' outputs are discarded.
/// 'success_limits' limits how many times 'p' must succeed. requires allocator.
pub fn sepBy(
    comptime p: anytype,
    comptime sep: anytype,
    comptime success_limits: Limits,
) Many(p) {
    const P = Many(p);
    return .{
        .runFn = struct {
            fn run(_: P, i: P.Input, opts: Options) P.Result {
                var results = std.ArrayListUnmanaged(TypeOf(p).Ok){};
                const allocator = opts.allocator orelse failing_allocator;
                defer results.deinit(allocator);

                var imut = i;
                while (!imut.eos() and results.items.len < success_limits.max) {
                    const r1 = p.run(imut, opts);
                    imut.index = r1.input.index;
                    if (r1.output == .ok) {
                        results.append(allocator, r1.output.ok) catch |e|
                            return P.errWith(imut, e, r1.resource);
                    } else break;

                    const r2 = sep.run(imut, opts);
                    imut.index = r2.input.index;
                    if (r2.output == .err)
                        break;
                }
                return if (results.items.len < success_limits.min)
                    P.err(imut, .{})
                else blk: {
                    const slice = results.toOwnedSlice(allocator) catch |e|
                        return P.errWith(imut, e, .{});
                    break :blk P.ok(imut, slice, Resource.init(
                        P.Ok,
                        @ptrCast(slice.ptr),
                        slice.len,
                    ));
                };
            }
        }.run,
        .fail_handler = p.fail_handler,
        .type = .sepBy,
    };
}

/// same as 'sepBy' but with 'min = 1' and 'max = maxInt(usize)'
pub fn sepBy1(
    comptime p: anytype,
    comptime sep: anytype,
) Many(p) {
    return sepBy(p, sep, .{ .min = 1 }).withType(.sepBy1);
}

/// a parser that doesn't advance input and always succeeds with an optional
/// next byte or null if eos
pub const peekChar = Parser(Input, ?u8){
    .runFn = struct {
        const P = Parser(Input, ?u8);
        fn run(_: P, i: Input, _: Options) P.Result {
            return P.ok(i, i.get(0), .{});
        }
    }.run,
    .fail_handler = default_fail_handler,
    .type = .peekChar,
};

/// a parser that doesn't advance input and succeeds with next byte if available
/// or fails
pub const peekCharFail = ByteParser{
    .runFn = struct {
        fn run(_: ByteParser, i: Input, _: Options) ByteParser.Result {
            return if (i.get(0)) |c|
                ByteParser.ok(i, c, .{})
            else
                ByteParser.err(i, .{});
        }
    }.run,
    .fail_handler = default_fail_handler,
    .type = .peekCharFail,
};

/// a parser that doesn't advance input and succeeds with next 'count' bytes if
/// available or fails
pub fn peekString(comptime count: usize) StringParser {
    return .{
        .runFn = struct {
            fn run(_: StringParser, i: Input, _: Options) StringParser.Result {
                return if (i.hasSliceCount(count))
                    StringParser.ok(i, i.sliceAssume(count), .{})
                else
                    StringParser.err(i, .{});
            }
        }.run,
        .fail_handler = default_fail_handler,
        .type = .peekString,
    };
}

/// positive lookahead. a parser that doesn't advance input and returns output
/// of running 'p'
pub fn peek(comptime p: anytype) TypeOf(p) {
    const P = TypeOf(p);
    return .{
        .runFn = struct {
            fn run(_: P, i: Input, opts: Options) P.Result {
                const r = p.run(i, opts);
                return if (r.output == .ok)
                    P.ok(i, r.output.ok, r.resource)
                else
                    P.errWith(i, r.output.err, r.resource);
            }
        }.run,
        .fail_handler = p.fail_handler,
        .type = .peek,
    };
}

/// negative lookahead. never consumes any input and inverts the result of 'p'.
pub fn peekNot(comptime p: anytype) VoidParser {
    const P = VoidParser;
    return .{
        .runFn = struct {
            fn run(_: P, i: P.Input, opts: Options) P.Result {
                const r = p.run(i, opts);
                return if (r.output == .err)
                    P.ok(i, {}, r.resource)
                else
                    P.err(i, r.resource);
            }
        }.run,
        .fail_handler = default_fail_handler,
        .type = .peekNot,
    };
}

/// a parser that discards output of 'p'.  'success_limits' limits how many times
/// 'p' must succeed.
pub fn skipMany(
    comptime p: anytype,
    comptime success_limits: Limits,
) Parser(TypeOf(p).Input, void) {
    const P = Parser(TypeOf(p).Input, void);
    return .{
        .runFn = struct {
            fn run(_: P, i: Input, opts: Options) P.Result {
                var imut = i;
                var count: usize = 0;
                while (!imut.eos() and count < success_limits.max) : (count += 1) {
                    const r = p.run(imut, opts);
                    if (r.output == .err) break;
                    imut.index = r.input.index;
                }
                return if (count >= success_limits.min)
                    P.ok(imut, {}, .{})
                else
                    P.err(imut, .{});
            }
        }.run,
        .fail_handler = p.fail_handler,
        .type = .skipMany,
    };
}

/// same as 'skipMany' but with 'min = 1' and 'max = maxInt(usize)'
pub fn skipMany1(
    comptime p: anytype,
) Parser(TypeOf(p).Input, void) {
    return skipMany(p, .{ .min = 1 }).withType(.skipMany1);
}

pub fn Discard(comptime p: anytype) type {
    const P = TypeOf(p);
    return ParserWithErrorSet(P.Input, void, P.Err);
}

/// a parser that converts 'p's output type to void
pub fn discard(comptime p: anytype) Discard(p) {
    return p.map(lib.toVoid).withType(.discard);
}

/// a parser that converts 'p's output type to void
pub fn discardSeq(comptime ps: anytype) Discard(@as(Seq(ps), undefined)) {
    return seq(ps).discard().withType(.discardSeq);
}

/// convert 'p' into a parser that outputs a `[]const u8` by discarding the
/// result of 'p' and returning the input slice from 'p's start to end.
pub fn asStr(comptime p: anytype) Parser(TypeOf(p).Input, []const u8) {
    const P = Parser(TypeOf(p).Input, []const u8);
    return .{
        .runFn = struct {
            fn run(_: P, i: P.Input, opts: Options) P.Result {
                const r = p.run(i, opts);
                if (r.output == .err) return .{
                    .input = i,
                    .output = .{ .err = r.output.err },
                };
                return P.ok(r.input, i.s[i.index..r.input.index], r.resource);
            }
        }.run,
        .fail_handler = p.fail_handler,
        .type = .asStr,
    };
}

/// a parser that runs 'p' and passes its result to 'f' before returning it.
/// this is meant to be a convenient way to print-debug parser results.  it can
/// be used with 'printResult'.  for example:
/// `some_parser.inspect(parakeet.printResult)`.
pub fn inspect(comptime p: anytype, comptime f: anytype) TypeOf(p) {
    const P = TypeOf(p);
    return .{
        .runFn = struct {
            fn run(_: P, i: P.Input, opts: Options) P.Result {
                const r = p.run(i, opts);
                f(r);
                return r;
            }
        }.run,
        .fail_handler = p.fail_handler,
        .type = p.type,
    };
}

pub fn debug(comptime p: anytype) TypeOf(p) {
    return p.inspect(lib.printResult);
}

/// a parser that accepts from one to 'max_digits' digits allowing for 'base'
/// and the signedness of 'T'.  for example: when base=2, only 0s and 1s are
/// accepted.  and if 'T' is signed, a leading '+' or '-' are accepted.
pub fn intToken(
    comptime T: type,
    comptime max_digits: UpperLimit,
    comptime base: u8,
) Parser(Input, []const u8) {
    // TODO limit max tokens by int size
    const sign = if (@typeInfo(T).Int.signedness == .signed)
        option(anycharIn("+-"))
    else
        constant(Input, {});

    const digit = switch (base) {
        2...10 => charRange('0', '0' + base - 1),
        16 => choice(.{
            charRange('0', '9'),
            charRange('a', 'f'),
            charRange('A', 'F'),
        }),
        else => @compileError(std.fmt.comptimePrint(
            "base '{}' not supported.  expected 2..10, 16.",
            .{base},
        )),
    };

    return seq(.{
        sign,
        digit.takeWhile(.{ .min = 1, .max = max_digits.max }),
    })
        .withType(.intToken)
        .asStr();
}

/// a parser that converts digits into an integer of type 'T'.  it is simply
/// `intToken(T, max_digits, base).map(toInt(T, base))`
pub fn int(
    comptime T: type,
    comptime max_digits: UpperLimit,
    comptime base: u8,
) ParserWithErrorSet(Input, T, std.fmt.ParseIntError || ParseError) {
    return comptime intToken(T, max_digits, base)
        .map(lib.toInt(T, base))
        .withType(.int);
}

const EnumField = std.builtin.Type.EnumField;
const SortContext = struct {
    fields: []EnumField,

    pub fn lessThan(comptime ctx: @This(), a: usize, b: usize) bool {
        return ctx.fields[a].name.len > ctx.fields[b].name.len;
    }

    pub fn swap(comptime ctx: @This(), a: usize, b: usize) void {
        return std.mem.swap(EnumField, &ctx.fields[a], &ctx.fields[b]);
    }
};

fn sortedEnumFields(comptime E: type) []const EnumField {
    const fs = @typeInfo(E).Enum.fields;
    var fields = fs[0..fs.len].*;
    mem.sortUnstableContext(0, fields.len, SortContext{ .fields = &fields });
    return &fields;
}

/// a parser that succeeds when input starts with any tag name from 'E'.  'E's
/// fields are sorted at comptime descending by length so that the longer tag
/// names will match first.  the first matching tag is returned so all tags
/// don't need to be checked.  for example, `enum{foo, foobar}` and input "foobar"
/// will match the tag 'foobar'.
pub fn enumeration(comptime E: type) Parser(Input, E) {
    const P = Parser(Input, E);
    return .{
        .runFn = struct {
            fn run(_: P, i: Input, _: Options) P.Result {
                inline for (sortedEnumFields(E)) |f| {
                    if (i.startsWith(f.name))
                        return P.ok(
                            i.advanceBy(f.name.len),
                            @enumFromInt(f.value),
                            .{},
                        );
                }
                return P.err(i, .{});
            }
        }.run,
        .fail_handler = default_fail_handler,
        .type = .enumeration,
    };
}

/// a parser that nests a parser in a function 'f'.  this indirection allows
/// for creating recursive grammars and makes it possible to work around what
/// would otherwise be 'dependency loop' errors.
pub fn ref(comptime f: anytype) Ret(f) {
    const P = Ret(f);
    return .{
        .runFn = struct {
            fn run(_: P, i: Input, opts: Options) P.Result {
                return f().run(i, opts);
            }
        }.run,
        // TODO don't lose P's fail_handler?
        .fail_handler = default_fail_handler,
        .type = .ref,
    };
}

pub fn Scan(comptime State: type) type {
    return Parser(Input, struct { []const u8, ?State });
}

/// a parser that will accumulate input while 'f' returns a non-null value.
/// returns a tuple of accumulated input and final state:
/// `struct {[]const u8, ?State}`
pub fn scan(
    comptime State: type,
    comptime init_state: State,
    comptime f: fn (State, u8) ?State,
) Scan(State) {
    const P = Scan(State);
    return .{
        .runFn = struct {
            fn run(_: P, i: Input, _: Options) P.Result {
                const start = i.index;
                if (start >= i.len) return P.err(i, .{});
                var imut = i;
                var state = init_state;
                while (imut.get(0)) |c| {
                    state = f(state, c) orelse
                        return if (imut.index == i.index)
                        P.err(i, .{})
                    else
                        P.ok(imut, .{ i.s[start..imut.index], null }, .{});
                    imut = imut.advanceBy(1);
                }
                // std.debug.print("scan ok s={s}\n", .{i.s[start .. imut.index]});

                return if (imut.index == i.index)
                    P.err(i, .{})
                else
                    P.ok(imut, .{ i.s[start..imut.index], state }, .{});
            }
        }.run,
        .fail_handler = default_fail_handler,
        .type = .scan,
    };
}

/// a parser that is the same as 'scan()' except that it only returns a string,
/// discarding the final state.
pub fn scanString(
    comptime State: type,
    comptime init_state: State,
    comptime f: fn (State, u8) ?State,
) StringParser {
    return scan(State, init_state, f)
        .map(struct {
        fn func(r: Scan(State).Ok) []const u8 {
            return r[0];
        }
    }.func);
}

pub fn FoldWhile(comptime p: anytype, comptime T: type) type {
    return Parser(TypeOf(p).Input, T);
}

/// a parser that loops while 'p' succeeds, passing a 'state' and the parse
/// result to 'f'. 'state' begins with the value 'init_state'.
pub fn foldWhile(
    comptime init_state: anytype,
    comptime p: anytype,
    comptime f: fn (*@TypeOf(init_state), TypeOf(p).Ok) void,
) FoldWhile(p, @TypeOf(init_state)) {
    const P = FoldWhile(p, @TypeOf(init_state));
    return .{
        .runFn = struct {
            fn run(_: P, i: P.Input, opts: Options) P.Result {
                var state = init_state;
                var imut = i;
                while (true) {
                    const r = p.run(imut, opts);
                    if (r.output == .err) break;
                    imut.index = r.input.index;
                    f(&state, r.output.ok);
                }
                return if (imut.index == i.index)
                    P.err(i, .{})
                else
                    P.ok(imut, state, .{});
            }
        }.run,
        .fail_handler = default_fail_handler,
        .type = .foldWhile,
    };
}

/// a parser that only accepts digits of the given 'base' (aka radix)
pub fn digits(comptime base: u8) StringParser {
    return takeWhile1(charRange('0', '0' + base - 1)).withType(.digits);
}
