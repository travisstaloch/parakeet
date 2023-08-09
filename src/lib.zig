const std = @import("std");
const mem = std.mem;
pub const FailingAllocator = @import("FailingAllocator.zig");
pub const parsers = @import("parsers.zig");
pub const peg = @import("peg.zig");
pub const util = @import("util.zig");
pub const build_options = @import("build_options");

var failing_allocator_instance = FailingAllocator{};
pub const failing_allocator = failing_allocator_instance.allocator();

pub const When = enum { runtime, @"comptime" };
const root = @import("root");

/// when will the parsers be run.  needed because runtime and comptime semantics
/// are slightly different and can lead to difficult to understand compiler bugs.
/// defaults to `.runtime`.
pub const when: When = if (@hasDecl(root, "when"))
    root.when
else
    .runtime;

pub fn checkRunTime(comptime message: []const u8, comptime note: []const u8) void {
    if ((when == .@"comptime") != @inComptime())
        @compileError(std.fmt.comptimePrint(
            "{s}: when {s} doesn't match @inComptime()={}\n{s}",
            .{ message, @tagName(when), @inComptime(), note },
        ));
}

pub const Input = struct {
    s: [*]const u8,
    len: u32,
    index: u32 = 0,

    pub fn hasCount(i: Input, count: u32) bool {
        return i.index + count < i.len;
    }

    pub fn getAssume(i: Input, offset: u32) u8 {
        return i.s[i.index + offset];
    }

    pub fn get(i: Input, offset: u32) ?u8 {
        if (i.index + offset >= i.len) return null;
        return i.getAssume(offset);
    }

    pub fn hasSliceCount(i: Input, count: u32) bool {
        return i.index + count <= i.len;
    }

    pub fn sliceAssume(i: Input, len: u32) []const u8 {
        return i.s[i.index .. i.index + len];
    }

    pub fn advanceBy(i: Input, count: u32) Input {
        return .{ .s = i.s, .len = i.len, .index = i.index + count };
    }

    pub fn rest(i: Input) []const u8 {
        return i.s[i.index..i.len];
    }

    pub fn restRange(i: Input) [2]u32 {
        return .{ i.index, i.len };
    }

    pub fn range(i: Input, len: u32) [2]u32 {
        return .{ i.index, i.index + len };
    }

    pub fn rangeTo(i: Input, index: u32) [2]u32 {
        return .{ i.index, index };
    }

    pub fn eos(i: Input) bool {
        return i.index >= i.len;
    }

    pub fn startsWith(i: Input, s: []const u8) bool {
        return util.startsWith(i.s[i.index..i.len], s);
    }

    pub fn format(i: Input, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        const r = i.rest();
        const len = @min(10, r.len);
        try writer.print("{}/{} '{}'", .{ i.index, i.len, std.zig.fmtEscapes(r[0..len]) });
    }
};

pub fn input(s: []const u8) Input {
    return .{ .s = s.ptr, .len = @intCast(s.len) };
}

pub const ParseError = error{ ParseFailure, AllocatorRequired } || mem.Allocator.Error;
pub const Options = struct { allocator: ?mem.Allocator = null };

/// a generated enum with tag of all parser names in parsers.zig
pub const Type = blk: {
    const EnumField = std.builtin.Type.EnumField;
    var fields: []const EnumField = &.{};
    var i: usize = 0;
    inline for (std.meta.declarations(parsers)) |decl| {
        if (std.ascii.isLower(decl.name[0])) {
            fields = fields ++ [1]EnumField{.{ .name = decl.name, .value = i }};
            i += 1;
        }
    }
    break :blk @Type(.{ .Enum = .{
        .fields = fields,
        .tag_type = std.math.IntFittingRange(0, i),
        .decls = &.{},
        .is_exhaustive = true,
    } });
};

/// a pointer to an allocated resource along with a cleanup function
/// pointer for the resource.
pub const Resource = struct {
    ptr: ?*anyopaque = null,
    len: usize = 0,
    cleanup: ?Cleanup = null,

    pub const Cleanup = *const fn (
        *anyopaque,
        usize,
        ?mem.Allocator,
    ) void;

    pub fn init(
        comptime T: type,
        ptr: ?*anyopaque,
        len: usize,
    ) Resource {
        return .{
            .ptr = ptr,
            .len = len,
            .cleanup = cleanup(T),
        };
    }

    pub fn cleanup(comptime T: type) Cleanup {
        return struct {
            fn cleanup(
                ptr: *anyopaque,
                len: usize,
                mallocator: ?mem.Allocator,
            ) void {
                // std.debug.print("cleanup({s}) ptr={*} len={}\n", .{ @typeName(T), ptr, len });
                if (len != 0) {
                    const p = @as([*]std.meta.Child(T), @ptrCast(@alignCast(ptr)));
                    const allocator = mallocator orelse
                        @panic("cleanup() missing allocator");
                    allocator.free(p[0..len]);
                }
            }
        }.cleanup;
    }
};

/// 'ParserWithErrorSet(I, O, E)' is a struct with a 'runFn' field
/// and a 'fail_hander' field.  'runFn' is a parser body. 'fail_handler' makes
/// it possible for users to log failures.
/// * Result: `struct{ input: I, output: E!O}`
/// * I: type of first argument to 'run'.  usually `parakeet.Input`
/// * O: payload type of 'Result.output'
/// * E: error set type of 'Result.output'
pub fn ParserWithErrorSet(
    comptime I: type,
    comptime O: type,
    comptime E: type,
) type {
    return struct {
        /// function pointer to parser's body
        runFn: Run,
        // TODO remove fail_handler
        /// initially set to 'default_fail_handler'. users can assign a new
        /// handler with 'onFail()'
        fail_handler: FailHandler,
        /// enum of parser types.  ie .char, .str, .seq. autogenerated from pub
        /// decls in parsers.zig
        type: Type,
        /// a failure message
        message: []const u8 = "",

        pub const Result = struct {
            input: I,
            output: Output,
            /// an error message which may be set using withMessage()
            message: []const u8 = "",
            /// an allocated resource. only slices are currently supported.
            /// when there is a chain of parsers, this field is how later
            /// parsers cleanup resources allocated earlier in the chain.
            resource: Resource = .{},

            pub const Output = union(enum) {
                ok: Ok,
                err: Err,
            };

            pub fn format(
                r: Result,
                comptime _: []const u8,
                _: std.fmt.FormatOptions,
                writer: anytype,
            ) !void {
                try writer.print("{s} {}", .{ @tagName(r.output), r.input });
            }
        };

        const Self = @This();
        pub const Run = *const fn (Self, I, Options) Result;
        pub const Input = I;
        pub const Ok = O;
        pub const Err = E;

        pub fn init(run_: Run, typ: Type, fh: FailHandler) Self {
            return .{ .runFn = run_, .type = typ, .fail_handler = fh };
        }

        pub fn ok(i: I, output: O, resource: Resource) Result {
            return .{
                .input = i,
                .output = .{ .ok = output },
                .resource = resource,
            };
        }

        pub fn err(i: I, resource: Resource) Result {
            return .{
                .input = i,
                .output = .{ .err = error.ParseFailure },
                .resource = resource,
            };
        }

        pub fn errWith(i: I, e: E, resource: Resource) Result {
            return .{
                .input = i,
                .output = .{ .err = e },
                .resource = resource,
            };
        }

        const pk = parsers;
        pub const takeWhile = pk.takeWhile;
        pub const takeWhile1 = pk.takeWhile1;
        pub const takeUntil = pk.takeUntil;
        pub const takeUntil1 = pk.takeUntil1;
        pub const discardR = pk.discardR;
        pub const @"<*" = pk.discardR;
        pub const discardL = pk.discardL;
        pub const @"*>" = pk.discardL;
        pub const map = pk.map;
        pub const mapAlloc = pk.mapAlloc;
        pub const @">>|" = pk.map;
        pub const many = pk.many;
        pub const many1 = pk.many1;
        pub const until = pk.until;
        pub const option = pk.option;
        pub const sepBy = pk.sepBy;
        pub const sepBy1 = pk.sepBy1;
        pub const peek = pk.peek;
        pub const skipMany = pk.skipMany;
        pub const skipMany1 = pk.skipMany1;
        pub const discard = pk.discard;
        pub const asStr = pk.asStr;
        pub const inspect = pk.inspect;
        pub const debug = pk.debug;
        pub const onFail = pk.onFail; // TODO remove
        pub const withMessage = pk.withMessage;

        fn handleErr(self: Self, i: Self.Input) void {
            checkRunTime("handleErr()", "");
            if (@as(
                FailHandler.WriteFn,
                @alignCast(@ptrCast(self.fail_handler.writeFn)),
            )) |writeFn| writeFn(
                i,
                self.type,
                self.message,
                self.fail_handler.writer,
                self.fail_handler.data,
            );
        }

        pub fn run(self: Self, i: Self.Input, opts: Options) Result {
            checkRunTime("run()", "Make sure that the comptime portion of " ++
                "the parser is in a separate statement from run() " ++
                "or wrapped with parens. This allows run() ");
            var r = self.runFn(self, i, opts);
            if (r.output == .err) {
                self.handleErr(i);
                r.message = self.message;

                if (r.resource.ptr) |ptr| {
                    r.resource.cleanup.?(ptr, r.resource.len, opts.allocator);
                    r.resource = .{};
                }
            }
            return r;
        }

        pub fn withType(comptime self: Self, comptime typ: Type) Self {
            var s = self;
            s.type = typ;
            return s;
        }
    };
}

pub const Limits = struct {
    /// the minimum number of bytes or successes required for a parser to
    /// succeed.  default 0.
    min: usize = 0,
    /// the maximum number of bytes or successes a parser may return.  default
    /// `maxInt(usize)`. when a parser stops before 'max' it doesn't fail.
    max: usize = std.math.maxInt(usize),
};

pub const UpperLimit = struct {
    /// the maximum number of bytes or successes a parser may return.  default
    /// `maxInt(usize)`
    max: usize = std.math.maxInt(usize),
};

pub const FailHandler = struct {
    writer: ?*const anyopaque,
    writeFn: WriteFn,
    data: ?*const anyopaque = null,

    pub const WriteFn = ?*const fn (
        Input,
        Type,
        []const u8,
        ?*const anyopaque,
        ?*const anyopaque,
    ) void;

    pub fn init(
        writer: ?*const anyopaque,
        writeFn: WriteFn,
        data: ?*const anyopaque,
    ) FailHandler {
        return .{
            .writer = writer,
            .writeFn = writeFn,
            .data = data,
        };
    }
};

/// does nothing on failure
// TODO make it possible for users to set this
pub const default_fail_handler = FailHandler{ .writer = null, .writeFn = null };

pub fn Parser(comptime I: type, comptime O: type) type {
    return ParserWithErrorSet(I, O, ParseError);
}

pub const StringParser = Parser(Input, []const u8);
pub const ByteParser = Parser(Input, u8);
pub const VoidParser = Parser(Input, void);
pub const BoolParser = Parser(Input, bool);
pub const UsizeParser = Parser(Input, usize);

pub fn Ret(comptime f: anytype) type {
    return @typeInfo(@TypeOf(f)).Fn.return_type.?;
}

pub fn RetErrorSet(comptime f: anytype) type {
    return @typeInfo(Ret(f)).ErrorUnion.error_set;
}

// -------------------
// --- map helpers ---
// -------------------

pub fn toVoid(_: anytype) void {}

pub fn toInt(
    comptime I: type,
    comptime base: u8,
) fn ([]const u8) std.fmt.ParseIntError!I {
    return struct {
        fn func(s: []const u8) std.fmt.ParseIntError!I {
            return try std.fmt.parseInt(I, s, base);
        }
    }.func;
}

pub fn toFloat(
    comptime Float: type,
) fn ([]const u8) std.fmt.ParseFloatError!Float {
    return struct {
        fn func(s: []const u8) std.fmt.ParseFloatError!Float {
            return try std.fmt.parseFloat(Float, s);
        }
    }.func;
}

pub const UnicodeError = RetErrorSet(std.unicode.utf8Decode) ||
    RetErrorSet(std.unicode.utf8ByteSequenceLength);
pub fn toChar(s: []const u8) (UnicodeError || ParseError)!u21 {
    if (s.len > 1) {
        const cp_len = try std.unicode.utf8ByteSequenceLength(s[0]);
        if (cp_len > s.len)
            return error.ParseFailure;
        return try std.unicode.utf8Decode(s[0..cp_len]);
    } else return s[0];
}

pub fn toEnum(comptime E: type) fn ([]const u8) ParseError!E {
    return struct {
        fn func(s: []const u8) ParseError!E {
            return std.meta.stringToEnum(E, s) orelse error.ParseFailure;
        }
    }.func;
}

pub fn toBool(s: []const u8) ParseError!bool {
    const E = enum { true, false };
    return try toEnum(E)(s) == .true;
}

/// read a little-endian binary integer
pub fn toIntLittle(comptime T: type) fn ([]const u8) ParseError!T {
    return struct {
        fn func(s: []const u8) ParseError!T {
            const n = @divExact(@typeInfo(T).Int.bits, 8);
            if (s.len < n) return error.ParseFailure;
            return mem.readIntLittle(T, s[0..n]);
        }
    }.func;
}

/// read a big-endian binary integer
pub fn toIntBig(comptime T: type) fn ([]const u8) ParseError!T {
    return struct {
        fn func(s: []const u8) ParseError!T {
            const n = @divExact(@typeInfo(T).Int.bits, 8);
            if (s.len < n) return error.ParseFailure;
            return mem.readIntBig(T, s[0..n]);
        }
    }.func;
}

pub fn ToStruct(comptime T: type) type {
    return @TypeOf(struct {
        fn func(_: anytype) T {
            return undefined;
        }
    }.func);
}

pub fn toStruct(comptime T: type) ToStruct(T) {
    return struct {
        fn func(tup: anytype) T {
            const fields = @typeInfo(T).Struct.fields;
            if (fields.len != tup.len)
                @compileError("toStruct(): '" ++ @typeName(T) ++ "' and '" ++
                    @typeName(@TypeOf(tup)) ++ "' do not have " ++
                    "same number of fields.  Conversion is not possible.");

            var t: T = undefined;
            inline for (fields, 0..) |field, i|
                @field(t, field.name) = tup[i];

            return t;
        }
    }.func;
}

// -------------------
// - end map helpers -
// -------------------

pub fn printResult(r: anytype) void {
    std.debug.print("{}\n", .{r});
}
