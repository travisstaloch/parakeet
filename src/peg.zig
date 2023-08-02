const std = @import("std");
const mem = std.mem;
const pk = @import("lib.zig");
const ps = pk.parsers;

pub const Charset = union(enum) {
    range: [2]u8,
    one: u8,

    pub fn one(c: u8) Charset {
        return .{ .one = c };
    }
    pub fn range(a: u8, b: u8) Charset {
        return .{ .range = .{ a, b } };
    }
};

pub const Expr = union(enum) {
    ident: []const u8,
    /// single quoted literal
    litS: []const u8,
    /// double quoted literal
    litD: []const u8,
    class: []const Charset,
    dot,
    /// positive lookahead
    amp: *const Expr,
    /// negative lookahead
    not: *const Expr,
    opt: *const Expr,
    star: *const Expr,
    plus: *const Expr,
    group: *const Expr,
    alt: []const Expr,
    seq: []const Expr,
    grammar: []const Def,

    pub const Def = struct { []const u8, Expr };
    pub const Tag = std.meta.Tag(Expr);

    pub fn deinit(e: Expr, allocator: mem.Allocator) void {
        switch (e) {
            .alt, .seq => |es| {
                for (es) |*ie| ie.deinit(allocator);
                allocator.free(es);
            },
            .not, .amp, .opt, .star, .plus, .group => |ie| {
                ie.deinit(allocator);
                allocator.destroy(ie);
            },
            .grammar => |ds| {
                for (ds) |d| d[1].deinit(allocator);
                allocator.free(ds);
            },
            .litD, .litS => |s| allocator.free(s),
            .class => |sets| allocator.free(sets),
            .ident, .dot => {},
        }
    }

    pub fn dot(_: u8) Expr {
        return .dot;
    }
    pub fn initFn(comptime tag: Tag) fn (anytype) Expr {
        return struct {
            fn func(x: anytype) Expr {
                return @unionInit(Expr, @tagName(tag), x);
            }
        }.func;
    }
    const FnAlloc = fn ([]const Expr, ?mem.Allocator) pk.ParseError!Expr;
    pub fn initFnAlloc(comptime tag: Tag) FnAlloc {
        return struct {
            fn func(
                es: []const Expr,
                mallocator: ?mem.Allocator,
            ) pk.ParseError!Expr {
                if (es.len == 1) {
                    const allocator = mallocator orelse
                        return error.AllocatorRequired;
                    defer allocator.free(es);
                    return es[0];
                }
                return @unionInit(Expr, @tagName(tag), es);
            }
        }.func;
    }

    pub fn group(e: Expr, mallocator: ?mem.Allocator) !Expr {
        const allocator = mallocator orelse return error.AllocatorRequired;
        const o = try allocator.create(Expr);
        o.* = e;
        return .{ .group = o };
    }

    pub fn escape(c: u8) ?u8 {
        return switch (c) {
            'a' => '\x07',
            'b' => '\x08',
            'e' => '\x1b',
            'f' => '\x0c',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'v' => '\x0b',
            '\'' => '\'',
            '"' => '"',
            '[' => '[',
            ']' => ']',
            '\\' => '\\',
            else => null,
        };
    }

    pub fn unescapeByte(c: u8, writer: anytype, tag: Tag) !void {
        switch (c) {
            '\x07' => _ = try writer.write("\\a"),
            '\x08' => _ = try writer.write("\\b"),
            '\x1b' => _ = try writer.write("\\e"),
            '\x0c' => _ = try writer.write("\\f"),
            '\n' => _ = try writer.write("\\n"),
            '\r' => _ = try writer.write("\\r"),
            '\t' => _ = try writer.write("\\t"),
            '\x0b' => _ = try writer.write("\\v"),
            '\'' => _ = try writer.write((if (tag == .litS) "\\\'" else "'")),
            '"' => _ = try writer.write((if (tag == .litD) "\\\"" else "\"")),
            '[' => _ = try writer.write((if (tag == .class) "\\[" else "[")),
            ']' => _ = try writer.write((if (tag == .class) "\\]" else "]")),
            '\\' => _ = try writer.write("\\\\"),
            '-' => _ = try writer.write((if (tag == .class) "\\-" else "-")),
            // TODO not sure isPrint() is the correct way to decide if 'c' needs
            // octal escaping
            else => if (std.ascii.isPrint(c))
                try writer.writeByte(c)
            else {
                try writer.writeByte('\\');
                try std.fmt.formatInt(c, 8, .lower, .{}, writer);
            },
        }
    }

    pub fn unescape(e: Expr, writer: anytype) !void {
        switch (e) {
            .litS, .litD => |s| for (s) |c| try unescapeByte(c, writer, e),
            .class => |sets| for (sets) |set| {
                switch (set) {
                    .one => |c| try unescapeByte(c, writer, e),
                    .range => |ab| {
                        try unescapeByte(ab[0], writer, e);
                        try writer.writeByte('-');
                        try unescapeByte(ab[1], writer, e);
                    },
                }
            },
            else => unreachable,
        }
    }

    pub fn format(
        e: Expr,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try e.formatImpl(writer, 0);
    }

    pub fn formatImpl(
        e: Expr,
        writer: anytype,
        depth: u8,
    ) !void {
        switch (e) {
            .ident => |s| _ = try writer.write(s),
            .litS => {
                try writer.writeByte('\'');
                try unescape(e, writer);
                try writer.writeByte('\'');
            },
            .litD => {
                try writer.writeByte('"');
                try unescape(e, writer);
                try writer.writeByte('"');
            },
            .class => {
                try writer.writeByte('[');
                try unescape(e, writer);
                try writer.writeByte(']');
            },
            .dot => try writer.writeByte('.'),
            .seq => |es| for (es, 0..) |ie, i| {
                if (i != 0) try writer.writeByte(' ');
                try ie.formatImpl(writer, depth);
            },
            .alt => |es| for (es, 0..) |ie, i| {
                if (i != 0) _ = try writer.write(if (depth == 0)
                    "\n    / "
                else
                    " / ");
                try ie.formatImpl(writer, depth + 1);
            },
            .not => |ie| {
                try writer.writeByte('!');
                try ie.formatImpl(writer, depth);
            },
            .amp => |ie| {
                try writer.writeByte('&');
                try ie.formatImpl(writer, depth);
            },
            .opt => |ie| {
                try ie.formatImpl(writer, depth);
                try writer.writeByte('?');
            },
            .star => |ie| {
                try ie.formatImpl(writer, depth);
                try writer.writeByte('*');
            },
            .plus => |ie| {
                try ie.formatImpl(writer, depth);
                try writer.writeByte('+');
            },
            .group => |ie| {
                _ = try writer.write("( ");
                try ie.formatImpl(writer, depth + 1);
                _ = try writer.write(" )");
            },
            .grammar => |ds| {
                for (ds, 0..) |d, i| {
                    if (i != 0) try writer.writeByte('\n');
                    _ = try writer.write(d[0]);
                    _ = try writer.write(if (d[1] == .alt)
                        " <-\n      "
                    else
                        " <- ");
                    try d[1].formatImpl(writer, depth);
                }
            },
        }
    }
};

pub fn parseString(
    p: anytype,
    s: []const u8,
    allocator: mem.Allocator,
) !ps.PType(@TypeOf(p)).Ok {
    const r = p.run(pk.input(s), .{ .allocator = allocator });
    if (r.output == .err) {
        // std.debug.print("failed at {} err={}\n", .{ r.input, r.output.err });
        return r.output.err;
    }
    return r.output.ok;
}
