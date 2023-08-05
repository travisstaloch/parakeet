const std = @import("std");
const mem = std.mem;

pub fn startsWith(comptime T: type, haystk: []const T, needle: []const T) bool {
    return if (needle.len > haystk.len)
        false
    else
        eql(T, haystk[0..needle.len], needle);
}

pub const eql = if (@import("build_options").eql_naive) eqlNaive else eqlFast;

pub fn eqlNaive(comptime T: type, a: []const T, b: []const T) bool {
    for (a, b) |a_elem, b_elem| {
        if (a_elem != b_elem) return false;
    }
    return true;
}

pub fn eqlFast(comptime T: type, a: []const T, b: []const T) bool {
    const U = usize;
    const size = @sizeOf(U);
    var index: usize = 0;
    while (true) : (index += size) {
        if (index + size >= b.len) break;
        const ai = mem.readIntNative(U, a.ptr[index..][0..size]);
        const bi = mem.readIntNative(U, b.ptr[index..][0..size]);
        if (ai != bi) return false;
    }
    return eqlNaive(T, a.ptr[index..b.len], b.ptr[index..b.len]);
}

/// Comptime string map optimized for small sets of disparate string keys.
/// Works by separating the keys by length at comptime and only checking strings of
/// equal length at runtime.
///
/// `kvs_list` expects a list of `struct { []const u8, V }` (key-value pair) tuples.
/// You can pass `struct { []const u8 }` (only keys) tuples if `V` is `void`.
pub fn ComptimeStringMap(comptime V: type, comptime kvs_list: anytype) type {
    const precomputed = comptime blk: {
        @setEvalBranchQuota(1500);
        const KV = struct {
            key: []const u8,
            value: V,
        };
        var sorted_kvs: [kvs_list.len]KV = undefined;
        for (kvs_list, 0..) |kv, i| {
            if (V != void) {
                sorted_kvs[i] = .{ .key = kv.@"0", .value = kv.@"1" };
            } else {
                sorted_kvs[i] = .{ .key = kv.@"0", .value = {} };
            }
        }

        const SortContext = struct {
            kvs: []KV,

            pub fn lessThan(ctx: @This(), a: usize, b: usize) bool {
                return ctx.kvs[a].key.len < ctx.kvs[b].key.len;
            }

            pub fn swap(ctx: @This(), a: usize, b: usize) void {
                return std.mem.swap(KV, &ctx.kvs[a], &ctx.kvs[b]);
            }
        };
        mem.sortUnstableContext(0, sorted_kvs.len, SortContext{ .kvs = &sorted_kvs });

        const min_len = sorted_kvs[0].key.len;
        const max_len = sorted_kvs[sorted_kvs.len - 1].key.len;
        var len_indexes: [max_len + 1]usize = undefined;
        var len: usize = 0;
        var i: usize = 0;
        while (len <= max_len) : (len += 1) {
            // find the first keyword len == len
            while (len > sorted_kvs[i].key.len) {
                i += 1;
            }
            len_indexes[len] = i;
        }
        break :blk .{
            .min_len = min_len,
            .max_len = max_len,
            .sorted_kvs = sorted_kvs,
            .len_indexes = len_indexes,
        };
    };

    return struct {
        /// Array of `struct { key: []const u8, value: V }` where `value` is `void{}` if `V` is `void`.
        /// Sorted by `key` length.
        pub const kvs = precomputed.sorted_kvs;

        /// Checks if the map has a value for the key.
        pub fn has(str: []const u8) bool {
            return get(str) != null;
        }

        /// Returns the value for the key if any, else null.
        pub fn get(str: []const u8) ?V {
            if (str.len < precomputed.min_len or str.len > precomputed.max_len)
                return null;

            var i = precomputed.len_indexes[str.len];
            while (true) {
                const kv = precomputed.sorted_kvs[i];
                if (kv.key.len != str.len)
                    return null;
                if (kv.key.ptr == str.ptr or eql(u8, kv.key, str))
                    return kv.value;
                i += 1;
                if (i >= precomputed.sorted_kvs.len)
                    return null;
            }
        }
    };
}
