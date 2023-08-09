const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const options = b.addOptions();
    // TODO remove this flag once its possible to construct and use a grammar map at runtime
    const grammar = b.option([]const u8, "grammar", "which grammar to use. " ++
        " must be either 'peg' or 'zig'") orelse "";
    options.addOption([]const u8, "grammar", grammar);

    const parakeet_mod = b.addModule("parakeet", .{
        .source_file = .{ .path = "src/lib.zig" },
        .dependencies = &.{
            .{ .name = "build_options", .module = options.createModule() },
        },
    });

    { // tests
        const unit_tests = b.addTest(.{
            .root_source_file = .{ .path = "src/tests.zig" },
            .target = target,
            .optimize = optimize,
        });
        // unit_tests.filter = "";
        unit_tests.addModule("parakeet", parakeet_mod);
        const run_unit_tests = b.addRunArtifact(unit_tests);
        run_unit_tests.has_side_effects = true;
        const test_step = b.step("test", "Run unit tests");
        test_step.dependOn(&run_unit_tests.step);
    }

    { // examples
        const example_file = b.option([]const u8, "example", "path to example file");
        const example = b.addExecutable(.{
            .name = "example",
            .root_source_file = .{ .path = example_file orelse
                "src/examples/main.zig" },
            .target = target,
            .optimize = optimize,
        });
        example.addModule("parakeet", parakeet_mod);
        b.installArtifact(example);
        const run_cmd = b.addRunArtifact(example);
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        const example_run_step = b.step("example", "Run an example.  use " ++
            "-Dexample=src/examples/file.zig to specify a file.  defaults " ++
            "to src/examples/main.zig.");
        example_run_step.dependOn(&run_cmd.step);
    }

    { // exe
        const exe = b.addExecutable(.{
            .name = "main",
            .root_source_file = .{ .path = "src/main.zig" },
            .target = target,
            .optimize = optimize,
        });
        exe.addModule("parakeet", parakeet_mod);
        b.installArtifact(exe);
        const exe_run = b.addRunArtifact(exe);
        exe_run.step.dependOn(b.getInstallStep());
        if (b.args) |args| {
            exe_run.addArgs(args);
        }
        const exe_run_step = b.step("run", "Run the peg parser");
        exe_run_step.dependOn(&exe_run.step);
    }
}
