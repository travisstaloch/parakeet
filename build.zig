const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const options = b.addOptions();
    const max_stack_option = b.option(u16, "max-stack-size", "maximum parser stack size") orelse 256;
    options.addOption(u16, "max_stack_size", max_stack_option);

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
        const test_filter = b.option([]const u8, "test-filter", "");
        unit_tests.filter = test_filter;
        unit_tests.addModule("parakeet", parakeet_mod);
        unit_tests.main_pkg_path = .{ .path = "." };
        const install_test = b.addInstallArtifact(unit_tests, .{});
        const test_step = b.step("test", "Run unit tests");
        test_step.dependOn(&install_test.step);
        const run_tests_option = b.option(bool, "run-tests", "") orelse true;
        if (run_tests_option) {
            const run_unit_tests = b.addRunArtifact(unit_tests);
            run_unit_tests.has_side_effects = true;
            test_step.dependOn(&run_unit_tests.step);
        }
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
