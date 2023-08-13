set -xe
zig build test -freference-trace
touch src/gen/zig-grammar.y.zig src/gen/peg.peg.zig src/gen/json.peg.zig src/gen/json_memo.peg.zig src/gen/c.peg.zig 

zig build run -- examples/zig-grammar.y > src/gen/zig-grammar.y.zig
wget https://github.com/ziglang/zig/raw/master/src/AstGen.zig -O examples/AstGen.zig
zig build -Dgrammar=zig && zig-out/bin/main Root examples/AstGen.zig
zig build run -- examples/peg.peg > src/gen/peg.peg.zig
zig build -Dgrammar=peg && zig-out/bin/main Grammar examples/peg.peg
# zig build run -- examples/c.peg > src/gen/c.peg.zig
zig build run -- examples/json.peg > src/gen/json.peg.zig
wget https://github.com/simdjson/simdjson/raw/master/jsonexamples/twitter.json -O examples/twitter.json
zig build -Dgrammar=json && zig-out/bin/main doc examples/twitter.json
zig build run -- examples/json_memo.peg > src/gen/json_memo.peg.zig
zig build -Dgrammar=json_memo && zig-out/bin/main doc examples/twitter.json

zig build -Dgrammar=zig -Doptimize=ReleaseFast && zig-out/bin/main Root examples/AstGen.zig

rm examples/AstGen.zig
rm examples/twitter.json