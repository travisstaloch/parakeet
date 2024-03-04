set -xe
download=true

if [[ "$download" = true ]]; then
  wget https://github.com/ziglang/zig-spec/raw/master/grammar/grammar.y -O examples/zig-grammar.y
  wget https://github.com/ziglang/zig/raw/master/lib/std/zig/AstGen.zig -O examples/AstGen.zig
  wget https://github.com/simdjson/simdjson/raw/master/jsonexamples/twitter.json -O examples/twitter.json
fi

args=-freference-trace

zig build test $args
zig build $args 
zig-out/bin/main examples/zig-grammar.y examples/AstGen.zig
zig-out/bin/main examples/peg.peg examples/peg.peg
zig-out/bin/main examples/json.peg examples/twitter.json
zig-out/bin/main examples/json_memo.peg examples/twitter.json

zig build $args -Doptimize=ReleaseFast 
zig-out/bin/main examples/zig-grammar.y examples/AstGen.zig
# zig-out/bin/main examples/zig-grammar.y $(find . -not \( -path ./junk -prune \) -name "*.zig")
zig-out/bin/main examples/zig-grammar.y $(find ../zig/lib -name "*.zig")

if [[ "$download" = true ]]; then
  rm examples/AstGen.zig
  rm examples/twitter.json
fi

