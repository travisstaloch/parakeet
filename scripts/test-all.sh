set -xe
download=true

if [[ "$download" = true ]]; then
  wget https://github.com/ziglang/zig/raw/master/src/AstGen.zig -O examples/AstGen.zig
  wget https://github.com/simdjson/simdjson/raw/master/jsonexamples/twitter.json -O examples/twitter.json
fi

args="-freference-trace -Dmax-stack-size=4000"

zig build test $args
zig build $args 
zig-out/bin/main examples/zig-grammar.y examples/AstGen.zig
zig-out/bin/main examples/peg.peg examples/peg.peg
zig-out/bin/main examples/json.peg examples/twitter.json
zig-out/bin/main examples/json_memo.peg examples/twitter.json

set +x
zig_files=$(find ../zig/lib -name "*.zig")
set -x
declare -a modes=("recursive" "stack")
for mode in "${modes[@]}"; do
  zig build $args -Doptimize=ReleaseFast -Drun-mode=$mode
  zig-out/bin/main examples/zig-grammar.y examples/AstGen.zig
  cp zig-out/bin/main zig-out/bin/main-$mode
  # zig-out/bin/main examples/zig-grammar.y $(find . -not \( -path ./junk -prune \) -name "*.zig")
  set +x
  zig-out/bin/main examples/zig-grammar.y $zig_files
  set -x
done

sudo ../poop/zig-out/bin/poop "zig-out/bin/main-recursive examples/zig-grammar.y examples/AstGen.zig" "zig-out/bin/main-stack examples/zig-grammar.y examples/AstGen.zig"

if [[ "$download" = true ]]; then
  rm examples/AstGen.zig
  rm examples/twitter.json
fi

