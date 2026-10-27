#!/bin/sh
# Builds the crasher programs into crashers/build/ (gitignored), each with a dSYM.
#
#   ct-crasher-segv        null pointer write          EXC_BAD_ACCESS / SIGSEGV
#   ct-crasher-bus         write to a code page        EXC_BAD_ACCESS / SIGBUS
#   ct-crasher-trap        __builtin_trap              EXC_BREAKPOINT / SIGTRAP
#   ct-crasher-overflow    unbounded recursion         EXC_BAD_ACCESS / SIGSEGV
#   ct-crasher-throw       uncaught C++ exception      EXC_CRASH / SIGABRT
#   ct-crasher-swift       Swift fatalError            EXC_BREAKPOINT / SIGTRAP
#   ct-crasher-versioned   same bug, versions 1.0 and 2.0, symbols kept
#   ct-crasher-stripped    same bug, versions 1.0 and 2.0, symbols stripped
#                          (dSYM kept in build/dsyms.noindex/, for --symbolicate)
set -eu
cd "$(dirname "$0")"

OUT=build
rm -rf "$OUT"
mkdir -p "$OUT"

CFLAGS="-g -O0 -Wall -Wno-infinite-recursion"

# Embedded Info.plist so the crash report carries a version for a command-line tool.
write_plist() { # path name short_version build_version
    cat > "$1" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>dev.crashtriage.$2</string>
    <key>CFBundleName</key>
    <string>$2</string>
    <key>CFBundleShortVersionString</key>
    <string>$3</string>
    <key>CFBundleVersion</key>
    <string>$4</string>
</dict>
</plist>
EOF
}

dsym() { # binary
    xcrun dsymutil "$1" -o "$1.dSYM"
}

# Compile and link as separate steps: dsymutil reads the DWARF from the object
# files, so they must still exist when it runs.
mkdir -p "$OUT/obj"

for pair in segv:segv.c bus:bus.c trap:trap.c overflow:overflow.c; do
    name="ct-crasher-${pair%%:*}"
    xcrun clang $CFLAGS -c -o "$OUT/obj/$name.o" "src/${pair#*:}"
    xcrun clang -o "$OUT/$name" "$OUT/obj/$name.o"
    dsym "$OUT/$name"
done

xcrun clang++ $CFLAGS -std=c++17 -c -o "$OUT/obj/ct-crasher-throw.o" src/throw.cpp
xcrun clang++ -o "$OUT/ct-crasher-throw" "$OUT/obj/ct-crasher-throw.o"
dsym "$OUT/ct-crasher-throw"

xcrun swiftc -g -Onone -module-cache-path "$OUT/swift-module-cache" \
    -c -o "$OUT/obj/ct-crasher-swift.o" src/fatal.swift
xcrun swiftc -o "$OUT/ct-crasher-swift" "$OUT/obj/ct-crasher-swift.o"
dsym "$OUT/ct-crasher-swift"

for v in 1 2; do
    for kind in versioned stripped; do
        name="ct-crasher-$kind"
        dir="$OUT/$kind-v$v"
        mkdir -p "$dir"
        write_plist "$dir/Info.plist" "$name" "$v.0" "$v"
        xcrun clang $CFLAGS -DVERSION=$v -c -o "$dir/$name.o" src/versioned.c
        xcrun clang -Wl,-sectcreate,__TEXT,__info_plist,"$dir/Info.plist" \
            -o "$dir/$name" "$dir/$name.o"
        if [ "$kind" = versioned ]; then
            dsym "$dir/$name"
        else
            # ReportCrash finds dSYMs through Spotlight (by UUID) and would
            # symbolicate the "stripped" crash itself. Spotlight skips folders
            # named *.noindex, so the dSYM goes there and the report stays raw.
            mkdir -p "$OUT/dsyms.noindex/$kind-v$v"
            xcrun dsymutil "$dir/$name" -o "$OUT/dsyms.noindex/$kind-v$v/$name.dSYM"
            xcrun strip "$dir/$name"
            # strip invalidates the linker's ad-hoc signature; re-sign so the
            # kernel does not kill the process for a code-signing failure.
            codesign --force --sign - "$dir/$name"
        fi
    done
done

echo "built into $(pwd)/$OUT"
