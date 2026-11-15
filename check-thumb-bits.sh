#!/usr/bin/env bash
# Xcode 27
set -euo pipefail

DYLIB="${1:?usage: $0 <dylib>}"
[[ -f "$DYLIB" ]] || {
	echo "[❌] Binary not found: $DYLIB" >&2
	exit 1
}

if ! lipo -archs "$DYLIB" | tr ' ' '\n' | grep -qx armv7; then
	echo "[ℹ️ ] No armv7 slice in $(basename "$DYLIB"), skipping Thumb bit check"
	exit 0
fi

THIN="$(mktemp -t veterishelper-armv7)"
trap 'rm -f "$THIN"' EXIT
if [[ "$(lipo -archs "$DYLIB")" == "armv7" ]]; then
	cp "$DYLIB" "$THIN"
else
	lipo -thin armv7 "$DYLIB" -output "$THIN"
fi

THUMB_ADDRS="$(nm -m "$THIN" | awk '/\(__TEXT,__text\)/ && /\[Thumb\]/ { print tolower($1) }')"

POINTERS="$(otool -ov "$THIN" | awk '$1 == "imp" { print $2 }')"
INIT_OFFSET="$(otool -l "$THIN" | awk '/sectname __mod_init_func/ { found = 1 } found && $1 == "offset" { print $2; exit }')"
INIT_SIZE="$(otool -l "$THIN" | awk '/sectname __mod_init_func/ { found = 1 } found && $1 == "size" { print $2; exit }')"
if [[ -n "$INIT_OFFSET" && -n "$INIT_SIZE" ]]; then
	POINTERS+=$'\n'"$(xxd -s "$INIT_OFFSET" -l "$((INIT_SIZE))" -e -g 4 "$THIN" | awk '{ for (i = 2; i <= NF && $i ~ /^[0-9a-f]{8}$/; i++) print "0x" $i }')"
fi

checked=0
bad=0
while read -r pointer; do
	[[ -n "$pointer" ]] || continue
	checked=$((checked + 1))
	value=$((pointer))
	if ((value % 2 == 0)) && grep -qx "$(printf '%08x' "$value")" <<<"$THUMB_ADDRS"; then
		echo "[❌] Pointer $(printf '0x%x' "$value") targets a Thumb function without the Thumb bit" >&2
		bad=$((bad + 1))
	fi
done <<<"$POINTERS"

if ((checked == 0)); then
	echo "[❌] Found no IMPs or initializers to check in $(basename "$DYLIB")" >&2
	exit 1
fi
if ((bad > 0)); then
	echo "[❌] $bad of $checked armv7 function pointers lack the Thumb bit. Link with Xcode 26.6 (ld-1267), not Xcode 27 (ld-27037)." >&2
	exit 1
fi
echo "[✅] Thumb bits OK ($checked armv7 function pointers checked)"
