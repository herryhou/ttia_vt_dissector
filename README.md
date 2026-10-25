# ttia_vt_dissector

Rust Wireshark dissector for the TTIA 1.5 vehicle telemetry protocol (UDP port 3806, payload magic `APTS`), built with the [wsdf](https://crates.io/crates/wsdf) crate. Functional port of the original Lua dissector (`TTIA1.5.lua`, kept here as the protocol reference).

## Protocol coverage

- 20-byte header: ProtocolID (`APTS`), version, MsgID, CustID, CarID, StorageID, DriverID, Seq, Length
- GPS reports (`MonitorStruct1` 110 B / `MonitorStruct2` 30 B): satellites, fix status, degree-minute → decimal lat/lng, heading, speed, date/time
- MsgID dispatch: register (0x00), route update (0x02), GPS (0x04), event (0x08), ACC report (0x0A), debug text (0x28), malfunction (0xF0), OD report (0xF2), plus acks (0x01/0x03/0x05/0x07/0x09/0x0B/0x29/0xF1/0xF3)
- Event-type sub-dispatch (10 event bodies), OD records with nested ticket lists

Protocol filter: `ttiavt` (registered as `TTIAVT-RS`).

## Build

Requires Wireshark 4.6 dev headers (Homebrew) and Rust (edition 2021).

```bash
PKG_CONFIG_LIBDIR=/tmp/ws_pc cargo build --release
```

`/tmp/ws_pc/wireshark.pc` should contain only:

```
Name: wireshark
Version: 4.6.9
Description: Wireshark library
Libs: -L/opt/homebrew/opt/wireshark/lib -lwireshark
Cflags: -I/opt/homebrew/include
```

Linking only `-lwireshark` (no glib/wsutil) and pointing the dependency at `@rpath/libwireshark.19.dylib` lets one binary work in both Homebrew `tshark` and Wireshark.app without loading a second libwireshark into the app.

## Install

Plugin file must be named `*.so`, and re-signing after every copy is required on macOS:

```bash
cp target/release/libttia_vt_dissector.dylib /tmp/ttia_stage.so
install_name_tool -change /opt/homebrew/opt/wireshark/lib/libwireshark.19.dylib \
    @rpath/libwireshark.19.dylib /tmp/ttia_stage.so
codesign -f -s - /tmp/ttia_stage.so
rm -f ~/.local/lib/wireshark/plugins/4-6/epan/ttia_vt_dissector.so
cp /tmp/ttia_stage.so ~/.local/lib/wireshark/plugins/4-6/epan/ttia_vt_dissector.so
```

Fully quit Wireshark (Cmd+Q) after reinstalling — plugins load once per process. Verify with `tshark -G plugins | grep ttia`.

## Benchmark

9008-frame capture (`ttia_vt_fullSample.pcap`, ~3870 GPS reports), Homebrew Wireshark 4.6.9, best of 3, plugin cost measured against a no-plugin tshark baseline:

| mode | Lua (`TTIA1.5.lua`) | Rust (this plugin) | baseline |
|---|---|---|---|
| plain decode | 0.46 s | **0.12 s** | 0.12 s |
| `-V` (full tree) | 0.68 s | **0.33 s** | — |

- Plain decode: Rust adds nothing measurable over the tshark startup floor; Lua adds ~0.34 s → ~4× faster.
- `-V`: ~62 µs/frame (Lua) vs ~24 µs/frame (Rust) → ~2× faster.

The gap comes from per-field table lookups and value-string calls in interpreted Lua vs native field registration in Rust. Tree rendering cost is identical for both.

## Notes / known quirks

- Truncated frames degrade to a partial tree instead of crashing (root dissection wrapped in `catch_unwind`).
- Ack frames (`*_A`) carry a hidden swallow-all body: wsdf cannot add a subtree at the very end of the tvb, so bodyless variants would throw a spurious "Malformed Packet" on every empty ack.
- A Lua dissector file named `TTIA1.5.lua` can never load — Wireshark's Lua loader does `require("TTIA1.5")` and the dot breaks the module path. Use `TTIA15.lua`.
- If both this plugin and an active Lua dissector register on udp.port 3806, the last one registered wins.
