## Install to wireshark

```bash
rm -f ~/.local/lib/wireshark/plugins/4-6/epan/ttia_vt_dissector.so
cp target/release/libttia_vt_dissector.dylib ~/.local/lib/wireshark/plugins/4-6/epan/ttia_vt_dissector.so
codesign -f -s - ~/.local/lib/wireshark/plugins/4-6/epan/ttia_vt_dissector.so
```