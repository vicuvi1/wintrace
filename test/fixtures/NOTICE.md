# Test fixtures

These real `.evtx` files are used only to test the EVTX parser against known-good values.
They come from the [python-evtx](https://github.com/williballenthin/python-evtx) test suite
(Apache License 2.0, © Willi Ballenthin and contributors):

- `system.evtx`: originally from the [plaso](https://github.com/log2timeline/plaso) project test data
- `security.evtx`: contributed to python-evtx by Carlos Dias (2017)
- `dns_log_malformed.evtx`: contributed to python-evtx via GitHub issue #37

Expected values in `test/evtx.test.js` (record counts, the first record's fields) match the
assertions in python-evtx's own tests.
