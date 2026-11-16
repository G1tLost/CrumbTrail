# Third-party notices

The optional `evtx` extra installs `python-evtx==0.8.1`, an independent Apache-2.0 Python package by Willi Ballenthin and contributors. CrumbTrail uses its BinXML APIs; no parser source is vendored or relicensed here. Its dependency metadata includes `hexdump`. See the [primary repository](https://github.com/williballenthin/python-evtx) and [Apache license](https://github.com/williballenthin/python-evtx/blob/4d8ba92d934d8c08975ecb325124d480249312a6/LICENSE.TXT). The exact adapter verifies the installed parser version before reading EVTX; future upgrades need independent source-field and oracle validation.

The optional external EVTX validation corpus is listed in `docs/evtx-corpus.json` and is **not bundled or relicensed** by this repository. The pinned Velocidex/velociraptor source repository declares GNU AGPL version 3 in its root LICENSE. Fixture-specific collection history and consent are not established by that license. Validation retains downloaded data and all identifying records privately; public documentation contains aggregate results and source hashes only. Consult the pinned license and source before any redistribution.

The Windows JSONL fixture, Velociraptor artifact definitions, and event-interpretation/correlation logic were adapted from Bacon Egg and Cheese (BEC) 0.5.0. No BEC runtime or cloud-provider modules are included. Original license:

MIT License

Copyright (c) 2026 Bacon Egg and Cheese contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
