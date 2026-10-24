# Building WASP

Use Python 3.8 or later. A virtual environment keeps the capture dependencies separate from system Python.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install pytest
python -m pytest -q
python wasp.py --help
```

Offline replay requires no root. Live capture requires Scapy capture support, suitable OS permissions and a compatible interface. WASP does not configure monitor mode. Linux mode observation requires `iw`; USB inventory requires `lsusb` on Linux or `system_profiler` on macOS. Missing commands produce unavailable results.

For macOS packaging, install PyInstaller into the same environment and run `./make_dmg.sh`. Packaging was not exercised in the October 24 audit. Do not describe the old 1.0.0 DMG as a tested build of the current source.
