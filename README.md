# cryptomator-py
Prototype for decrypting Cryptomator vaults.

Purpose: to personally verify that Cryptomator’s cryptography is sound and that data remains recoverable, even if the official software is no longer available. The goal is a practical assessment of whether Cryptomator is a suitable option for private data and whether emergency recovery is realistically possible. Reading code alone is not enough for me. I need to work with it and build it myself to understand it and gain confidence.

This repository contains exploratory prototype code only. It is not intended or suitable for production use.

The code was enough for me to decide to use Cryptomator for private files. Since 2024 it has sat unused on my disk. Publishing it on GitHub is mainly for archival reasons. Anyone is free to inspect it, reuse parts of it, or ignore it entirely. Whether I continue working on it depends entirely on whether I need it again.

## TODO
- cleanup
- split in modules
- use pyproject.toml
- add tests
- define cryptonaror vault version
- fix base64 decoding issue relating python version >=3.14.4. works fine in 3.11

## Howto

```bash
python -m venv venv
. venv/bin/acticate.fish
python -m pip install -r requirements.txt
python cryptomator.py
```

## License
MIT

