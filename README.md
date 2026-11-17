# Miner-codes

Miners for the Munex testnet (chain 6621). Three miners are included:
a Python miner, a Go miner, and an ESP32 miner. All three connect to
a Munex node and play the maze to win blocks.

## What is inside

- `PC_Miner/python/` — the Python miner
  - `PC_Miner.py` — the miner
  - `requirements.txt` — Python dependencies
  - `INSTRUCTIONS.txt` — setup instructions
  - `show_key.py` — key recovery helper
- `PC_Miner/golang/` — the Go miner
  - `PC_Miner.go` — the miner
  - `go.mod`, `go.sum` — Go module files
  - `INSTRUCTIONS.txt` — setup instructions
  - `show_key.py` — key recovery helper
- `esp.ino` — the ESP32 miner. A single file with no libraries to
  download: WebSockets, JSON and secp256k1 are implemented in the
  file.

## How mining works

Munex blocks are won by a lottery over maze size (Proof of Spatial
Work). A miner grows its maze by catching the goal; the bigger the
maze, the more weight it carries. Only mazes above 5x5x5 are eligible
(weight = size^3 − 125; a size-5 maze has weight 0 and never wins).
A block seals every 50 seconds, and only when an eligible miner
exists: with no eligible miner, no block seals and the chain waits.
The winning miner signs the block; a node never seals a block alone.
The block reward is 1 MCX, paid to the winning miner. The hard cap
is 5,045,958 MCX. See
[consensus.md](https://github.com/Munex-coin/Munex-docs/blob/main/consensus.md)
for the full rules.

## Running a miner

Python miner, in `PC_Miner/python/`:

```
python -m pip install -r requirements.txt
python PC_Miner.py
```

Go miner, in `PC_Miner/golang/`:

```
go mod tidy
go run .
```

ESP32 miner: flash `esp.ino`. It needs a 2.4 GHz WiFi network and a
64-hex private key (or leave the key blank for an NVS-generated
identity). Serial baud is 115200.

## Status

Testnet software (chain 6621). TESTNET CANDIDATE. It has not been
independently audited. See [NOTICE.md](NOTICE.md).

## Related repositories

- [Munex-node](https://github.com/Munex-coin/Munex-node) — the node
- [Munex-API](https://github.com/Munex-coin/Munex-API) — developer API scripts
- [Munex-docs](https://github.com/Munex-coin/Munex-docs) — consensus rules, SVF, and the sample contract
