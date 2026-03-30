# Bitcoin Wallet Generator

A command-line tool to generate Bitcoin wallets with private keys (hex and WIF) and addresses. Implemented from scratch using only the Python standard library - no external packages required.

## Features

- Generate any number of wallets in one command.
- Export in `txt`, `csv`, or `json` format.
- Multi-process generation using all available CPU cores.
- Pure Python standard library, no external dependencies.

## Usage

```bash
python wallet_generator.py -n 1000 -f json -o mywallets.json
```

## Arguments

| Argument | Description | Default |
|---|---|---|
| `-n`, `--number` | Number of wallets to generate (required) | - |
| `-f`, `--format` | Export format: `txt`, `csv`, or `json` | `txt` |
| `-o`, `--output` | Output file name | `wallets.<format>` |

## Output fields

Each wallet entry contains:

- `index` - sequential number starting from 1
- `private_key_hex` - raw private key as 64-character hex string
- `private_key_wif` - private key in Wallet Import Format (WIF, compressed)
- `address` - compressed Bitcoin address (P2PKH, starts with `1`)

## Examples

Generate 10 wallets and save as JSON:

```bash
python wallet_generator.py -n 10 -f json -o wallets.json
```

Generate 500 wallets as CSV:

```bash
python wallet_generator.py -n 500 -f csv
```

## Requirements

- Python 3.6+
- No external packages

## Security note

Keep private keys secret. Anyone with access to a private key has full control over the corresponding Bitcoin address.

## License

MIT License.
