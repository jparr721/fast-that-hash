# fast-that-hash
Rust port of Bee-San's Name-That-Hash

## Usage

```sh
fth '5f4dcc3b5aa765d61d8327deb882cf99'
fth 'F8:8F:CA:00:11:22'
fth --json '5d41402abc4b2a76b9719d911017c592'
fth secret.txt
fth /path/to/directory
```

Note: Use single quotes `'` as double quotes `"` do not work well on Linux.

### Boundaryless mode

Scan for hashes embedded in text, log lines, or other noisy input:

```sh
fth -b 'the password hash is 5d41402abc4b2a76b9719d911017c592 for admin'
fth -b '2024-01-15 hash=098f6bcd4621d373cade4e832627b4f6 session=5d41402abc4b2a76b9719d911017c592'
fth -b --json 'commit da39a3ee5e6b4b0d3255bfef95601890afd80709 merged'
```

Sub-matches are automatically removed — a SHA-1 won't falsely trigger MD5.
