# Secure Memory

A Rust library for secure memory management operations with automatic memory wiping and constant-time operations.

## Features

- **Secure Memory Allocation**: Safe memory allocation with automatic wiping on drop
- **Constant-Time Operations**: Timing-attack resistant comparison functions
- **Type Safety**: Memory-safe abstractions with comprehensive error handling
- **Zero Dependencies**: Core functionality requires no external dependencies
- **Cross-Platform**: Works on Linux, macOS, and Windows

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
secure_memory = "0.1.0"
```

## Usage

### Basic Usage

```rust
use secure_memory::{SecureBuffer, Result};

fn main() -> Result<()> {
    // Create a secure buffer
    let mut buffer = SecureBuffer::new(256);
    
    // Write sensitive data
    let secret = b"my_secret_password";
    buffer.write_at(0, secret)?;
    
    // Read data back
    let data = buffer.read_at(0, secret.len())?;
    println!("Secret length: {}", data.len());
    
    // Buffer is automatically wiped when dropped
    Ok(())
}
```

### Constant-Time Operations

```rust
use secure_memory::utils;

let password1 = b"secret123";
let password2 = b"secret123";

// Timing-attack resistant comparison
if utils::constant_time_eq(password1, password2) {
    println!("Passwords match!");
}
```

## API Documentation

### `SecureBuffer`

- `new(size: usize) -> Self` - Create a new buffer
- `len(&self) -> usize` - Get buffer length
- `is_empty(&self) -> bool` - Check if buffer is empty
- `write_at(&mut self, offset: usize, data: &[u8]) -> Result<()>` - Write data
- `read_at(&self, offset: usize, len: usize) -> Result<&[u8]>` - Read data
- `wipe(&mut self)` - Manually wipe buffer contents

### Utility Functions

- `utils::constant_time_eq(a: &[u8], b: &[u8]) -> bool` - Constant-time comparison
- `utils::secure_wipe(data: &mut [u8])` - Secure memory wiping

## Project Structure

```
secure_memory/
├── Cargo.toml          # Project configuration and dependencies
├── README.md           # This file
├── .gitignore         # Git ignore rules
├── clippy.toml        # Clippy linting configuration
├── rustfmt.toml       # Code formatting configuration
├── src/               # Source code
│   ├── lib.rs         # Library root and public API
│   ├── main.rs        # Binary entry point
│   ├── buffer.rs      # SecureBuffer implementation
│   ├── error.rs       # Error types and handling
│   └── utils.rs       # Utility functions
├── tests/             # Integration tests
│   └── integration_test.rs
├── examples/          # Usage examples
│   ├── basic_usage.rs
│   └── secure_operations.rs
└── benches/           # Performance benchmarks
    └── buffer_bench.rs
```

## Development

### Running Tests

```bash
# Run unit tests
cargo test

# Run integration tests
cargo test --test integration_test

# Run all tests with output
cargo test -- --nocapture
```

### Running Examples

```bash
# Basic usage example
cargo run --example basic_usage

# Advanced operations example  
cargo run --example secure_operations

# Run the binary
cargo run -- 1024
```

### Benchmarks

```bash
# Run performance benchmarks
cargo bench
```

### Code Quality

```bash
# Format code
cargo fmt

# Run clippy lints
cargo clippy -- -D warnings

# Check documentation
cargo doc --open
```

## Features

### Optional Features

- `serde` - Enable serialization support
- `async` - Enable async/await support

Enable features in `Cargo.toml`:

```toml
[dependencies]
secure_memory = { version = "0.1.0", features = ["serde", "async"] }
```

## Security Considerations

- Memory is wiped using volatile writes to prevent compiler optimizations
- Constant-time operations help prevent timing attacks  
- No sensitive data is logged or exposed in debug output
- Drop implementation ensures cleanup even on panic

## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.