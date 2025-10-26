# SecureMemory Java Bindings

Java bindings for the SecureMemory Rust library using JNA (Java Native Access).

## Features

- **AES-256-GCM encryption** at rest
- **Buffer overflow protection** with random canaries
- **Automatic memory zeroing** on close
- **Thread-safe operations**
- Object-oriented API with AutoCloseable support

## Directory Structure

```
java/
├── README.md                           (this file)
├── pom.xml                            (Maven build file)
└── src/main/java/com/securememory/
    ├── SecureMemoryNative.java        (JNA bindings - low-level)
    ├── SecureMemory.java              (High-level wrapper)
    └── Example.java                   (Usage examples)
```

## Prerequisites

1. **Java Development Kit (JDK)** 8 or higher
2. **Maven** (for dependency management)
3. **Compiled Rust library** (`libsecure_memory.so` on Linux, `secure_memory.dll` on Windows, `libsecure_memory.dylib` on macOS)

## Building the Rust Library

First, build the Rust library as a C-compatible shared library:

```bash
# From the project root
cd /home/pilou/myprojects/secure_memory

# Build the library in release mode
cargo build --release --lib

# The library will be in: target/release/libsecure_memory.so (Linux)
```

### Configure Cargo for cdylib

Make sure your `Cargo.toml` includes:

```toml
[lib]
name = "secure_memory"
crate-type = ["lib", "cdylib"]  # Add cdylib for C-compatible shared library
```

## Setting up Maven

Create a `pom.xml` file in the `java/` directory:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>io.github.pilougit.security</groupId>
    <artifactId>secure-memory-java</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>

    <name>SecureMemory Java Bindings</name>
    <description>Java bindings for the SecureMemory Rust library</description>

    <properties>
        <maven.compiler.source>8</maven.compiler.source>
        <maven.compiler.target>8</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>

    <dependencies>
        <!-- JNA for native library access -->
        <dependency>
            <groupId>net.java.dev.jna</groupId>
            <artifactId>jna</artifactId>
            <version>5.14.0</version>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.11.0</version>
            </plugin>
        </plugins>
    </build>
</project>
```

## Compiling the Java Code

```bash
cd java/
mvn clean compile
```

## Running the Example

```bash
# Set the library path to point to the Rust library
export LD_LIBRARY_PATH=../target/release:$LD_LIBRARY_PATH

# Run the example
mvn exec:java -Dexec.mainClass="io.github.pilougit.security.Example"
```

## Usage Example

```java
import io.github.pilougit.security.SecureMemory;
import java.nio.charset.StandardCharsets;

public class MyApp {
    public static void main(String[] args) {
        // Use try-with-resources for automatic cleanup
        try (SecureMemory memory = new SecureMemory(1024)) {

            // Write sensitive data
            String secret = "My password: SuperSecret123!";
            memory.write(secret.getBytes(StandardCharsets.UTF_8));

            // Read it back
            byte[] data = memory.read();
            String retrieved = new String(data, 0, secret.length(), StandardCharsets.UTF_8);
            System.out.println("Retrieved: " + retrieved);

            // Memory is automatically freed and zeroed when exiting this block
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

## API Reference

### `SecureMemory(long size)`
Create a new secure memory buffer.
- **Parameters**: `size` - Size in bytes (must be > 0)
- **Throws**: `IllegalArgumentException` if size <= 0, `SecureMemoryException` if allocation fails

### `void write(byte[] data)`
Write data to the secure memory.
- **Parameters**: `data` - Data to write
- **Throws**: `IllegalStateException` if closed, `SecurityException` if canary corruption detected

### `byte[] read()`
Read all data from the secure memory.
- **Returns**: Copy of the decrypted data
- **Throws**: `IllegalStateException` if closed, `SecurityException` if canary corruption detected

### `byte[] read(int length)`
Read a portion of the secure memory.
- **Parameters**: `length` - Number of bytes to read
- **Returns**: Copy of the decrypted data
- **Throws**: `IllegalArgumentException` if length is invalid

### `long getSize()`
Get the size of the buffer.
- **Returns**: Size in bytes

### `void close()`
Free the memory and zero all data. Called automatically with try-with-resources.

## Error Handling

The library throws specific exceptions:

- `IllegalArgumentException` - Invalid parameters
- `IllegalStateException` - Operation on closed memory
- `SecurityException` - Buffer overflow/canary corruption detected
- `SecureMemoryException` - General operation failure

## Security Considerations

1. **Data is encrypted at rest**: All data in the buffer is AES-256-GCM encrypted when not in use
2. **Canary protection**: Random canaries detect buffer overflows
3. **Memory zeroing**: All memory is zeroed on close/finalize
4. **Thread safety**: Operations are protected by the Rust implementation

## Troubleshooting

### "Unable to load library 'secure_memory'"

Make sure:
1. The Rust library is compiled: `cargo build --release --lib`
2. The library path is set: `export LD_LIBRARY_PATH=../target/release:$LD_LIBRARY_PATH`
3. The library file exists: `ls ../target/release/libsecure_memory.so`

### "java.lang.UnsatisfiedLinkError"

Check that:
1. The Cargo.toml has `crate-type = ["lib", "cdylib"]`
2. The function names match (check with `nm -D target/release/libsecure_memory.so | grep secure_memory`)

### "SECURITY VIOLATION: Buffer overflow detected"

This indicates canary corruption, which means:
1. A buffer overflow occurred
2. Memory corruption was detected
3. The data should not be trusted

This is a security feature - the library detected an attack or bug.

## License

Same license as the parent Rust project.
