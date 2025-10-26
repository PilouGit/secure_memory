# Memory Security Verification

This guide explains how to verify that `SecureMemory` does not leave traces of secrets in memory.

## Why Verify Memory?

When you store passwords or other sensitive data in a JVM, they can persist in:
- **JVM heap**: String objects, byte arrays
- **Native memory**: allocations via JNI/JNA
- **Core dumps**: if the process crashes
- **Swap**: if memory is swapped to disk

`SecureMemory` is designed to:
1. Store data in **native memory** (outside JVM heap)
2. **Lock** memory to prevent swapping (`mlock`)
3. **Zero** memory on release
4. **Detect corruption** with canaries

## Verification Methods

### Method 1: Automated Test with Script

The easiest way is to use the provided script:

```bash
cd java
./verify-memory-security.sh
```

This script will:
1. Start a Java program with SecureMemory
2. Create a heap dump
3. Search for the secret in the dump
4. Report whether the secret was found or not

**Expected result**: The secret should **NOT** be found in the heap.

### Method 2: Manual Verification with jmap

#### Step 1: Compile and run the test program

```bash
cd java
mvn compile

# Run MemoryLeakDemo
java -cp target/classes:$(mvn dependency:build-classpath -q -DincludeScope=runtime -Dmdep.outputFile=/dev/stdout) \
    io.github.pilougit.security.MemoryLeakDemo
```

The program will display its PID and wait 60 seconds.

#### Step 2: Create a heap dump

In another terminal:

```bash
# Replace <PID> with the displayed PID
jmap -dump:format=b,file=heap.hprof <PID>
```

#### Step 3: Search for the secret in the heap dump

```bash
# Search for the password in the dump
strings heap.hprof | grep "MyTopSecretPassword@2025!"

# If FOUND: the secret leaked (normal String)
# If NOT FOUND: the secret was erased (SecureMemory)
```

### Method 3: VisualVM (GUI)

1. **Start VisualVM**:
   ```bash
   jvisualvm
   ```

2. **Attach to the Java process**:
   - Select the process from the list
   - Click "Heap Dump"

3. **Analyze the dump**:
   - "Classes" tab → search for `String`
   - "Instances" tab → examine values
   - Use OQL (Object Query Language) search:
     ```javascript
     select s from java.lang.String s where s.toString().contains("MyTopSecret")
     ```

4. **Expected result**:
   - Secret stored in a normal `String` will be found
   - Secret stored in `SecureMemory` will **NOT** be found

### Method 4: Native Memory Verification (Linux)

This method requires root permissions.

#### Option A: Create a core dump

```bash
# Get the Java process PID
PID=$(jps | grep MemoryLeakDemo | awk '{print $1}')

# Create a core dump
sudo gcore $PID

# Search for the secret in the core dump
strings core.$PID | grep "MyTopSecretPassword@2025!"
```

#### Option B: Read /proc/[pid]/mem

```bash
# Search directly in process memory
sudo grep -a "MyTopSecretPassword@2025!" /proc/$PID/mem 2>/dev/null && echo "FOUND" || echo "NOT FOUND"
```

**Note**: This method may find the secret even after it has been erased from the JVM heap, because of:
- Strings in log messages
- Temporary copies created for display
- SecureMemory native memory **before** its `close()`

### Method 5: Programmatic Test with MemorySecurityTester

```bash
cd java
mvn compile

java -cp target/classes:$(mvn dependency:build-classpath -q -DincludeScope=runtime -Dmdep.outputFile=/dev/stdout) \
    io.github.pilougit.security.MemorySecurityTester
```

This program will:
1. Create a normal String and verify it persists in memory
2. Create a SecureMemory and verify it does not persist
3. Display the results

## Unit Tests

Unit tests verify SecureMemory behavior:

```bash
cd java
mvn test
```

Included tests:
- `testBasicReadWrite`: basic read/write operations
- `testMemoryIsZeroedAfterClose`: verify close() makes operations impossible
- `testCanaryDetection`: corruption detection
- `testZeroingByteArrays`: manual byte array zeroing

## Best Practices

### ✅ DO

```java
// 1. Use try-with-resources for automatic cleanup
try (SecureMemory sm = new SecureMemory(256)) {
    sm.write(password.getBytes(StandardCharsets.UTF_8));
    byte[] data = sm.read();

    // Use the data
    processPassword(data);

    // Clear the array immediately after use
    for (int i = 0; i < data.length; i++) {
        data[i] = 0;
    }
}
// SecureMemory is automatically closed and zeroed here

// 2. Clear byte arrays after use
byte[] sensitive = getSensitiveData();
try {
    useSensitiveData(sensitive);
} finally {
    for (int i = 0; i < sensitive.length; i++) {
        sensitive[i] = 0;
    }
}

// 3. Use char[] instead of String for passwords
char[] password = getPasswordFromUser();
try {
    // Convert to bytes for SecureMemory
    byte[] passwordBytes = new String(password).getBytes(StandardCharsets.UTF_8);
    try (SecureMemory sm = new SecureMemory(256)) {
        sm.write(passwordBytes);
        // ...
    } finally {
        for (int i = 0; i < passwordBytes.length; i++) {
            passwordBytes[i] = 0;
        }
    }
} finally {
    for (int i = 0; i < password.length; i++) {
        password[i] = '\0';
    }
}
```

### ❌ DON'T

```java
// 1. DON'T use String for secrets
String password = "MyPassword123!"; // STAYS IN MEMORY!

// 2. DON'T forget to close SecureMemory
SecureMemory sm = new SecureMemory(256);
sm.write(data);
// ... Forgot close() → memory leak

// 3. DON'T log or print secrets
System.out.println("Password: " + password); // STAYS IN MEMORY!
logger.info("Secret: {}", secret); // STAYS IN MEMORY!

// 4. DON'T reuse SecureMemory after close()
try (SecureMemory sm = new SecureMemory(256)) {
    sm.write(data);
}
sm.read(); // ERROR: already closed
```

## Verification Limitations

### What can cause false positives:

1. **String interning**: JVM may cache Strings in the pool
2. **Log messages**: Logs may contain copies of the secret
3. **Stack traces**: Exceptions may capture values
4. **Garbage collector**: Data may persist until GC
5. **JIT compilation**: Compiler may create temporary copies
6. **Debugger**: Inspected variables persist in memory

### Solutions:

- **Avoid String**: Use `char[]` or `byte[]`
- **Avoid logs**: Never log secrets
- **Clear quickly**: Zero arrays immediately after use
- **Force GC**: Call `System.gc()` (not guaranteed)
- **Disable JIT for tests**: `-Xint` (very slow)

## Additional Tools

### Memory Analyzer Tool (MAT)

```bash
# Download MAT: https://eclipse.dev/mat/
# Analyze a heap dump
java -jar mat/MemoryAnalyzer.jar heap.hprof
```

### GDB (for native memory debugging)

```bash
# Attach GDB to the process
sudo gdb -p <PID>

# Search for a string in memory
(gdb) find /s 0x7f0000000000, 0x7fffffffffff, "MyTopSecret"

# Examine memory at an address
(gdb) x/100s 0x7ffff7a00000
```

## Results Interpretation

| Result | Meaning | Action |
|--------|---------|--------|
| Secret found in heap after String | Normal | String is not secure, use SecureMemory |
| Secret found in heap after SecureMemory.close() | **PROBLEM** | Bug in SecureMemory, investigate |
| Secret NOT found in heap after SecureMemory.close() | **CORRECT** | SecureMemory works correctly |
| Secret found in /proc/mem before close() | Normal | SecureMemory is still open |
| Secret found in /proc/mem after close() | **PROBLEM** | Zeroing did not work |

## Conclusion

For maximum security:

1. ✅ Use `SecureMemory` for sensitive data
2. ✅ Always use `try-with-resources`
3. ✅ Clear `byte[]` immediately after use
4. ✅ Avoid `String` for secrets
5. ✅ Never log or print secrets
6. ✅ Test regularly with verification tools

Memory security is an ongoing process. Use these tools regularly to verify that no secrets leak.
