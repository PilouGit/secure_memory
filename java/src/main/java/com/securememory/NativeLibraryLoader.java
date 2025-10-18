package com.securememory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;

/**
 * Automatically loads the native library from the JAR.
 *
 * This class extracts libsecure_memory.so/.dll/.dylib from the JAR to a temporary directory
 * and loads it with System.load().
 */
public class NativeLibraryLoader {

    private static boolean loaded = false;

    private static File tempLibFile = null;

    /**
     * Loads the appropriate native library for the platform.
     * Returns the path to the extracted library file.
     */
    public static synchronized String loadLibrary() {
        if (loaded) {
            return tempLibFile != null ? tempLibFile.getAbsolutePath() : null;
        }

        try {
            String osName = System.getProperty("os.name").toLowerCase();
            String osArch = System.getProperty("os.arch").toLowerCase();

            String libraryPath = detectLibraryPath(osName, osArch);

            // Extract the library from the JAR to a temporary file
            tempLibFile = extractLibraryFromJar(libraryPath);

            // Load the library
            System.load(tempLibFile.getAbsolutePath());

            loaded = true;

            return tempLibFile.getAbsolutePath();

        } catch (Exception e) {
            throw new RuntimeException("Failed to load native library", e);
        }
    }

    /**
     * Detects the library path based on OS and architecture.
     */
    private static String detectLibraryPath(String osName, String osArch) {
        String libName;
        String platform;

        if (osName.contains("linux")) {
            libName = "libsecure_memory.so";
            platform = "linux";
        } else if (osName.contains("mac") || osName.contains("darwin")) {
            libName = "libsecure_memory.dylib";
            platform = "macos";
        } else if (osName.contains("windows")) {
            libName = "secure_memory.dll";
            platform = "windows";
        } else {
            throw new UnsupportedOperationException("Unsupported OS: " + osName);
        }

        // Detect architecture
        String arch = osArch.contains("64") ? "x86_64" : "x86";

        // Path in JAR: /native/{platform}/{arch}/{libName}
        return String.format("/native/%s/%s/%s", platform, arch, libName);
    }

    /**
     * Extracts the library from the JAR to a temporary file.
     */
    private static File extractLibraryFromJar(String resourcePath) throws Exception {
        // Get the resource stream from the JAR
        InputStream in = NativeLibraryLoader.class.getResourceAsStream(resourcePath);

        if (in == null) {
            // If not in JAR, try to load from system library path
            String libName = extractLibraryName(resourcePath);

            // Try to load with System.loadLibrary (uses LD_LIBRARY_PATH)
            System.loadLibrary(libName);
            throw new RuntimeException("Loaded from system path, not from JAR");
        }

        // Create a temporary file
        String libFileName = resourcePath.substring(resourcePath.lastIndexOf('/') + 1);
        File tempDir = Files.createTempDirectory("securememory-native").toFile();
        tempDir.deleteOnExit();

        File tempLib = new File(tempDir, libFileName);
        tempLib.deleteOnExit();

        // Copy the JAR content to the temporary file
        try (OutputStream out = new FileOutputStream(tempLib)) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        }

        return tempLib;
    }

    /**
     * Extracts the library name (without lib prefix and extension).
     */
    private static String extractLibraryName(String path) {
        String fileName = path.substring(path.lastIndexOf('/') + 1);

        // Remove "lib" prefix if present
        if (fileName.startsWith("lib")) {
            fileName = fileName.substring(3);
        }

        // Remove extension
        int dotIndex = fileName.lastIndexOf('.');
        if (dotIndex > 0) {
            fileName = fileName.substring(0, dotIndex);
        }

        return fileName;
    }

    /**
     * Checks if the library is loaded.
     */
    public static boolean isLoaded() {
        return loaded;
    }
}
