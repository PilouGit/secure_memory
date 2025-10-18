package com.securememory.springboot.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;

/**
 * Charge automatiquement la bibliothèque native depuis le JAR.
 *
 * Cette classe extrait libsecure_memory.so du JAR vers un répertoire temporaire
 * et le charge avec System.load().
 */
public class NativeLibraryLoader {

    private static final Logger log = LoggerFactory.getLogger(NativeLibraryLoader.class);
    private static boolean loaded = false;

    /**
     * Charge la bibliothèque native appropriée pour la plateforme.
     */
    public static synchronized void loadLibrary() {
        if (loaded) {
            log.debug("Library already loaded");
            return;
        }

        try {
            String osName = System.getProperty("os.name").toLowerCase();
            String osArch = System.getProperty("os.arch").toLowerCase();

            log.info("Detecting platform: OS={}, Arch={}", osName, osArch);

            String libraryPath = detectLibraryPath(osName, osArch);

            log.info("Loading native library from: {}", libraryPath);

            // Extraire la bibliothèque du JAR vers un fichier temporaire
            File tempLib = extractLibraryFromJar(libraryPath);

            // Charger la bibliothèque
            System.load(tempLib.getAbsolutePath());

            loaded = true;
            log.info("✓ Native library loaded successfully: {}", tempLib.getAbsolutePath());

        } catch (Exception e) {
            log.error("✗ Failed to load native library", e);
            throw new RuntimeException("Failed to load native library", e);
        }
    }

    /**
     * Détecte le chemin de la bibliothèque en fonction de l'OS et de l'architecture.
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

        // Détecter l'architecture
        String arch = osArch.contains("64") ? "x86_64" : "x86";

        // Chemin dans le JAR: /native/{platform}/{arch}/{libName}
        return String.format("/native/%s/%s/%s", platform, arch, libName);
    }

    /**
     * Extrait la bibliothèque du JAR vers un fichier temporaire.
     */
    private static File extractLibraryFromJar(String resourcePath) throws Exception {
        log.debug("Extracting library from JAR: {}", resourcePath);

        // Obtenir le flux de la ressource depuis le JAR
        InputStream in = NativeLibraryLoader.class.getResourceAsStream(resourcePath);

        if (in == null) {
            // Si pas dans le JAR, essayer de charger depuis le système de fichiers
            log.warn("Library not found in JAR at {}, trying system library path", resourcePath);
            String libName = extractLibraryName(resourcePath);

            // Essayer de charger avec System.loadLibrary (utilise LD_LIBRARY_PATH)
            System.loadLibrary(libName);
            throw new RuntimeException("Loaded from system path, not from JAR");
        }

        // Créer un fichier temporaire
        String libFileName = resourcePath.substring(resourcePath.lastIndexOf('/') + 1);
        File tempDir = Files.createTempDirectory("securememory-native").toFile();
        tempDir.deleteOnExit();

        File tempLib = new File(tempDir, libFileName);
        tempLib.deleteOnExit();

        // Copier le contenu du JAR vers le fichier temporaire
        try (OutputStream out = new FileOutputStream(tempLib)) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        }

        log.debug("Library extracted to: {}", tempLib.getAbsolutePath());

        return tempLib;
    }

    /**
     * Extrait le nom de la bibliothèque (sans lib prefix et extension).
     */
    private static String extractLibraryName(String path) {
        String fileName = path.substring(path.lastIndexOf('/') + 1);

        // Enlever le préfixe "lib" si présent
        if (fileName.startsWith("lib")) {
            fileName = fileName.substring(3);
        }

        // Enlever l'extension
        int dotIndex = fileName.lastIndexOf('.');
        if (dotIndex > 0) {
            fileName = fileName.substring(0, dotIndex);
        }

        return fileName;
    }

    /**
     * Vérifie si la bibliothèque est chargée.
     */
    public static boolean isLoaded() {
        return loaded;
    }
}
