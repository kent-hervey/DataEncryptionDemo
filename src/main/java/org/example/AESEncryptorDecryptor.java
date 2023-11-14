package org.example;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Base64;

public class AESEncryptorDecryptor {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;

    public static void main(String[] args) throws Exception {
        // Generate an encryption key
        byte[] key = generateRandomKey();

        System.out.println("Here is the key:  " + key);

        // Store the key in the environment variable
        System.setProperty("ENCRYPTION_KEY", Base64.getEncoder().encodeToString(key));

        // Check if the environment variable is set
        String environmentKey = System.getenv("ENCRYPTION_KEY");
        if (environmentKey != null) {
            System.out.println("Environment variable ENCRYPTION_KEY is set to: " + environmentKey);
        } else {
            System.out.println("Environment variable ENCRYPTION_KEY is not set.");
        }
//
//        // Encrypt the data
//        String plaintext = "This is my secret data!";
//        byte[] ciphertext = encrypt(plaintext, key);
//
//        // Write the ciphertext to the JSON file
//        writeJSONToFile("my_secret_data.json", ciphertext);
//
//        // Read the ciphertext from the JSON file
//        byte[] ciphertextFromFile = readJSONFromFile("my_secret_data.json");
//
//        // Decrypt the data
//
//        String decryptedPlaintext = new String(decrypt(ciphertextFromFile, key), "UTF-8");
//
//
//        //String decryptedPlaintext = decrypt(ciphertextFromFile, key);
//
//        // Print the decrypted plaintext
//        System.out.println(decryptedPlaintext);
    }

    private static byte[] generateRandomKey() throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[32];
        random.nextBytes(key);
        return key;
    }

    private static byte[] encrypt(String plaintext, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParams = new GCMParameterSpec(128, generateRandomIV());
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParams);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());

        return ciphertext;
    }

    private static byte[] decrypt(byte[] ciphertext, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParams = new GCMParameterSpec(128, generateRandomIV());
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParams);
        byte[] plaintext = cipher.doFinal(ciphertext);

        return plaintext;
    }

    private static byte[] generateRandomIV() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[GCM_IV_LENGTH];
        random.nextBytes(iv);
        return iv;
    }

    private static void writeJSONToFile(String filename, byte[] ciphertext) throws IOException {
        FileWriter fileWriter = new FileWriter(filename);
        fileWriter.write(Base64.getEncoder().encodeToString(ciphertext));
        fileWriter.close();
    }

    private static byte[] readJSONFromFile(String filename) throws IOException {
        Path path = Paths.get(filename);
        byte[] ciphertext = Files.readAllBytes(path);
        return ciphertext;
    }

}
