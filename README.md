# INTERMEDIATE--1
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;
import java.util.Base64;

public class PasswordEncryptionExample {

    public static void main(String[] args) throws Exception {
        String password = "yourStrongPassword";
        String encryptedPassword = encrypt(password);
        System.out.println("Encrypted Password: " + encryptedPassword);

        String decryptedPassword = decrypt(encryptedPassword);
        System.out.println("Decrypted Password: " + decryptedPassword);
    }

    public static String encrypt(String password) throws Exception {
        // Salt (8 bytes)
        byte[] salt = {
                (byte) 0x1a, (byte) 0x9c, (byte) 0xef, (byte) 0x51,
                (byte) 0x3f, (byte) 0x86, (byte) 0x91, (byte) 0xf8
        };

        // Number of iterations
        int iterations = 65536;

        // Generate a secret key
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, 128);
        SecretKey secretKey = factory.generateSecret(spec);
        SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");

        // Encryption
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secret);
        byte[] encryptedBytes = cipher.doFinal(password.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedPassword) throws Exception {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedPassword);

        // Salt (8 bytes)
        byte[] salt = {
                (byte) 0x1a, (byte) 0x9c, (byte) 0xef, (byte) 0x51,
                (byte) 0x3f, (byte) 0x86, (byte) 0x91, (byte) 0xf8
        };

        // Number of iterations
        int iterations = 65536;

        // Generate a secret key
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec("yourStrongPassword".toCharArray(), salt, iterations, 128);
        SecretKey secretKey = factory.generateSecret(spec);
        SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");

        // Decryption
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secret);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }
}
