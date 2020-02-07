package com.example.security;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.springframework.stereotype.Service;

@Service
public class RSACipher {

    private static final String MODE_CIPHER = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private Cipher rsaCipherInstance;
    private String publicKey;
    private String privateKey;

    public RSACipher(RSAConfig config) {
        try {
            rsaCipherInstance = Cipher.getInstance(MODE_CIPHER);
            publicKey = config.getPublicKeyFile();
            privateKey = config.getPrivateKeyFile();

            System.out.println("[App]: Public Key");
            System.out.println(publicKey);
            System.out.println("[App]: Private Key");
            System.out.println(privateKey);
        } catch (IOException e) {
          throw new Error(e.getMessage());
        } catch (NoSuchAlgorithmException e) {
          throw new Error(e.getMessage());
        } catch (NoSuchPaddingException e) {
          throw new Error(e.getMessage());
        }
    }

    public synchronized String rsaEncrypt(String value, String publicKey) {
        return Base64.getEncoder().encodeToString(encrypt(value, RSAUtil.getPublicKey(publicKey)));
    }

    public synchronized String rsaDecrypt(String value, String privateKey) {
        return decrypt(Base64.getDecoder().decode(value.getBytes()), RSAUtil.getPrivateKey(privateKey));
    }


    public String decrypt(byte[] data, PrivateKey privateKey) {
        try {
            Cipher cipher = this.rsaCipherInstance;
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(cipher.doFinal(data));
        } catch (BadPaddingException e) {
            throw new Error(e.getMessage());
        } catch (InvalidKeyException e) {
            throw new Error(e.getMessage());
        } catch (IllegalBlockSizeException e) {
          throw new Error(e.getMessage());
        }
    }

    public byte[] encrypt(String data, PublicKey publicKey) {
        try {
            Cipher cipher = this.rsaCipherInstance;
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(data.getBytes());
        } catch (BadPaddingException e) {
            throw new Error(e.getMessage());
        } catch (InvalidKeyException e) {
            throw new Error(e.getMessage());
        } catch (IllegalBlockSizeException e) {
            throw new Error(e.getMessage());
        }
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }
}
