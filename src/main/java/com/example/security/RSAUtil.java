package com.example.security;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public final class RSAUtil {

    private static final String CIPHER_ALGORITHM = "RSA";

    private RSAUtil() {
        //not called
    }

    /**
     * Constructs a public key (RSA) from the given string
     *
     * @param base64PublicKey PEM Public Key
     * @return RSA Public Key
     */
    public static PublicKey getPublicKey(String base64PublicKey) {
        PublicKey publicKey = null;
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance(CIPHER_ALGORITHM);
            publicKey = keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new Error(e.getMessage());
        } catch (InvalidKeySpecException e) {
            throw new Error(e.getMessage());
        }
        return publicKey;
    }

    /**
     * Constructs a private key (RSA) from the given string
     *
     * @param base64PrivateKey PEM Private Key
     * @return RSA Private Key
     */
    public static PrivateKey getPrivateKey(String base64PrivateKey) {
        PrivateKey privateKey = null;
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance(CIPHER_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new Error(e.getMessage());
        }
        try {
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new Error(e.getMessage());
        }
        return privateKey;
    }

}
