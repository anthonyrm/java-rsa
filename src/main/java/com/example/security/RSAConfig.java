package com.example.security;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RSAConfig {

    private static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    private static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";
    private static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";
    private static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";

    @Value("${application.public.key}")
    private String publicKey;

    @Value("${application.private.key}")
    private String privateKey;

    public String getPublicKeyFile() throws IOException {
	    return getKey(publicKey, BEGIN_PUBLIC_KEY, END_PUBLIC_KEY);
    }

    public String getPrivateKeyFile() throws IOException {
	    return getKey(privateKey, BEGIN_PRIVATE_KEY, END_PRIVATE_KEY);
    }

    private String getKey(String key, String beginTextKey, String endTextKey) throws IOException {
      String strKeyPEM = "";
      BufferedReader br = null;
      try {
          br = new BufferedReader(new FileReader(key));
          String line;
          while ((line = br.readLine()) != null) {
            if (!line.equals(beginTextKey) && !line.equals(endTextKey)) {
                strKeyPEM += line;
            }
          }
      } catch (IOException exc) {
          throw exc;
      } finally {
          if (br != null) {
        br.close();
          }
      }

      return strKeyPEM;
    }
}
