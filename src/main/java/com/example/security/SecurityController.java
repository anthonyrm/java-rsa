package com.example.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.CrossOrigin;

import com.example.security.RSACipher;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("${application.api.path}")
public class SecurityController {

  RSACipher rsaCipher;
  
  @Autowired
  public SecurityController(RSACipher rsaCipher) {
      this.rsaCipher = rsaCipher;
  }

  @PostMapping(
      value = "/encrypt",
      produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public EncryptResponse encrypt(@RequestBody EncryptRequest payload) {
    EncryptResponse encryptResponse = new EncryptResponse();
    encryptResponse.setValue(this.rsaCipher.rsaEncrypt(payload.getValue(), this.rsaCipher.getPublicKey()));
    System.out.println("[App]: Encrypting");
    System.out.println("[App]: plain value: " + payload.getValue());
    System.out.println("[App]: encrypted value: " + encryptResponse.getValue());
    return encryptResponse;
  }

  @PostMapping(
      value = "/decrypt",
      produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public DecryptResponse decrypt(@RequestBody DecryptRequest payload) {
    DecryptResponse decryptResponse = new DecryptResponse();
    decryptResponse.setValue(this.rsaCipher.rsaDecrypt(payload.getValue(), this.rsaCipher.getPrivateKey()));
    System.out.println("[App]: Decrypting");
    System.out.println("[App]: encrypted value: " + payload.getValue());
    System.out.println("[App]: plain value: " + decryptResponse.getValue());
    return decryptResponse;
  }
}
