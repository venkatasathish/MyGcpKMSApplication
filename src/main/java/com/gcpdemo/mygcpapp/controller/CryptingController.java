package com.gcpdemo.mygcpapp.controller;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.gcpdemo.mygcpapp.model.KMSProperties;
import com.gcpdemo.mygcpapp.service.CryptingService;
import com.google.cloud.kms.v1.CryptoKeyName;
import com.google.cloud.kms.v1.CryptoKeyVersionName;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

@RestController
@RequestMapping(path = "/crypting")
public class CryptingController {
	
	@Autowired
	private CryptingService cryptingService;
	
	@Autowired
	private KMSProperties kmsProperties;
	
	@PostMapping(path= "symmetric/encrypt", consumes = "application/json", produces = "application/json")
    public ResponseEntity<String> symmetricEncryptObject(@RequestBody String jsonObject)
    {
		
		byte[] encryptBytes = null;
		try {
			encryptBytes = cryptingService.encrypt(kmsProperties.getProjectId(), kmsProperties.getLocationId(), kmsProperties.getKeyRingId(), kmsProperties.getCryptoKeyId(), jsonObject.getBytes("UTF-8"));
			return new ResponseEntity<>(new String(Base64.getEncoder().encode(encryptBytes),"UTF-8"),HttpStatus.ACCEPTED);
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
		
	
    }
	
	
	@PostMapping(path= "symmetric/decrypt", consumes = "application/json", produces = "application/json")
    public ResponseEntity<String> symmetricDecryptObject(@RequestBody String jsonObject)
    {
		
		byte[] decryptBytes = null;
		try {
			decryptBytes = cryptingService.decrypt(kmsProperties.getProjectId(), kmsProperties.getLocationId(), kmsProperties.getKeyRingId(), kmsProperties.getCryptoKeyId(), Base64.getDecoder().decode(jsonObject.getBytes("UTF-8")));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return new ResponseEntity<>(new String(decryptBytes),HttpStatus.ACCEPTED);
	
    }
	
	
	@PostMapping(path= "asymmetric/encrypt", consumes = "application/json", produces = "application/json")
    public ResponseEntity<String> asymmetricEncryptObject(@RequestBody String jsonObject)
    {
		
		byte[] encryptBytes = null;
		try {
			String resourceName = CryptoKeyVersionName.format(kmsProperties.getProjectId(), kmsProperties.getLocationId(), kmsProperties.getKeyRingId(), kmsProperties.getAsymmCryptoKeyId(),kmsProperties.getAsymmCryptoKeyVer());
			encryptBytes = cryptingService.encryptRSA(resourceName, jsonObject.getBytes("UTF-8"));
			return new ResponseEntity<>(new String(Base64.getEncoder().encode(encryptBytes),"UTF-8"),HttpStatus.ACCEPTED);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
		
	
    }
	
	
	@PostMapping(path= "asymmetric/decrypt", consumes = "application/json", produces = "application/json")
    public ResponseEntity<String> asymmetricDecryptObject(@RequestBody String jsonObject)
    {
		
		byte[] decryptBytes = null;
		try {
			String resourceName = CryptoKeyVersionName.format(kmsProperties.getProjectId(), kmsProperties.getLocationId(), kmsProperties.getKeyRingId(), kmsProperties.getAsymmCryptoKeyId(),kmsProperties.getAsymmCryptoKeyVer());
			decryptBytes = cryptingService.decryptRSA(resourceName, Base64.getDecoder().decode(jsonObject.getBytes("UTF-8")));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return new ResponseEntity<>(new String(decryptBytes),HttpStatus.ACCEPTED);
	
    }
	
	
	@PostMapping(path= "signAsymmetric", consumes = "application/json", produces = "application/json")
    public ResponseEntity<String> signAsymmetric(@RequestBody String jsonObject)
    {
		
		byte[] encryptBytes = null;
		try {
			String resourceName = CryptoKeyVersionName.format(kmsProperties.getProjectId(), kmsProperties.getLocationId(), kmsProperties.getKeyRingId(), kmsProperties.getAsymmSignCryptoKeyId(),kmsProperties.getAsymmSignCryptoKeyVer());
			encryptBytes = cryptingService.signAsymmetric(resourceName, jsonObject.getBytes());
			
			
			System.out.println("Verification Signature:"+cryptingService.verifySignatureRSA(resourceName,jsonObject.getBytes(), encryptBytes));
			
			
			return new ResponseEntity<>(new String(Base64.getEncoder().encode(encryptBytes),"UTF-8"),HttpStatus.ACCEPTED);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;

	
    }
	
	
	@PostMapping(path= "verifySignature", consumes = "application/json", produces = "application/json")
    public ResponseEntity<Boolean> verifySignatureRSA(@RequestBody String jsonObject)
    {
		
		boolean verifySign = false;
		try {
			
			Gson g = new Gson();
			JsonObject obj = g.fromJson(jsonObject, JsonObject.class);
			String resourceName = CryptoKeyVersionName.format(kmsProperties.getProjectId(), kmsProperties.getLocationId(), kmsProperties.getKeyRingId(), kmsProperties.getAsymmSignCryptoKeyId(),kmsProperties.getAsymmSignCryptoKeyVer());
			verifySign = cryptingService.verifySignatureRSA(resourceName,obj.get("message").toString().getBytes("UTF-8"), Base64.getDecoder().decode(obj.get("sign").toString().getBytes("UTF-8")));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return new ResponseEntity<>(verifySign,HttpStatus.ACCEPTED);
	
    }

}
