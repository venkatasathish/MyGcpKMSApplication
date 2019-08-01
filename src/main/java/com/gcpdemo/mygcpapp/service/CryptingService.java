package com.gcpdemo.mygcpapp.service;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.google.cloud.kms.v1.AsymmetricDecryptResponse;
import com.google.cloud.kms.v1.AsymmetricSignRequest;
import com.google.cloud.kms.v1.AsymmetricSignResponse;
import com.google.cloud.kms.v1.CryptoKeyName;
import com.google.cloud.kms.v1.DecryptResponse;
import com.google.cloud.kms.v1.Digest;
import com.google.cloud.kms.v1.EncryptResponse;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyManagementServiceSettings;
import com.google.common.io.BaseEncoding;
import com.google.protobuf.ByteString;

@Service
public class CryptingService {
	
	@Autowired 
	KeyManagementServiceSettings keyManagementServiceSettings;
	
	/**
	 * Encrypts the given plaintext using the specified crypto key.
	 */
	public byte[] encrypt(
	    String projectId, String locationId, String keyRingId, String cryptoKeyId, byte[] plaintext)
	    throws IOException {

	  // Create the KeyManagementServiceClient using try-with-resources to manage client cleanup.
	  try (KeyManagementServiceClient client = KeyManagementServiceClient.create(keyManagementServiceSettings)) {

	    // The resource name of the cryptoKey
	    String resourceName = CryptoKeyName.format(projectId, locationId, keyRingId, cryptoKeyId);

	    // Encrypt the plaintext with Cloud KMS.
	    EncryptResponse response = client.encrypt(resourceName, ByteString.copyFrom(plaintext));

	    // Extract the ciphertext from the response.
	    return response.getCiphertext().toByteArray();
	  }
	}
	//projects/gcp-demo-247008/locations/us-central1/keyRings/cloudkmstest/cryptoKeys/cloudkmstestkey
	
	/**
	 * Decrypts the provided ciphertext with the specified crypto key.
	 */
	public byte[] decrypt(
	    String projectId, String locationId, String keyRingId, String cryptoKeyId, byte[] ciphertext)
	    throws IOException {

	  // Create the KeyManagementServiceClient using try-with-resources to manage client cleanup.
	  try (KeyManagementServiceClient client = KeyManagementServiceClient.create(keyManagementServiceSettings)) {

	    // The resource name of the cryptoKey
	    String resourceName = CryptoKeyName.format(projectId, locationId, keyRingId, cryptoKeyId);

	    // Decrypt the ciphertext with Cloud KMS.
	    DecryptResponse response = client.decrypt(resourceName, ByteString.copyFrom(ciphertext));

	    // Extract the plaintext from the response.
	    return response.getPlaintext().toByteArray();
	  }
	}
	
	
	
	public byte[] encryptRSA(String keyName, byte[] plaintext)
		    throws IOException, GeneralSecurityException {
		  // Create the Cloud KMS client.
		  try (KeyManagementServiceClient client = KeyManagementServiceClient.create(keyManagementServiceSettings)) {
		    // Get the public key
		    com.google.cloud.kms.v1.PublicKey pub = client.getPublicKey(keyName);
		    String pemKey = pub.getPem();
		    pemKey = pemKey.replaceFirst("-----BEGIN PUBLIC KEY-----", "");
		    pemKey = pemKey.replaceFirst("-----END PUBLIC KEY-----", "");
		    pemKey = pemKey.replaceAll("\\s", "");
		    byte[] derKey = BaseEncoding.base64().decode(pemKey);
		    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(derKey);
		    PublicKey rsaKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);

		    // Encrypt plaintext for the 'RSA_DECRYPT_OAEP_2048_SHA256' key.
		    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		    OAEPParameterSpec oaepParams = new OAEPParameterSpec(
		        "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
		    cipher.init(Cipher.ENCRYPT_MODE, rsaKey, oaepParams);

		    return cipher.doFinal(plaintext);
		  }
		}
	
	public byte[] decryptRSA(String keyName, byte[] ciphertext) throws IOException {
		  // Create the Cloud KMS client.
		  try (KeyManagementServiceClient client = KeyManagementServiceClient.create(keyManagementServiceSettings)) {
		    AsymmetricDecryptResponse response = client.asymmetricDecrypt(
		        keyName, ByteString.copyFrom(ciphertext));
		    return response.getPlaintext().toByteArray();
		  }
		}
	
	
	
	public  byte[] signAsymmetric(String keyName, byte[] message)
		    throws IOException, NoSuchAlgorithmException {
		  // Create the Cloud KMS client.
		  try (KeyManagementServiceClient client = KeyManagementServiceClient.create(keyManagementServiceSettings)) {

		    // Note: some key algorithms will require a different hash function
		    // For example, EC_SIGN_P384_SHA384 requires SHA-384
		    byte[] messageHash = MessageDigest.getInstance("SHA-256").digest(message);

		    AsymmetricSignRequest request = AsymmetricSignRequest.newBuilder()
		        .setName(keyName)
		        .setDigest(Digest.newBuilder().setSha256(ByteString.copyFrom(messageHash)))
		        .build();

		    AsymmetricSignResponse response = client.asymmetricSign(request);
		    return response.getSignature().toByteArray();
		  }
		}
	
	public boolean verifySignatureRSA(String keyName, byte[] message, byte[] signature)
		    throws IOException, GeneralSecurityException {

		  // Create the Cloud KMS client.
		  try (KeyManagementServiceClient client = KeyManagementServiceClient.create(keyManagementServiceSettings)) {
		    // Get the public key
		    com.google.cloud.kms.v1.PublicKey pub = client.getPublicKey(keyName);
		    String pemKey = pub.getPem();
		    pemKey = pemKey.replaceFirst("-----BEGIN PUBLIC KEY-----", "");
		    pemKey = pemKey.replaceFirst("-----END PUBLIC KEY-----", "");
		    pemKey = pemKey.replaceAll("\\s", "");
		    byte[] derKey = BaseEncoding.base64().decode(pemKey);
		    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(derKey);
		    PublicKey rsaKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);

		    // Verify the 'RSA_SIGN_PKCS1_2048_SHA256' signature.
		    Signature rsaVerify = Signature.getInstance("SHA256withRSA");
		    rsaVerify.initVerify(rsaKey);
		    rsaVerify.update(message);
		    return rsaVerify.verify(signature);
		  }
		}
	

}
