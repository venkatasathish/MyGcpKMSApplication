package com.gcpdemo.mygcpapp.model;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties("kms")
public class KMSProperties {

	private String projectId;
	
	private String locationId;
	
	private String keyRingId;
	
	private String cryptoKeyId;
	
	private String asymmCryptoKeyId;
	
	private String asymmSignCryptoKeyId;
	
	private String asymmCryptoKeyVer;
	
	private String asymmSignCryptoKeyVer;

	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	public String getAsymmCryptoKeyVer() {
		return asymmCryptoKeyVer;
	}

	public void setAsymmCryptoKeyVer(String asymmCryptoKeyVer) {
		this.asymmCryptoKeyVer = asymmCryptoKeyVer;
	}

	public String getAsymmSignCryptoKeyVer() {
		return asymmSignCryptoKeyVer;
	}

	public void setAsymmSignCryptoKeyVer(String asymmSignCryptoKeyVer) {
		this.asymmSignCryptoKeyVer = asymmSignCryptoKeyVer;
	}

	public String getAsymmCryptoKeyId() {
		return asymmCryptoKeyId;
	}

	public void setAsymmCryptoKeyId(String asymmCryptoKeyId) {
		this.asymmCryptoKeyId = asymmCryptoKeyId;
	}

	public String getAsymmSignCryptoKeyId() {
		return asymmSignCryptoKeyId;
	}

	public void setAsymmSignCryptoKeyId(String asymmSignCryptoKeyId) {
		this.asymmSignCryptoKeyId = asymmSignCryptoKeyId;
	}

	public String getProjectId() {
		return projectId;
	}

	public void setProjectId(String projectId) {
		this.projectId = projectId;
	}

	public String getLocationId() {
		return locationId;
	}

	public void setLocationId(String locationId) {
		this.locationId = locationId;
	}

	public String getKeyRingId() {
		return keyRingId;
	}

	public void setKeyRingId(String keyRingId) {
		this.keyRingId = keyRingId;
	}

	public String getCryptoKeyId() {
		return cryptoKeyId;
	}

	public void setCryptoKeyId(String cryptoKeyId) {
		this.cryptoKeyId = cryptoKeyId;
	}
	
}
