package com.gcpdemo.mygcpapp.config;

import java.io.FileInputStream;
import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import com.google.api.gax.core.FixedCredentialsProvider;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.kms.v1.KeyManagementServiceSettings;
import com.google.common.collect.Lists;

@Configuration
public class CloudConfig {
	
	@Autowired 
	KeyManagementServiceSettings keyManagementServiceSettings;
	
	
	@Bean
	public KeyManagementServiceSettings getKeyManagementServiceSettings() {
		
		try {
			GoogleCredentials credentials = GoogleCredentials.fromStream(new FileInputStream("C:\\Users\\Desktop\\Sathish\\demo_id.json"))
			        .createScoped(Lists.newArrayList("https://www.googleapis.com/auth/cloud-platform"));
			
			keyManagementServiceSettings =  KeyManagementServiceSettings.newBuilder()
					       .setCredentialsProvider(FixedCredentialsProvider.create(credentials))
					         .build();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return keyManagementServiceSettings;
	}

}
