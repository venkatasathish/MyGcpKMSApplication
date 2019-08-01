package com.gcpdemo.mygcpapp;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class MyGcpKMSApplication {

	private static final Log LOGGER = LogFactory.getLog(MyGcpKMSApplication.class);

	public static void main(String[] args) {
		SpringApplication.run(MyGcpKMSApplication.class, args);
	}

	

}
