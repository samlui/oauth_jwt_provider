/**
 * KeyGenerator.java
 * Copyright (c) MuleSoft, Inc.
 * All rights reserved.  http://www.mulesoft.com
 * 
 * Genearte key in Json Web Key (JWK) format to be used in JWS / JWE token generation
 * 
 * Author : Samuel Lui
 * 
 */

package com.mule.custom.key;
import java.io.File;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.util.Map;
import java.util.Scanner;

import org.apache.commons.io.FileUtils;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.OctJwkGenerator;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.JoseException;




public class KeyGenerator {

	final String signPrivateFilename="/tmp/signPrivateKey.json";
	final String signPublicFilename="/tmp/signPublicKey.json";
	final String encryptFilename="/tmp/encKey.json";

//	private static final Logger LOGGER = Logger.getLogger(KeyGenerator.class);
	
	
//	public void runEcKey() {
//		// or an EC key, if you prefer
//	    PublicJsonWebKey ecJwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
//		
//		
//	}
	
	private String readfile(String filename) {
		
		String data = "";
		
		try {

			File file = new File(filename);
			FileInputStream in1;
			in1 = new FileInputStream(file);
			Scanner scanner = new Scanner(in1, "UTF-8");
			scanner.useDelimiter("\\A");
			data = scanner.hasNext() ? scanner.next() : "";
			System.out.println("key file : " + data);
			scanner.close();
			in1.close();

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return data;
		

		
	}
	
	private void readSignKey() {
		
		String signPrivateJson = readfile(signPrivateFilename);
		String signPublicJson = readfile(signPublicFilename);
		
		System.out.println("1. private key ---------- >: ");
	    
		try {
			// parse and convert into PublicJsonWebKey/JsonWebKey objects

			PublicJsonWebKey parsedKeyPairJwk = PublicJsonWebKey.Factory.newPublicJwk(signPrivateJson);

		    // the private key can be used to sign (JWS) or decrypt (JWE)
		    PrivateKey privateKey = parsedKeyPairJwk.getPrivateKey();

		    	System.out.println("private key : " + privateKey);
		    
		    // the public key can be used to verify (JWS) or encrypt (JWE)
		    PublicKey publicKey = parsedKeyPairJwk.getPublicKey();
		    
		    System.out.println("pubic key : " + publicKey);
		    
		} catch (JoseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    
	    System.out.println("2. pubic key ---------- >: ");
		
		try {
			// parse and convert into PublicJsonWebKey/JsonWebKey objects

			PublicJsonWebKey parsedKeyPairJwk = PublicJsonWebKey.Factory.newPublicJwk(signPublicJson);

		    // the private key can be used to sign (JWS) or decrypt (JWE)
		    PrivateKey privateKey = parsedKeyPairJwk.getPrivateKey();

		    	System.out.println("private key : " + privateKey);
		    
		    // the public key can be used to verify (JWS) or encrypt (JWE)
		    PublicKey publicKey = parsedKeyPairJwk.getPublicKey();
		    
		    System.out.println("pubic key : " + publicKey);
		    
		} catch (JoseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	
		
	}

	private void readEncryptKey() {
		
		String json = readfile(encryptFilename);
	    
		try {
			// parse and convert into PublicJsonWebKey/JsonWebKey objects

			OctetSequenceJsonWebKey symmetricKey = (OctetSequenceJsonWebKey) JsonWebKey.Factory.newJwk(json);
				    
		    System.out.println("symmetricKey  : " + symmetricKey);
		    
		} catch (JoseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    
	
		
	}
	private void generateEncryptKey() {
		
		try {
			
	        File file = new File(this.encryptFilename);
	        		
	        	// Generate a new RSA key pair wrapped in a JWK
	        	
	        final OctetSequenceJsonWebKey octetKey = OctJwkGenerator.generateJwk(256);
	        
	        final Map<String, Object> params = octetKey.toParams(JsonWebKey.OutputControlLevel.INCLUDE_SYMMETRIC);
	        String k= params.get("k").toString();
	        System.out.println("k : " + k);
	        System.out.println("OctetSequenceJsonWebKey : " + octetKey);
	        
	        String keyPairJwkString = octetKey.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);;
	        FileUtils.write(file, keyPairJwkString, StandardCharsets.UTF_8);
	        System.out.println("Generated Octet JSK key in : "+ file);
	        
	        //
//	                    System.out.println("Generated JSON web keystore at [{}]"+ file);
//	            final JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(rsaJsonWebKey);
            
//         // A JSON string with only the public key info
//            publicKeyJwkString = OctetSequenceJsonWebKey
//            
//            System.out.println("public keyset : " + publicKeyJwkString);
//
//            // A JSON string with both the public and private key info
//            
//            keyPairJwkString = rsaJsonWebKey.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);
//            
//            System.out.println("private keyset : "  + keyPairJwkString);
//            
//            FileUtils.write(file, keyPairJwkString, StandardCharsets.UTF_8);
//
//            System.out.println("Generated JSON web keystore at [{}]"+ file);

	    } catch (final Exception e) {
	        e.printStackTrace();
	    }
	}
	
	private void generateSignKey() {
		
		String keyPairJwkString = "";
		String publicKeyJwkString = "";
		
		try {
			
	        File privateFile = new File(signPrivateFilename);
	        File publicFile = new File(signPublicFilename);
	        		
	        	// Generate a new RSA key pair wrapped in a JWK
	        	
            RsaJsonWebKey rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);
            rsaJsonWebKey.setKeyId("rsa-jwk");
            rsaJsonWebKey.setUse("sig");
            
//	            final JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(rsaJsonWebKey);
            
         // A JSON string with only the public key info
            publicKeyJwkString = rsaJsonWebKey.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
            
            System.out.println("public keyset : " + publicKeyJwkString);
            FileUtils.write(publicFile, publicKeyJwkString, StandardCharsets.UTF_8);
            System.out.println("Generated public key file for signature verificatino to : "+ publicFile);
            
            // A JSON string with both the public and private key info
            
            keyPairJwkString = rsaJsonWebKey.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);
            
            System.out.println("private keyset : "  + keyPairJwkString);
            
            FileUtils.write(privateFile, keyPairJwkString, StandardCharsets.UTF_8);

            System.out.println("Generated private key file for signature to : "+ privateFile);

	    } catch (final Exception e) {
	        e.printStackTrace();
	    }
	}
	
	public void run() {
		
		
		String keyPairJwkString = "";
		String publicKeyJwkString = "";
		
		try {
		

			// Generate a new RSA key pair wrapped in a JWK
			PublicJsonWebKey rsaJwk = RsaJwkGenerator.generateJwk(2048);
		
		    // or an EC key, if you prefer
		    PublicJsonWebKey ecJwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
	
		    // A JSON string with only the public key info
		    publicKeyJwkString = rsaJwk.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
		    System.out.println("public key jws : " + publicKeyJwkString);
	
		    // A JSON string with both the public and private key info
		    keyPairJwkString = rsaJwk.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);
		    System.out.println("public+private key jws : " + keyPairJwkString);
	
		    // parse and convert into PublicJsonWebKey/JsonWebKey objects
		    PublicJsonWebKey parsedPublicKeyJwk = PublicJsonWebKey.Factory.newPublicJwk(publicKeyJwkString);
		    PublicJsonWebKey parsedKeyPairJwk = PublicJsonWebKey.Factory.newPublicJwk(keyPairJwkString);
	
		    // the private key can be used to sign (JWS) or decrypt (JWE)
//		    PrivateKey privateKey = parsedKeyPairJwk.getPrivateKey();
//		    System.out.println("private key : " + privateKey.getAlgorithm());
		    
		    // the public key can be used to verify (JWS) or encrypt (JWE)
		    PublicKey publicKey = parsedPublicKeyJwk.getPublicKey();
		    System.out.println("public key : " + publicKey.toString());
		    
		} catch (JoseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	
	public static void main(String[] args) throws JoseException {
		// TODO Auto-generated method stub
		KeyGenerator instance = new KeyGenerator();
		instance.generateSignKey();
		instance.generateEncryptKey();
		instance.readSignKey();
		instance.readEncryptKey();
//		instance.run();
	}

}
