/**
 * 
 * Copyright (c) MuleSoft, Inc.
 * All rights reserved.  http://www.mulesoft.com
 * 
 * JWS and JWE Token Generation Strategy used in Mulesoft OAuth 2.0 Provider 
 * 
 * Author : Samuel Lui
 * 
 */
package com.mule.custom.security.token.strategy;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;

import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

import com.mule.custom.security.provider.CustomUser;
import com.mulesoft.modules.oauth2.provider.api.token.generator.TokenGeneratorStrategy;
import org.springframework.security.core.context.SecurityContextHolder;


public class TokenGeneratorOpenIdStrategy implements TokenGeneratorStrategy {

//	private static final Logger LOGGER = Logger.getLogger(TokenGeneratorOpenIdStrategy.class);

		// Passed by parameter
		private Long ttlSeconds = (long) 60; // 1 min
		private String issuer="mulesoft";
		private String signingKeyPath="signPrivateKey.json";
		private String encryptionKeyPath = "enckey.json";
		private String encryptionAlgorithm = ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256;
		private String signingAlgorithm = AlgorithmIdentifiers.RSA_USING_SHA256;
		
		@Override
		public String generateToken() {

			CustomUser user = (CustomUser) SecurityContextHolder.getContext().getAuthentication()
					.getPrincipal();
			System.out.println("user in generateToken :" + user);
 
			
			// JWS key
			String signingKeyJWKString;
			try {
				signingKeyJWKString = loadResource(signingKeyPath);
			} catch (IOException e) {
				throw new RuntimeException("Signing key not found");
			}
			
			RsaJsonWebKey signingKey;
			try {
				signingKey = (RsaJsonWebKey) JsonWebKey.Factory.newJwk(signingKeyJWKString);
				System.out.println("Signing Key - Public & Private:");
			    System.out.println(signingKey.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));
			} catch (JoseException e) {
				throw new RuntimeException("Loading signing key failed: " + e.getMessage());
			}

			// JWE key
			String encryptionKeyJWKString;
			try {
				encryptionKeyJWKString = loadResource(encryptionKeyPath);
			} catch (IOException e) {
				throw new RuntimeException("Encryption key not found");
			}

			OctetSequenceJsonWebKey symmetricKey;
			try {
				symmetricKey = (OctetSequenceJsonWebKey) JsonWebKey.Factory.newJwk(encryptionKeyJWKString);
			    System.out.println("Encryption Key : OctetSequenceJsonWebKey : " + symmetricKey);
			} catch (JoseException e) {
				throw new RuntimeException("Loading symmetric encryption key failed: " + e.getMessage());
			}

				
			// Build JWS token
			System.out.println("Granting JWS token...");
			JwtClaims claims = buildJWTClaims(user);
			String jws;
			try {
				jws = buildJWS(claims.toJson(), signingAlgorithm, signingKey);
			} catch (JoseException e) {
				throw new RuntimeException("Signing token failed: " + e.getMessage());
			}
			System.out.println("jws : " + jws);
			
			// Build JWE token
			System.out.println("Granting JWE token...");
			String jwe;
			try {
				jwe = buildNestedJWE(jws, encryptionAlgorithm, symmetricKey);
			} catch (JoseException e) {
				throw new RuntimeException("Encrypting token failed: " + e.getMessage());
			}
			System.out.println("jwe : " + jwe);
			return jws;
			
		}

		/**
		 * @param setSigningKey
		 *            the JWT signing key path
		 */
		public void setSigningKeyPath(String signingKeyPath) {
			this.signingKeyPath = signingKeyPath;
		}

		/**
		 * @param setTtlSeconds
		 *            the JWT token validity time in seconds
		 */
		public void setTtlSeconds(Long ttlSeconds) {
			this.ttlSeconds = ttlSeconds;
		}

		/**
		 * @param setEncryptionKey
		 *            the JWT encryption key path
		 */
		public void setEncryptionKeyPath(String encryptionKeyPath) {
			this.encryptionKeyPath = encryptionKeyPath;
		}

		/**
		 * 
		 * @param signingAlgorithm
		 *            Signing algorithm for inner JWS (RS256, RS384 or RS512).
		 */
		public void setSigningAlgorithm(String signingAlgorithm) {
			this.signingAlgorithm = signingAlgorithm;
		}

		/**
		 * 
		 * @param encryptionAlgorithm
		 *            Content encryption algorithm (A128GCM or A256GCM).
		 */
		public void setEncryptionAlgorithm(String encryptionAlgorithm) {
			this.encryptionAlgorithm = encryptionAlgorithm;
		}

		/**
		 * @param issuer
		 *            the JWT issuer to set
		 */
		public void setIssuer(String issuer) {
			this.issuer = issuer;
		}

		private JwtClaims buildJWTClaims(CustomUser user) {
			System.out.println("user" + user);
			JwtClaims claims = new JwtClaims();

			claims.setIssuer(issuer);
			claims.setExpirationTimeMinutesInTheFuture(ttlSeconds / 60);
			claims.setIssuedAtToNow();

			claims.setClaim("uid", user.getUsername());
			List<String> scopes = new ArrayList<String>();
			
			for (Map.Entry<String, String> entry: user.getCustomProperties().entrySet()) {
				if ("id".equalsIgnoreCase(entry.getKey()))
					claims.setSubject(entry.getValue());
				else if ("aud".equalsIgnoreCase(entry.getKey()))
					claims.setAudience(entry.getValue());
				else if (entry.getKey().startsWith("scp")) {
					scopes.add(entry.getValue());
				} else {
					claims.setClaim(entry.getKey(), entry.getValue());
				}
				
			}
			if (scopes.size()!=0)
				claims.setClaim("scp",scopes);

			return claims;
		}

		private String buildJWS(String claims, String signingAlgorithm, RsaJsonWebKey signingKey) throws JoseException {

			JsonWebSignature jws = new JsonWebSignature();
						
			jws.setAlgorithmHeaderValue(signingAlgorithm);
			jws.setKeyIdHeaderValue(signingKey.getKeyId());

			jws.setKey(signingKey.getPrivateKey());
			jws.setPayload(claims);

			return jws.getCompactSerialization();
		}

		private String buildNestedJWE(String jwsPayload, String encAlgorithm, OctetSequenceJsonWebKey encryptionKey)
				throws JoseException {
			JsonWebEncryption jwe = new JsonWebEncryption();

			// header + settings
			jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);
			jwe.setEncryptionMethodHeaderParameter(encAlgorithm);
			jwe.setContentTypeHeaderValue("JWT");

			jwe.setPayload(jwsPayload);
			jwe.setKey(encryptionKey.getKey());

			return jwe.getCompactSerialization();
		}

		private String loadResource(String resourceName) throws IOException {
			System.out.println("resourceName :" + resourceName);
			InputStream inputStream = this.getClass().getResourceAsStream("/" + resourceName);
			Scanner scanner = new Scanner(inputStream, "UTF-8");
			scanner.useDelimiter("\\A");
			String fileString = scanner.hasNext() ? scanner.next() : "";
			scanner.close();
			inputStream.close();
			return fileString;
		}

}