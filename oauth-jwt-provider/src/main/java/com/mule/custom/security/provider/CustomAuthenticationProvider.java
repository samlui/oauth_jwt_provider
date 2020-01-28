/**
 * KeyGenerator.java
 * Copyright (c) MuleSoft, Inc.
 * All rights reserved.  http://www.mulesoft.com
 * 
 * Resource Authentication Provider for Mulesoft OAuth 2.0 Provider 
 * 
 * Author : Samuel Lui
 * 
 */
package com.mule.custom.security.provider;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;

import javax.inject.Inject;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import org.mule.runtime.core.api.construct.Flow;
import org.mule.runtime.core.api.event.CoreEvent;
import org.mule.runtime.core.api.event.EventContextFactory;
import org.mule.runtime.api.artifact.Registry;
import org.mule.runtime.api.event.Event;
import org.mule.runtime.api.message.Message;

public class CustomAuthenticationProvider implements AuthenticationProvider {

	
	private final String DEFAULT_GRANT_1 = "ROLE_USER";
	private final String DEFAULT_GRANT_2 = "ROLE_ADMIN";
	private final String AUTH_MULE_FLOW = "authenticateFlow";
	private final String AUTH_KEY = "authenticated";
	private final String CUSTOM_ATTR = "custom_attributes";
	
	@Inject
    private Registry muleRegistry;
	
    @Override
    public Authentication authenticate(Authentication authentication) 
      throws AuthenticationException {
  
        Map<String, String> data = new HashMap<String, String>();
        
        data.put("user", authentication.getName());
        data.put("pass", authentication.getCredentials().toString());
  
        System.out.println(data.get("user") + " , " + data.get("pass"));
        
        System.out.println("muleRegistry : " + muleRegistry);
        
        // Lookup the 
        Flow flow = (Flow) muleRegistry.lookupByName(AUTH_MULE_FLOW).orElse(null);
        System.out.println("flow : " + flow);
        
        Message msg = Message.builder().value(data).build();
        
        CoreEvent inEvent = CoreEvent
                .builder(EventContextFactory.create(flow,
                            org.mule.runtime.dsl.api.component.config.DefaultComponentLocation
                                         .fromSingleComponent("add-location")))
                .message(msg).build();
        
        System.out.println("inEvent  : " + inEvent.getMessage().getPayload() );

        CompletableFuture<Event> result = flow.execute(inEvent);
        
        Event outEvent = null;
        
        try {
        		outEvent = result.get();
        		System.out.println("result  : " + outEvent);
        
        } catch (Exception ex) {
        		ex.printStackTrace();
        		System.out.println("result  : exception : " + ex.getMessage() );
        }
        // output of muleflow is a Map containing 2 key: authenticated and customProperties
        System.out.println("result payload  : " + outEvent.getMessage().getPayload().getValue() );
        Map outMap = (Map) outEvent.getMessage().getPayload().getValue() ; 
        Map customAttributes = (Map) outMap.get(CUSTOM_ATTR) ; 
        Boolean authenticated = (Boolean) outMap.get(AUTH_KEY) ;
        if (authenticated) {
        		System.out.println("user authenticated : " + data.get("user"));
        		//        if (data.get("user").equalsIgnoreCase(data.get("pass"))) {
	        final List grantedAuths = new ArrayList();
	        grantedAuths.add(new SimpleGrantedAuthority(DEFAULT_GRANT_1));
	        grantedAuths.add(new SimpleGrantedAuthority(DEFAULT_GRANT_2));
	        final UserDetails principal = new CustomUser(data.get("user"), data.get("pass"), grantedAuths, customAttributes);
	        final Authentication auth = new UsernamePasswordAuthenticationToken(principal, data.get("pass"), grantedAuths);
            // use the credentials
            // and authenticate against the third-party system
	        SecurityContextHolder.getContext().setAuthentication(auth);
//	        LOGGER.info("Auth Successful !!");
            return auth;
        } else {
            return null;
        }
    }
	
    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}