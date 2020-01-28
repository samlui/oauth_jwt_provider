/**
 * 
 * Copyright (c) MuleSoft, Inc.
 * All rights reserved.  http://www.mulesoft.com
 * 
 * Custom User used in Mulesoft OAuth 2.0 Provider 
 * 
 * Author : Samuel Lui
 * 
 */
package com.mule.custom.security.provider;

import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

public class CustomUser extends User {

	private Map<String, String> customProperties;
	
	public CustomUser(String username, String password, Collection<? extends GrantedAuthority> authorities,
			Map<String, String> customProperties) {
		super(username, password, authorities);
		this.customProperties = customProperties;
	}

	public CustomUser(String username, String password, boolean enabled, boolean accountNonExpired,
			boolean credentialsNonExpired, boolean accountNonLocked,
			Collection<? extends GrantedAuthority> authorities) {
		super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
		
	}

	public Map<String, String> getCustomProperties() {
		return customProperties;
	}

	public void setCustomProperties(Map<String, String> customProperties) {
		this.customProperties = customProperties;
	}

}
