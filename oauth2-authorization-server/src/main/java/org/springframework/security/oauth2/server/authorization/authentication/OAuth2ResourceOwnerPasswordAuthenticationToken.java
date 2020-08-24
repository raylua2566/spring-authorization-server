/*
 * Copyright 2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.server.authorization.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityCoreVersion2;
import org.springframework.util.Assert;

import java.util.Collections;

/**
 * An {@link Authentication} implementation used for OAuth 2.0 Client Authentication.
 *
 * @author Ray Lau
 * @since 0.0.1
 * @see AbstractAuthenticationToken
 * @see OAuth2ClientAuthenticationProvider
 */
public class OAuth2ResourceOwnerPasswordAuthenticationToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = SpringSecurityCoreVersion2.SERIAL_VERSION_UID;
	private String userName;
	private String password;
	private Authentication clientPrincipal;

	/**
	 * Constructs an {@code OAuth2ResourceOwnerPasswordAuthenticationToken} using the provided parameters.
	 * @param clientPrincipal the client principal
	 * @param userName the client identifier
	 * @param password the client secret
	 */
	public OAuth2ResourceOwnerPasswordAuthenticationToken(Authentication clientPrincipal, String userName, String password) {
		super(Collections.emptyList());
		Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
		Assert.hasText(userName, "userName cannot be empty");
		Assert.hasText(password, "password cannot be empty");
		this.userName = userName;
		this.password = password;
		this.clientPrincipal = clientPrincipal;
	}

	@Override
	public Object getPrincipal() {
		return clientPrincipal;
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	public UsernamePasswordAuthenticationToken makeUsernamePasswordAuthenticationToken() {
		return new UsernamePasswordAuthenticationToken(this.userName,this.password);
	}
}
