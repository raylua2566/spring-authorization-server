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

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.JoseHeader;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationAttributeNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Set;

/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Client Credentials Grant.
 *
 * @author Ray Lau
 * @since 0.0.1
 * @see OAuth2ResourceOwnerPasswordAuthenticationToken
 * @see OAuth2AccessTokenAuthenticationToken
 * @see OAuth2AuthorizationService
 * @see JwtEncoder
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.3">Section 4.4 Resource Owner Password Credentials Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.3.2">Section 4.4.2 Access Token Request</a>
 */
public class OAuth2ResourceOwnerPasswordAuthenticationProvider implements AuthenticationProvider {
	private final OAuth2AuthorizationService authorizationService;
	private final JwtEncoder jwtEncoder;
	private DaoAuthenticationProvider daoAuthenticationProvider;

	/**
	 * Constructs an {@code OAuth2ClientCredentialsAuthenticationProvider} using the provided parameters.
	 *
	 * @param daoAuthenticationProvider
	 * @param authorizationService the authorization service
	 * @param jwtEncoder the jwt encoder
	 */
	public OAuth2ResourceOwnerPasswordAuthenticationProvider(DaoAuthenticationProvider daoAuthenticationProvider, OAuth2AuthorizationService authorizationService,
			JwtEncoder jwtEncoder) {
		this.daoAuthenticationProvider = daoAuthenticationProvider;
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(jwtEncoder, "jwtEncoder cannot be null");
		this.authorizationService = authorizationService;
		this.jwtEncoder = jwtEncoder;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2ResourceOwnerPasswordAuthenticationToken resourceOwnerPasswordAuthentication =
				(OAuth2ResourceOwnerPasswordAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal = null;
		if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(resourceOwnerPasswordAuthentication.getPrincipal().getClass())) {
			clientPrincipal = (OAuth2ClientAuthenticationToken) resourceOwnerPasswordAuthentication.getPrincipal();
		}
		if (clientPrincipal == null || !clientPrincipal.isAuthenticated()) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
		}
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

		Set<String> scopes = registeredClient.getScopes();		// Default to configured scopes
		// TODO: add request scopes
		// Code

		final Authentication authenticate = this.daoAuthenticationProvider.authenticate(resourceOwnerPasswordAuthentication.makeUsernamePasswordAuthenticationToken());
		if(!authenticate.isAuthenticated()) {
			throw new UsernameNotFoundException("");
		}


		JoseHeader joseHeader = JoseHeader.withAlgorithm(SignatureAlgorithm.RS256).build();

		// TODO Allow configuration for issuer claim
		URL issuer = null;
		try {
			issuer = URI.create("https://oauth2.provider.com").toURL();
		} catch (MalformedURLException e) { }

		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);		// TODO Allow configuration for access token time-to-live

		JwtClaimsSet jwtClaimsSet = JwtClaimsSet.withClaims()
				.issuer(issuer)
				.subject(authenticate.getName())
				.audience(Collections.singletonList(registeredClient.getClientId()))
				.issuedAt(issuedAt)
				.expiresAt(expiresAt)
				.notBefore(issuedAt)
				.claim(OAuth2ParameterNames.SCOPE, scopes)
				.build();

		Jwt jwt = this.jwtEncoder.encode(joseHeader, jwtClaimsSet);

		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), scopes);

		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
				.attribute(OAuth2AuthorizationAttributeNames.ACCESS_TOKEN_ATTRIBUTES, jwt)
				.principalName(clientPrincipal.getName())
				.accessToken(accessToken)
				.build();
		this.authorizationService.save(authorization);

		return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2ResourceOwnerPasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}
}
