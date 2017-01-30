/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.authentication;

import java.io.IOException;
import java.sql.Timestamp;
import java.util.Calendar;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.sun.jna.platform.win32.Sspi;
import com.sun.xml.internal.bind.v2.TODO;
import org.cloudfoundry.identity.uaa.authentication.manager.LoginPolicy;
import org.cloudfoundry.identity.uaa.authentication.manager.LoginPolicy.Result;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;


/**
 * This class is an extension of Spring Framework BasicAuthenticationFilter that observes
 * the client lockout policy and throws ClientLockoutException when the client attempting
 * to authenticate is locked out.
 */
public class ClientBasicAuthenticationFilter extends BasicAuthenticationFilter {

    protected LoginPolicy loginPolicy;
    protected ClientDetailsService clientDetailsService;

    public ClientBasicAuthenticationFilter(AuthenticationManager authenticationManager,
            AuthenticationEntryPoint authenticationEntryPoint) {

        super(authenticationManager, authenticationEntryPoint);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response, FilterChain chain)
                    throws IOException, ServletException {
        try{
            String header = request.getHeader("Authorization");
            if (header == null || !header.startsWith("Basic ")) {
                chain.doFilter(request, response);
                return;
            }

            String[] decodedHeader = extractAndDecodeHeader(header, request);
            //Validate against client lockout policy
            String clientId = decodedHeader[0];
            Result policyResult = loginPolicy.isAllowed(clientId);
            if(!policyResult.isAllowed()){
                throw new ClientLockoutException("Client " + clientId + " has "
                        + policyResult.getFailureCount() + " failed authentications within the last checking period.");
            }

            //Validate against client secret expiration in the zone configured client secret policy
            //TODO
            Timestamp lastModified = (Timestamp) clientDetailsService.loadClientByClientId(clientId).getAdditionalInformation().get(ClientConstants.LAST_MODIFIED);

            int expiringPassword = IdentityZoneHolder.get().getConfig().
                        getClientSecretPolicy().getExpirePasswordInMonths();
            if (expiringPassword>0) {
                Calendar cal = Calendar.getInstance();
                cal.setTimeInMillis(lastModified.getTime());
                cal.add(Calendar.MONTH, expiringPassword);
                if (cal.getTimeInMillis() < System.currentTimeMillis()) {
                    throw new PasswordExpiredException("Your current password has expired. Please reset your password.");
                }
            }

        } catch(BadCredentialsException e) {
            super.getAuthenticationEntryPoint().commence(request, response, e);
            return;
        }
        //call parent class to authenticate
        super.doFilterInternal(request, response, chain);
    }

    public LoginPolicy getLoginPolicy() {
        return loginPolicy;
    }

    public void setLoginPolicy(LoginPolicy loginPolicy) {
        this.loginPolicy = loginPolicy;
    }

    private String[] extractAndDecodeHeader(String header, HttpServletRequest request)
            throws IOException {

        byte[] base64Token = header.substring(6).getBytes("UTF-8");
        byte[] decoded;
        try {
            decoded = Base64.decode(base64Token);
        }
        catch (IllegalArgumentException e) {
            throw new BadCredentialsException(
                    "Failed to decode basic authentication token");
        }

        String token = new String(decoded, getCredentialsCharset(request));

        int delim = token.indexOf(":");

        if (delim == -1) {
            throw new BadCredentialsException("Invalid basic authentication token");
        }
        return new String[] { token.substring(0, delim), token.substring(delim + 1) };
    }
}
