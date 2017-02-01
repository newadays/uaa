package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.authentication.manager.LoginPolicy;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.zone.ClientSecretPolicy;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import java.io.IOException;
import java.sql.Timestamp;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

public class ClientBasicAuthenticationFilterTests {

    @Test
    public void doesNotContinueWithFilterChain_IfClientSecretExpired() throws IOException, ServletException, ParseException {
        AuthenticationManager clientAuthenticationManager = mock(AuthenticationManager.class);
        AuthenticationEntryPoint authenticationEntryPoint = mock(AuthenticationEntryPoint.class);

        ClientBasicAuthenticationFilter filter = new ClientBasicAuthenticationFilter(clientAuthenticationManager,
                        authenticationEntryPoint);

        LoginPolicy loginPolicy = mock(LoginPolicy.class);

        ClientDetailsService clientDetailsService = mock(ClientDetailsService.class);

        filter.setLoginPolicy(loginPolicy);
        filter.setClientDetailsService(clientDetailsService);

        when(loginPolicy.isAllowed(Mockito.anyString())).thenReturn(new LoginPolicy.Result(true, 3));


        BaseClientDetails clientDetails = new BaseClientDetails("client-1", "none", "uaa.none", "client_credentials",
                               "http://localhost:5000/uaadb" );

        clientDetails.setAdditionalInformation(createTestAdditionalInformation());

        when(clientDetailsService.loadClientByClientId(Mockito.anyString())).thenReturn(clientDetails);

        MockFilterChain chain = mock(MockFilterChain.class);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Basic " + enccodeTestHeaderValue());
        MockHttpServletResponse response = new MockHttpServletResponse();

        IdentityZoneHolder.set(getTestZone());

        filter.doFilter(request, response, chain);

        verify(authenticationEntryPoint).commence(any(request.getClass()), any(response.getClass()), any(BadCredentialsException.class));
        verifyNoMoreInteractions(chain);
    }

    private IdentityZone getTestZone() {
        IdentityZone testZone = new IdentityZone();
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0,255,0,0,0,0,6));
        return testZone;
    }

    private String enccodeTestHeaderValue()
            throws IOException {
        return new String( Base64.getEncoder().encode("app:appclientsecret".getBytes()));
    }

    private Map<String, Object> createTestAdditionalInformation() throws ParseException{
        Map<String,Object> additionalInformation = new HashMap<String,Object>();
        additionalInformation.put(ClientConstants.LAST_MODIFIED,
                new Timestamp(new SimpleDateFormat("MM/dd/yyyy").parse("01/01/2016").getTime()));

        return additionalInformation;
    }
}