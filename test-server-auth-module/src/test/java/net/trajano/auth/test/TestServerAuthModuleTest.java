package net.trajano.auth.test;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

import java.net.HttpURLConnection;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import net.trajano.auth.TestServerAuthModule;

public class TestServerAuthModuleTest {

    /**
     * Module options.
     */
    private final Map<String, String> options = ImmutableMap.<String, String> builder().build();

    /**
     * The policy has determined it is not mandatory without SSL.
     */
    @Test
    public void testNoAuthNeededWithoutSSL() throws Exception {

        final TestServerAuthModule module = new TestServerAuthModule();
        final CallbackHandler h = mock(CallbackHandler.class);

        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(false);

        module.initialize(mockRequestPolicy, null, h, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("GET");
        when(servletRequest.isSecure()).thenReturn(false);
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);
        when(servletRequest.getRequestURI()).thenReturn("/util/ejb2");
        when(servletRequest.getContextPath()).thenReturn("/util");

        final Subject client = new Subject();
        assertEquals(AuthStatus.SUCCESS, module.validateRequest(messageInfo, client, null));
        verifyZeroInteractions(h);
    }

    /**
     * The policy has determined it is not mandatory.
     */
    @Test
    public void testNoAuthNeededWithSSL() throws Exception {

        final TestServerAuthModule module = new TestServerAuthModule();
        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(false);

        final CallbackHandler h = mock(CallbackHandler.class);
        module.initialize(mockRequestPolicy, null, h, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("GET");
        when(servletRequest.isSecure()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn("/util/ejb2");
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final Subject client = new Subject();
        assertEquals(AuthStatus.SUCCESS, module.validateRequest(messageInfo, client, null));
        verifyZeroInteractions(h);
    }

    @Test
    public void testSSLRequired() throws Exception {

        final TestServerAuthModule module = new TestServerAuthModule();
        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);

        module.initialize(mockRequestPolicy, null, null, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("GET");
        when(servletRequest.isSecure()).thenReturn(false);
        when(servletRequest.getRequestURI()).thenReturn("/util/ejb2");
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final HttpServletResponse servletResponse = mock(HttpServletResponse.class);
        when(messageInfo.getResponseMessage()).thenReturn(servletResponse);

        final Subject client = new Subject();
        assertEquals(AuthStatus.SEND_FAILURE, module.validateRequest(messageInfo, client, null));
        verify(servletResponse).sendError(HttpURLConnection.HTTP_FORBIDDEN, "SSL Required");
    }
}
