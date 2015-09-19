package net.trajano.auth.test;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLDecoder;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.RequestDispatcher;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Matchers;

import net.trajano.auth.TestServerAuthModule;

public class TestServerAuthModuleTest {

    /**
     * Module options.
     */
    private final Map<String, String> options = new HashMap<>();

    @Test
    public void testCleanSubject() throws Exception {

        final Subject subject = new Subject();

        final Principal groupPrincipal = mock(Principal.class);
        when(groupPrincipal.getName()).thenReturn("authenticated");
        subject.getPrincipals().add(groupPrincipal);

        final Principal userPrincipal = mock(Principal.class);
        when(userPrincipal.getName()).thenReturn("https://foo@test-server-auth-module");
        subject.getPrincipals().add(userPrincipal);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final Cookie[] cookies = new Cookie[] {
            new Cookie("X-Subject", "https://foo@test-server-auth-module"),
            new Cookie("not-relevant", "foo")
        };
        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("POST");
        when(servletRequest.isSecure()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn("/util/j_security_check");
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(servletRequest.getParameter("state")).thenReturn("/");
        when(servletRequest.getCookies()).thenReturn(cookies);
        when(servletRequest.getParameter("j_username")).thenReturn("foofoo");
        when(servletRequest.getRequestDispatcher(Matchers.anyString())).thenReturn(mock(RequestDispatcher.class));
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        new TestServerAuthModule().cleanSubject(messageInfo, subject);
    }

    /**
     * Tests when a servlet API method throws an exception
     */
    @Test(expected = AuthException.class)
    public void testFailFromIOException() throws Exception {

        final TestServerAuthModule module = new TestServerAuthModule();
        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);

        final CallbackHandler h = mock(CallbackHandler.class);
        module.initialize(mockRequestPolicy, null, h, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("GET");
        when(servletRequest.isSecure()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn("/util/j_security_check");
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(servletRequest.getParameter("state")).thenReturn("/");
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final HttpServletResponse servletResponse = mock(HttpServletResponse.class);
        when(messageInfo.getResponseMessage()).thenReturn(servletResponse);

        final RequestDispatcher dispatcher = mock(RequestDispatcher.class);
        doThrow(IOException.class).when(dispatcher).forward(servletRequest, servletResponse);
        when(servletRequest.getRequestDispatcher(Matchers.anyString())).thenReturn(dispatcher);

        final Subject client = new Subject();
        assertEquals(AuthStatus.SEND_SUCCESS, module.validateRequest(messageInfo, client, null));
        verifyZeroInteractions(h);
    }

    /**
     * Tests the login endpoint PUT operation.
     */
    @Test(expected = AuthException.class)
    public void testFailLoginInvalidMethod() throws Exception {

        final TestServerAuthModule module = new TestServerAuthModule();
        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);

        final CallbackHandler h = mock(CallbackHandler.class);
        module.initialize(mockRequestPolicy, null, h, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("PUT");
        when(servletRequest.isSecure()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn("/util/j_security_check");
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(servletRequest.getParameter("state")).thenReturn("/rooted/page");
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final Subject client = new Subject();
        module.validateRequest(messageInfo, client, null);
    }

    /**
     * Tests the login endpoint GET operation.
     */
    @Test(expected = AuthException.class)
    public void testFailLoginInvalidState() throws Exception {

        final TestServerAuthModule module = new TestServerAuthModule();
        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);

        final CallbackHandler h = mock(CallbackHandler.class);
        module.initialize(mockRequestPolicy, null, h, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("GET");
        when(servletRequest.isSecure()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn("/util/j_security_check");
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(servletRequest.getParameter("state")).thenReturn("http://www.trajano.net/");
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final Subject client = new Subject();
        module.validateRequest(messageInfo, client, null);
    }

    /**
     * Tests the login endpoint GET operation.
     */
    @Test(expected = AuthException.class)
    public void testFailLoginInvalidState2() throws Exception {

        final TestServerAuthModule module = new TestServerAuthModule();
        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);

        final CallbackHandler h = mock(CallbackHandler.class);
        module.initialize(mockRequestPolicy, null, h, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("GET");
        when(servletRequest.isSecure()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn("/util/j_security_check");
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(servletRequest.getParameter("state")).thenReturn("some/non/rooted/page");
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final Subject client = new Subject();
        module.validateRequest(messageInfo, client, null);
    }

    /**
     * Tests the login endpoint GET operation.
     */
    @Test(expected = AuthException.class)
    public void testFailLoginInvalidState3() throws Exception {

        final TestServerAuthModule module = new TestServerAuthModule();
        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);

        final CallbackHandler h = mock(CallbackHandler.class);
        module.initialize(mockRequestPolicy, null, h, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("GET");
        when(servletRequest.isSecure()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn("/util/j_security_check");
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(servletRequest.getParameter("state")).thenReturn("/foo/../../abc");
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final Subject client = new Subject();
        module.validateRequest(messageInfo, client, null);
    }

    /**
     * Tests the login endpoint GET operation.
     */
    @Test(expected = AuthException.class)
    public void testFailLoginMissingState() throws Exception {

        final TestServerAuthModule module = new TestServerAuthModule();
        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);

        final CallbackHandler h = mock(CallbackHandler.class);
        module.initialize(mockRequestPolicy, null, h, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("GET");
        when(servletRequest.isSecure()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn("/util/j_security_check");
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final Subject client = new Subject();
        module.validateRequest(messageInfo, client, null);
    }

    /**
     * Tests the login endpoint GET operation.
     */
    @Test(expected = AuthException.class)
    public void testFailLoginNotSecure() throws Exception {

        final TestServerAuthModule module = new TestServerAuthModule();
        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);

        final CallbackHandler h = mock(CallbackHandler.class);
        module.initialize(mockRequestPolicy, null, h, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("GET");
        when(servletRequest.isSecure()).thenReturn(false);
        when(servletRequest.getRequestURI()).thenReturn("/util/j_security_check");
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final Subject client = new Subject();
        module.validateRequest(messageInfo, client, null);
    }

    /**
     * Tests the logout endpoint GET operation.
     */
    @Test(expected = AuthException.class)
    public void testFailLogoutInvalidRedirect() throws Exception {

        final TestServerAuthModule module = new TestServerAuthModule();
        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);

        final CallbackHandler h = mock(CallbackHandler.class);
        module.initialize(mockRequestPolicy, null, h, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("GET");
        when(servletRequest.isSecure()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn("/util/j_logout");
        when(servletRequest.getRequestURL()).thenReturn(new StringBuffer("https://www.trajano.net/util/j_logout"));
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(servletRequest.getParameter("post_logout_redirect_uri")).thenReturn("https://site.trajano.net/util/");
        when(servletRequest.getRequestDispatcher(Matchers.anyString())).thenReturn(mock(RequestDispatcher.class));
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final HttpServletResponse servletResponse = mock(HttpServletResponse.class);
        when(messageInfo.getResponseMessage()).thenReturn(servletResponse);

        final Subject client = new Subject();
        module.validateRequest(messageInfo, client, null);
    }

    /**
     * Tests the logout endpoint GET operation.
     */
    @Test(expected = AuthException.class)
    public void testFailLogoutMissingRedirect() throws Exception {

        final TestServerAuthModule module = new TestServerAuthModule();
        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);

        final CallbackHandler h = mock(CallbackHandler.class);
        module.initialize(mockRequestPolicy, null, h, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("GET");
        when(servletRequest.isSecure()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn("/util/j_logout");
        when(servletRequest.getRequestURL()).thenReturn(new StringBuffer("https://www.trajano.net/util/j_logout"));
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(servletRequest.getRequestDispatcher(Matchers.anyString())).thenReturn(mock(RequestDispatcher.class));
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final HttpServletResponse servletResponse = mock(HttpServletResponse.class);
        when(messageInfo.getResponseMessage()).thenReturn(servletResponse);

        final Subject client = new Subject();
        module.validateRequest(messageInfo, client, null);
    }

    /**
     * Tests the redirect to login.
     */
    @Test(expected = AuthException.class)
    public void testFailRedirectToLoginWithPOST() throws Exception {

        final TestServerAuthModule module = new TestServerAuthModule();
        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);

        final CallbackHandler h = mock(CallbackHandler.class);
        module.initialize(mockRequestPolicy, null, h, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("POST");
        when(servletRequest.isSecure()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn("/util/securePage");
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(servletRequest.getQueryString()).thenReturn("abc=123&doremi=abc123");
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final HttpServletResponse servletResponse = mock(HttpServletResponse.class);
        when(messageInfo.getResponseMessage()).thenReturn(servletResponse);

        final Subject client = new Subject();
        module.validateRequest(messageInfo, client, null);
    }

    /**
     * Tests the login endpoint GET operation.
     */
    @Test
    public void testLogin() throws Exception {

        final TestServerAuthModule module = new TestServerAuthModule();
        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);

        final CallbackHandler h = mock(CallbackHandler.class);
        module.initialize(mockRequestPolicy, null, h, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("GET");
        when(servletRequest.isSecure()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn("/util/j_security_check");
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(servletRequest.getParameter("state")).thenReturn("/");
        when(servletRequest.getRequestDispatcher(Matchers.anyString())).thenReturn(mock(RequestDispatcher.class));
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final Subject client = new Subject();
        assertEquals(AuthStatus.SEND_SUCCESS, module.validateRequest(messageInfo, client, null));
        verifyZeroInteractions(h);
    }

    /**
     * Tests the login endpoint POST operation.
     */
    @Test
    public void testLoginPost() throws Exception {

        final TestServerAuthModule module = new TestServerAuthModule();
        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);

        final CallbackHandler h = mock(CallbackHandler.class);
        module.initialize(mockRequestPolicy, null, h, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("POST");
        when(servletRequest.isSecure()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn("/util/j_security_check");
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(servletRequest.getParameter("state")).thenReturn("/");
        when(servletRequest.getParameter("j_username")).thenReturn("foofoo");
        when(servletRequest.getRequestDispatcher(Matchers.anyString())).thenReturn(mock(RequestDispatcher.class));
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final HttpServletResponse servletResponse = mock(HttpServletResponse.class);
        when(messageInfo.getResponseMessage()).thenReturn(servletResponse);

        final Subject client = new Subject();
        assertEquals(AuthStatus.SEND_SUCCESS, module.validateRequest(messageInfo, client, null));

        final ArgumentCaptor<String> redirectUri = ArgumentCaptor.forClass(String.class);
        verify(servletResponse).sendRedirect(redirectUri.capture());
        assertEquals("/util/", redirectUri.getValue());
        verifyZeroInteractions(h);
    }

    /**
     * Tests the login endpoint POST operation with .. in state that resolves
     * cleanly.
     */
    @Test
    public void testLoginPostWithParen() throws Exception {

        final TestServerAuthModule module = new TestServerAuthModule();
        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);

        final CallbackHandler h = mock(CallbackHandler.class);
        module.initialize(mockRequestPolicy, null, h, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("POST");
        when(servletRequest.isSecure()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn("/util/j_security_check");
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(servletRequest.getParameter("state")).thenReturn("/abc/../abc/../abc/abc/../abc/../aaaa");
        when(servletRequest.getParameter("j_username")).thenReturn("foofoo");
        when(servletRequest.getRequestDispatcher(Matchers.anyString())).thenReturn(mock(RequestDispatcher.class));
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final HttpServletResponse servletResponse = mock(HttpServletResponse.class);
        when(messageInfo.getResponseMessage()).thenReturn(servletResponse);

        final Subject client = new Subject();
        assertEquals(AuthStatus.SEND_SUCCESS, module.validateRequest(messageInfo, client, null));

        final ArgumentCaptor<String> redirectUri = ArgumentCaptor.forClass(String.class);
        verify(servletResponse).sendRedirect(redirectUri.capture());
        assertEquals("/util/abc/aaaa", redirectUri.getValue());
        verifyZeroInteractions(h);
    }

    /**
     * Tests the login endpoint POST operation.
     */
    @Test
    public void testLoginPostWithQuery() throws Exception {

        final TestServerAuthModule module = new TestServerAuthModule();
        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);

        final CallbackHandler h = mock(CallbackHandler.class);
        module.initialize(mockRequestPolicy, null, h, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("POST");
        when(servletRequest.isSecure()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn("/util/j_security_check");
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(servletRequest.getParameter("state")).thenReturn("/securePage?abc=123&doremi=abc123");
        when(servletRequest.getParameter("j_username")).thenReturn("foofoo");
        when(servletRequest.getRequestDispatcher(Matchers.anyString())).thenReturn(mock(RequestDispatcher.class));
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final HttpServletResponse servletResponse = mock(HttpServletResponse.class);
        when(messageInfo.getResponseMessage()).thenReturn(servletResponse);

        final Subject client = new Subject();
        assertEquals(AuthStatus.SEND_SUCCESS, module.validateRequest(messageInfo, client, null));

        final ArgumentCaptor<String> redirectUri = ArgumentCaptor.forClass(String.class);
        verify(servletResponse).sendRedirect(redirectUri.capture());
        assertEquals("/util/securePage?abc=123&doremi=abc123", redirectUri.getValue());
        verifyZeroInteractions(h);
    }

    /**
     * Tests the logout endpoint GET operation.
     */
    @Test
    public void testLogout() throws Exception {

        final TestServerAuthModule module = new TestServerAuthModule();
        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);

        final CallbackHandler h = mock(CallbackHandler.class);
        module.initialize(mockRequestPolicy, null, h, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("GET");
        when(servletRequest.isSecure()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn("/util/j_logout");
        when(servletRequest.getRequestURL()).thenReturn(new StringBuffer("https://www.trajano.net/util/j_logout"));
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(servletRequest.getParameter("post_logout_redirect_uri")).thenReturn("https://www.trajano.net/util/");
        when(servletRequest.getRequestDispatcher(Matchers.anyString())).thenReturn(mock(RequestDispatcher.class));
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final HttpServletResponse servletResponse = mock(HttpServletResponse.class);
        when(messageInfo.getResponseMessage()).thenReturn(servletResponse);

        final Subject client = new Subject();
        assertEquals(AuthStatus.SEND_SUCCESS, module.validateRequest(messageInfo, client, null));
        verifyZeroInteractions(h);
    }

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
        when(servletRequest.getRequestURI()).thenReturn("/util/ejb2");
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

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

    /**
     * Tests the redirect to login.
     */
    @Test
    public void testRedirectToLogin() throws Exception {

        final TestServerAuthModule module = new TestServerAuthModule();
        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);

        final CallbackHandler h = mock(CallbackHandler.class);
        module.initialize(mockRequestPolicy, null, h, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("GET");
        when(servletRequest.isSecure()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn("/util/securePage");
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final HttpServletResponse servletResponse = mock(HttpServletResponse.class);
        when(messageInfo.getResponseMessage()).thenReturn(servletResponse);

        final Subject client = new Subject();
        final ArgumentCaptor<String> redirectUri = ArgumentCaptor.forClass(String.class);
        assertEquals(AuthStatus.SEND_SUCCESS, module.validateRequest(messageInfo, client, null));
        verify(servletResponse).sendRedirect(redirectUri.capture());
        assertEquals("/util/j_security_check?state=%2FsecurePage", redirectUri.getValue());
        verifyZeroInteractions(h);
    }

    /**
     * Tests the redirect to login.
     */
    @Test
    public void testRedirectToLoginWithQueryString() throws Exception {

        final TestServerAuthModule module = new TestServerAuthModule();
        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);

        final CallbackHandler h = mock(CallbackHandler.class);
        module.initialize(mockRequestPolicy, null, h, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("GET");
        when(servletRequest.isSecure()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn("/util/securePage");
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(servletRequest.getQueryString()).thenReturn("abc=123&doremi=abc123");
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final HttpServletResponse servletResponse = mock(HttpServletResponse.class);
        when(messageInfo.getResponseMessage()).thenReturn(servletResponse);

        final Subject client = new Subject();
        final ArgumentCaptor<String> redirectUri = ArgumentCaptor.forClass(String.class);
        assertEquals(AuthStatus.SEND_SUCCESS, module.validateRequest(messageInfo, client, null));
        verify(servletResponse).sendRedirect(redirectUri.capture());
        assertEquals("/util/j_security_check?state=%2FsecurePage%3Fabc%3D123%26doremi%3Dabc123", redirectUri.getValue());
        final String decoded = URLDecoder.decode(URI.create(redirectUri.getValue()).getRawQuery().substring("state=".length()), "US-ASCII");
        assertEquals("/securePage?abc=123&doremi=abc123", decoded);
        verifyZeroInteractions(h);
    }

    @Test
    public void testSecureMessage() throws Exception {

        final Subject subject = new Subject();

        final Principal groupPrincipal = mock(Principal.class);
        when(groupPrincipal.getName()).thenReturn("authenticated");
        subject.getPrincipals().add(groupPrincipal);

        final Principal userPrincipal = mock(Principal.class);
        when(userPrincipal.getName()).thenReturn("https://foo@test-server-auth-module");
        subject.getPrincipals().add(userPrincipal);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final Cookie[] cookies = new Cookie[] {
            new Cookie("X-Subject", "https://foo@test-server-auth-module"),
            new Cookie("not-relevant", "foo")
        };
        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("POST");
        when(servletRequest.isSecure()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn("/util/secure_page");
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(servletRequest.getCookies()).thenReturn(cookies);
        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final CallbackHandler h = mock(CallbackHandler.class);

        final ServerAuthModule sam = new TestServerAuthModule();

        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);

        sam.initialize(mockRequestPolicy, null, h, options);

        assertEquals(AuthStatus.SUCCESS, sam.validateRequest(messageInfo, null, subject));
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

    @Test
    public void testSupportedMessageTypes() {

        assertEquals(2, new TestServerAuthModule().getSupportedMessageTypes().length);
    }
}
