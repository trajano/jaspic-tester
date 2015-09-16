package net.trajano.auth.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.config.ServerAuthContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;

import net.trajano.auth.AuthModuleConfigProvider;
import net.trajano.auth.Initializer;

/**
 * Tests the initialization of the module via application managed methods.
 *
 * @author Archimedes Trajano
 */
public class ApplicationManagedJaspicTest {

    @Test
    public void testInitializer() throws Exception {

        AuthConfigFactory.setFactory(mock(AuthConfigFactory.class));
        final Initializer i = new Initializer();
        i.contextInitialized(null);
        i.contextDestroyed(null);
    }

    @Test
    public void testProvider() throws Exception {

        final CallbackHandler h = mock(CallbackHandler.class);
        final Map<String, String> options = new HashMap<>();
        final AuthModuleConfigProvider provider = new AuthModuleConfigProvider(options, null);
        assertNull(provider.getClientAuthConfig("HttpServlet", "server1 /", h));

        final ServerAuthConfig serverAuthConfig = provider.getServerAuthConfig("HttpServlet", "server1 /", h);
        assertNotNull(serverAuthConfig);
        assertEquals("server1 /", serverAuthConfig.getAppContext());
        assertEquals("HttpServlet", serverAuthConfig.getMessageLayer());

        final Subject serviceSubject = new Subject();

        assertNull(serverAuthConfig.getAuthContextID(mock(MessageInfo.class)));

        final ServerAuthContext nonMandatoryAuthContext = serverAuthConfig.getAuthContext(null, serviceSubject, null);
        assertNotNull(nonMandatoryAuthContext);

        final MessageInfo messageInfoMandatory = mock(MessageInfo.class);
        when(messageInfoMandatory.getMap()).thenReturn(Collections.singletonMap("javax.security.auth.message.MessagePolicy.isMandatory", "true"));

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("GET");
        when(servletRequest.isSecure()).thenReturn(true);
        when(servletRequest.getRequestURI()).thenReturn("/util/ejb2");
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(messageInfoMandatory.getRequestMessage()).thenReturn(servletRequest);

        final HttpServletResponse servletResponse = mock(HttpServletResponse.class);
        when(messageInfoMandatory.getResponseMessage()).thenReturn(servletResponse);

        final String authContextID = serverAuthConfig.getAuthContextID(messageInfoMandatory);
        assertNotNull(authContextID);

        final ServerAuthContext authContext = serverAuthConfig.getAuthContext(authContextID, serviceSubject, new HashMap<>());
        assertNotNull(authContext);
        final AuthStatus validateRequest = authContext.validateRequest(messageInfoMandatory, null, serviceSubject);
        assertEquals(AuthStatus.SEND_SUCCESS, validateRequest);

        final AuthStatus secureResponse = authContext.secureResponse(messageInfoMandatory, serviceSubject);
        assertEquals(AuthStatus.SEND_SUCCESS, secureResponse);

        authContext.cleanSubject(messageInfoMandatory, serviceSubject);

        assertTrue(serverAuthConfig.isProtected());
        serverAuthConfig.refresh();
        provider.refresh();

    }

    @Test
    public void testProviderAutoRegistration() throws Exception {

        final Map<String, String> options = new HashMap<>();
        new AuthModuleConfigProvider(options, mock(AuthConfigFactory.class));
    }
}
