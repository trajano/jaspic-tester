package net.trajano.auth.session;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLEncoder;
import java.security.Principal;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.UriBuilder;
import javax.xml.bind.DatatypeConverter;

/**
 * <p>
 * This is a JASPIC {@link ServerAuthModule} used for testing purposes.
 * </p>
 * <p>
 * The module will detect if the user is not yet authenticated to a simple web
 * form that asks for a user name. It forms a subject with the pattern
 * </p>
 *
 * <pre>
 * https://[username]@test-server-auth-module
 * </pre>
 * <p>
 * The module does uses <code>HttpSession</code> to store the data subject and
 * nonce data.
 * </p>
 *
 * @author Archimedes Trajano
 */
public class TestServerAuthModule implements
    ServerAuthModule,
    ServerAuthContext {

    /**
     * Groups associated to the user.
     */
    private static final String[] GROUPS = {
        "authenticated"
    };

    /**
     * Logger.
     */
    private static final Logger LOG = Logger.getLogger(TestServerAuthModule.class.getName());

    /**
     * Login endpoint.
     */
    public static final String LOGIN_ENDPOINT = "/j_security_check";

    /**
     * Logout endpoint.
     */
    public static final String LOGOUT_ENDPOINT = "/j_logout";

    /**
     * Request parameter for nonce. <code>nonce</code> is used to make it
     * consistent with OpenID Connect specifications.
     */
    public static final String NONCE = "nonce";

    /**
     * Nonce session key.
     */
    public static final String NONCE_SESSION_KEY = "X-Nonce";

    /**
     * Post logout redirect URI. The value is used to make it consistent with
     * OpenID Connect specifications.
     */
    public static final String POST_LOGOUT_REDIRECT_URI = "post_logout_redirect_uri";

    /**
     * Request parameter for state. <code>state</code> is used to make it
     * consistent with OpenID Connect specifications.
     */
    public static final String STATE = "state";

    /**
     * Subject session key.
     */
    public static final String SUBJECT_SESSION_KEY = "X-Subject";

    /**
     * Obtains the subject from the cookies in the HttpServletRequest.
     *
     * @param req
     *            servlet request
     * @return subject may be null if not found
     */
    private static String getSubject(final HttpServletRequest req) {

        final HttpSession session = req.getSession(false);
        if (session == null) {
            return null;
        }
        return (String) session.getAttribute(SUBJECT_SESSION_KEY);
    }

    /**
     * Handle the login endpoint. This will display the login page and will
     * handle login POST action.
     *
     * @param req
     *            request
     * @param resp
     *            response
     * @return authentication status
     * @throws AuthException
     *             happens when there is invalid request data
     * @throws IOException
     *             servlet error
     * @throws ServletException
     *             servlet error
     */
    private static AuthStatus handleLoginEndpoint(final HttpServletRequest req,
        final HttpServletResponse resp) throws ServletException,
            AuthException,
            IOException {

        if (!req.isSecure()) {
            throw new AuthException("Secure connection is required");
        }

        final String state = req.getParameter(STATE);
        if (state == null) {
            throw new AuthException("missing 'state' parameter");
        }

        // Ensure that the state is valid, it should be relative
        final URI stateUri = URI.create(state).normalize();
        validateStateUri(stateUri);

        final String nonce = req.getParameter(NONCE);
        if (nonce == null) {
            throw new AuthException("missing 'nonce' parameter");
        }

        if ("GET".equals(req.getMethod())) {
            return handleLoginGet(req, resp);
        } else if ("POST".equals(req.getMethod())) {
            return handleLoginPost(req, resp, stateUri, nonce);
        } else {
            throw new AuthException("unsupported method");
        }
    }

    /**
     * Handles the GET method for login endpoint.
     *
     * @param req
     *            request
     * @param resp
     *            response
     * @return {@link AuthStatus#SEND_SUCCESS}
     * @throws IOException
     *             servlet error
     * @throws ServletException
     *             servlet error
     */
    private static AuthStatus handleLoginGet(final HttpServletRequest req,
        final HttpServletResponse resp) throws ServletException,
            IOException {

        req.getRequestDispatcher("/WEB-INF/login.jsp").forward(req, resp);
        return AuthStatus.SEND_SUCCESS;
    }

    /**
     * Handles the POST method for login endpoint.
     *
     * @param req
     *            request
     * @param resp
     *            response
     * @param stateUri
     *            URI for the state
     * @param nonce
     *            nonce
     * @return {@link AuthStatus#SEND_SUCCESS}
     * @throws IOException
     *             servlet error
     * @throws ServletException
     *             servlet error
     * @throws AuthException
     *             authentication error
     */
    private static AuthStatus handleLoginPost(final HttpServletRequest req,
        final HttpServletResponse resp,
        final URI stateUri,
        final String nonce) throws ServletException,
            IOException,
            AuthException {

        final HttpSession session = req.getSession(false);
        if (session == null) {
            throw new AuthException("session is required");
        }
        if (!nonce.equals(session.getAttribute(NONCE_SESSION_KEY))) {
            throw new AuthException("nonce mismatch");
        }
        final String subject = UriBuilder.fromUri("https://test-server-auth-module").userInfo(req.getParameter("j_username"))
            .build().toASCIIString();
        session.setAttribute(SUBJECT_SESSION_KEY, subject);

        // Remove nonce as it is no longer required
        session.removeAttribute(NONCE_SESSION_KEY);
        final String redirectUri = req.getContextPath() + stateUri.toASCIIString();
        resp.sendRedirect(URI.create(redirectUri).normalize().toASCIIString());
        return AuthStatus.SEND_SUCCESS;
    }

    /**
     * Handle the logout endpoint. This will clear the cookie and redirect to
     * the URI that has been specified.
     *
     * @param req
     *            request
     * @param resp
     *            response
     * @return authentication status
     * @throws AuthException
     *             happens when there is invalid request data
     * @throws IOException
     *             servlet error
     * @throws ServletException
     *             servlet error
     */
    private static AuthStatus handleLogoutEndpoint(final HttpServletRequest req,
        final HttpServletResponse resp) throws AuthException,
            ServletException,
            IOException {

        final String postLogoutRedirectUri = req.getParameter(POST_LOGOUT_REDIRECT_URI);
        if (postLogoutRedirectUri != null) {

            final String postLogoutRedirectUriNormalized = URI.create(postLogoutRedirectUri).normalize().toASCIIString();
            // Check that the post logout redirect uri is relative to the application if not fail.
            final String contextUri = URI.create(req.getRequestURL().toString()).resolve(req.getContextPath()).toASCIIString();
            if (!postLogoutRedirectUriNormalized.startsWith(contextUri)) {
                throw new AuthException("invalid post_logout_redirect_uri");
            }

            final HttpSession session = req.getSession(false);
            if (session != null) {
                session.removeAttribute(SUBJECT_SESSION_KEY);
                session.removeAttribute(NONCE_SESSION_KEY);
            }
            resp.sendRedirect(postLogoutRedirectUriNormalized);
            return AuthStatus.SEND_SUCCESS;
        }
        throw new AuthException("missing post_logout_redirect_uri");
    }

    /**
     * Builds the redirect URI including the assembly of <code>state</code>.
     *
     * @param req
     *            servlet request
     * @param resp
     *            servlet response
     * @return {@link AuthStatus#SEND_SUCCESS}
     * @throws AuthException
     *             happens when there is invalid request data
     * @throws IOException
     *             servlet error
     * @throws ServletException
     *             servlet error
     */
    private static AuthStatus handleRedirectToLoginEndpoint(final HttpServletRequest req,
        final HttpServletResponse resp) throws AuthException,
            ServletException,
            IOException {

        if (!"GET".equals(req.getMethod())) {
            throw new AuthException("Only 'GET' method is supported when redirecting to the endpoint");
        }
        final StringBuilder stateBuilder = new StringBuilder(req.getRequestURI().substring(req.getContextPath().length()));
        if (req.getQueryString() != null) {
            stateBuilder.append('?');
            stateBuilder.append(req.getQueryString());
        }
        final byte[] nonce = new byte[8];
        ThreadLocalRandom.current().nextBytes(nonce);

        final String nonceString = DatatypeConverter.printHexBinary(nonce);
        req.getSession().setAttribute(NONCE_SESSION_KEY, nonceString);
        final StringBuilder redirectUriBuilder = new StringBuilder(req.getContextPath());
        redirectUriBuilder.append(LOGIN_ENDPOINT);
        redirectUriBuilder.append("?state=");
        redirectUriBuilder.append(
            URLEncoder.encode(stateBuilder.toString(), "US-ASCII"));
        redirectUriBuilder.append("&nonce=");
        redirectUriBuilder.append(nonceString);
        resp.sendRedirect(URI.create(redirectUriBuilder.toString()).normalize().toASCIIString());

        // The JASPIC spec is ambiguous for this scenario, however
        // SEND_SUCCESS works on the top three application servers.

        return AuthStatus.SEND_SUCCESS;
    }

    /**
     * Validates the state URI. It ensures that it is:
     * <ul>
     * <li>an absolute URI, no <code>http:</code> or any other scheme
     * definition.
     * <li>It has no host component.
     * <li>Path must start with <code>/</code>
     * <li>Path must not contain <code>/..</code>
     * </ul>
     *
     * @param stateUri
     *            URI to evaluate
     * @throws AuthException
     *             validation failure
     */
    private static void validateStateUri(final URI stateUri) throws AuthException {

        if (stateUri.isAbsolute()) {
            throw new AuthException("'state' must not be an absolute URI");
        }
        if (stateUri.getHost() != null) {
            throw new AuthException("'state' must not have a host component");
        }
        if (!stateUri.getPath().startsWith("/")) {
            throw new AuthException("'state' must start with '/'");
        }
        if (stateUri.getPath().contains("/..")) {
            throw new AuthException("'state' must not resolve to a parent path");
        }
    }

    /**
     * Callback handler that is passed in initialize by the container. This
     * processes the callbacks which are objects that populate the "subject".
     */
    private CallbackHandler handler;

    /**
     * Mandatory flag.
     */
    private boolean mandatory;

    /**
     * Removes the <code>authenticated</code> group and the user ID from the
     * principal set.
     *
     * @param messageInfo
     *            message info
     * @param subject
     *            subject
     */
    @Override
    public void cleanSubject(final MessageInfo messageInfo,
        final Subject subject) throws AuthException {

        final HttpServletRequest req = (HttpServletRequest) messageInfo.getRequestMessage();
        final String subjectCookie = getSubject(req);

        final Iterator<Principal> iterator = subject.getPrincipals().iterator();
        while (iterator.hasNext()) {
            final Principal principal = iterator.next();
            if ("authenticated".equals(principal.getName())) {
                iterator.remove();
            }
            if (principal.getName().equals(subjectCookie)) {
                iterator.remove();
            }
        }
        // Does nothing.
    }

    /**
     * <p>
     * Supported message types. For our case we only need to deal with HTTP
     * servlet request and responses. On Java EE 7 this will handle WebSockets
     * as well.
     * </p>
     * <p>
     * This creates a new array for security at the expense of performance.
     * </p>
     *
     * @return {@link HttpServletRequest} and {@link HttpServletResponse}
     *         classes.
     */
    @SuppressWarnings("rawtypes")
    @Override
    public Class[] getSupportedMessageTypes() {

        return new Class<?>[] {
            HttpServletRequest.class,
            HttpServletResponse.class
        };
    }

    /**
     * {@inheritDoc}
     *
     * @param requestPolicy
     *            request policy, ignored
     * @param responsePolicy
     *            response policy, ignored
     * @param h
     *            callback handler
     * @param options
     *            options
     */
    @Override
    public void initialize(final MessagePolicy requestPolicy,
        final MessagePolicy responsePolicy,
        final CallbackHandler h,
        @SuppressWarnings("rawtypes") final Map options) throws AuthException {

        handler = h;
        mandatory = requestPolicy.isMandatory();
    }

    /**
     * Return {@link AuthStatus#SEND_SUCCESS}.
     *
     * @param messageInfo
     *            contains the request and response messages. At this point the
     *            response message is already committed so nothing can be
     *            changed.
     * @param subject
     *            subject.
     * @return {@link AuthStatus#SEND_SUCCESS}
     */
    @Override
    public AuthStatus secureResponse(final MessageInfo messageInfo,
        final Subject subject) throws AuthException {

        return AuthStatus.SEND_SUCCESS;
    }

    /**
     * <p>
     * Checks for the presence of the cookie, if it is present it will use that
     * as the subject if not it will redirect to a login screen.
     * </p>
     * {@inheritDoc}
     */
    @Override
    public AuthStatus validateRequest(final MessageInfo messageInfo,
        final Subject client,
        final Subject serviceSubject)
            throws AuthException {

        final HttpServletRequest req = (HttpServletRequest) messageInfo.getRequestMessage();
        final HttpServletResponse resp = (HttpServletResponse) messageInfo.getResponseMessage();
        try {

            final String localRequestUri = req.getRequestURI().substring(req.getContextPath().length());

            if (LOGIN_ENDPOINT.equals(localRequestUri)) {
                return handleLoginEndpoint(req, resp);
            }

            if (LOGOUT_ENDPOINT.equals(localRequestUri)) {
                return handleLogoutEndpoint(req, resp);
            }

            // Allow if authentication is not required.
            if (!mandatory) {
                return AuthStatus.SUCCESS;
            }

            // require SSL if mandatory
            if (!req.isSecure()) {
                resp.sendError(HttpURLConnection.HTTP_FORBIDDEN, "SSL Required");
                return AuthStatus.SEND_FAILURE;
            }

            final String subject = getSubject(req);

            // Check if there is no subject then redirect to login endpoint
            if (subject == null) {
                return handleRedirectToLoginEndpoint(req, resp);
            }

            handler.handle(new Callback[] {
                new CallerPrincipalCallback(client, subject),
                new GroupPrincipalCallback(client, GROUPS)
            });
            return AuthStatus.SUCCESS;

        } catch (final IOException
            | ServletException
            | UnsupportedCallbackException e) {
            LOG.throwing(TestServerAuthModule.class.getName(), "validateRequest", e);
            throw new AuthException(e.getMessage());
        }
    }
}
