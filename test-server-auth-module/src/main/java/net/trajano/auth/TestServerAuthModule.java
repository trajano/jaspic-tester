package net.trajano.auth;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.Map;

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
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.UriBuilder;

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
 * The module does not make use of <code>HttpSession</code> but instead uses a
 * cookie <code>X-Subject</code> to store the subject.
 * </p>
 * 
 * @author Archimedes Trajano
 */
public class TestServerAuthModule implements ServerAuthModule, ServerAuthContext {

    /**
     * Login endpoint.
     */
    public static final String LOGIN_ENDPOINT = "/j_security_check";

    /**
     * Logout endpoint.
     */
    public static final String LOGOUT_ENDPOINT = "/j_logout";

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
     * Subject cookie key.
     */
    public static final String SUBJECT_COOKIE_KEY = "X-Subject";

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
     * Does nothing.
     *
     * @param messageInfo
     *            message info
     * @param subject
     *            subject
     */
    @Override
    public void cleanSubject(final MessageInfo messageInfo,
        final Subject subject) throws AuthException {

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
            HttpServletResponse.class };
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
     * @throws IOException
     *             servlet error
     * @throws ServletException
     *             servlet error
     */
    private AuthStatus handleLoginEndpoint(HttpServletRequest req,
        HttpServletResponse resp) throws ServletException, IOException {

        if ("GET".equals(req.getMethod())
                && req.getParameter(STATE) != null && req.isSecure()) {
            System.out.println("about to dispatch");
            req.getRequestDispatcher("/WEB-INF/login.jsp").forward(req, resp);
            System.out.println("after dispatch");
            return AuthStatus.SEND_SUCCESS;
        }
        if ("POST".equals(req.getMethod())
                && req.getParameter(STATE) != null && req.isSecure()) {
            String subject = UriBuilder.fromUri("https://test-server-auth-module").userInfo(req.getParameter("j_username"))
                .build().toASCIIString();
            Cookie cookie = new Cookie(SUBJECT_COOKIE_KEY, subject);
            cookie.setSecure(true);
            cookie.setHttpOnly(true);
            resp.addCookie(cookie);
            resp.sendRedirect(req.getContextPath() + req.getParameter(STATE));
            return AuthStatus.SEND_SUCCESS;
        }
        return AuthStatus.SEND_FAILURE;
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
     * @throws IOException
     *             servlet error
     * @throws ServletException
     *             servlet error
     */
    private AuthStatus handleLogoutEndpoint(HttpServletRequest req,
        HttpServletResponse resp) throws ServletException, IOException {

        if (req.getParameter(POST_LOGOUT_REDIRECT_URI) != null) {
            Cookie cookie = new Cookie(SUBJECT_COOKIE_KEY, "");
            cookie.setMaxAge(0);
            resp.addCookie(cookie);
            resp.sendRedirect(req.getParameter(POST_LOGOUT_REDIRECT_URI));
            return AuthStatus.SEND_SUCCESS;
        }
        return AuthStatus.SEND_FAILURE;
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

            String subject = null;
            if (req.getCookies() != null) {
                for (Cookie cookie : req.getCookies()) {
                    if (SUBJECT_COOKIE_KEY.equals(cookie.getName())) {
                        subject = cookie.getValue();
                    }
                }
            }

            // Check if there is no subject
            if (subject == null) {
                // The JASPIC spec is ambiguous for this scenario, however
                // SEND_SUCCESS works on the top three application servers.

                resp.sendRedirect(UriBuilder.fromUri(req.getContextPath()).path(LOGIN_ENDPOINT)
                    .queryParam("state", localRequestUri).build().toASCIIString());
                return AuthStatus.SEND_SUCCESS;
            }

            handler.handle(new Callback[] {
                new CallerPrincipalCallback(client, subject),
                new GroupPrincipalCallback(client, new String[] {
                    "authenticated" }) });
            return AuthStatus.SUCCESS;

        } catch (final IOException
                 | ServletException
                 | UnsupportedCallbackException e) {
            e.printStackTrace();
            throw new AuthException(e.getMessage());
        }
    }

}
