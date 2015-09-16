package net.trajano.auth;

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.config.AuthConfigProvider;
import javax.security.auth.message.config.ClientAuthConfig;
import javax.security.auth.message.config.ServerAuthConfig;

/**
 * This is used to provide the server auth module on the application rather than
 * being globally configured in a container.
 */
public class AuthModuleConfigProvider implements
    AuthConfigProvider {

    /**
     * Options.
     */
    private final Map<String, String> options;

    /**
     * This is called by
     * {@link AuthConfigFactory#registerConfigProvider(String, Map, String, String, String)}
     * when registering the provider.
     *
     * @param options
     *            options to pass to the modules and the name of the module
     *            classes
     * @param authConfigFactory
     *            configuration factory
     */
    public AuthModuleConfigProvider(final Map<String, String> options,
        final AuthConfigFactory factory) {

        this.options = options;
        if (factory != null) {
            factory.registerConfigProvider(this, null, null, "Auto registration");
        }
    }

    /**
     * <p>
     * Client authentication is not provided.
     * </p>
     * {@inheritDoc}
     *
     * @return <code>null</code>
     */
    @Override
    public ClientAuthConfig getClientAuthConfig(final String layer,
        final String appContext,
        final CallbackHandler handler) throws AuthException {

        return null;
    }

    /**
     * {@inheritDoc}
     *
     * @return {@link TestServerAuthModuleAuthConfig} with the data that was
     *         provided.
     */
    @Override
    public ServerAuthConfig getServerAuthConfig(final String layer,
        final String appContext,
        final CallbackHandler handler) throws AuthException {

        return new TestServerAuthModuleAuthConfig(options, layer, appContext, handler);
    }

    /**
     * Does nothing.
     */
    @Override
    public void refresh() {

        // does nothing
    }

}
