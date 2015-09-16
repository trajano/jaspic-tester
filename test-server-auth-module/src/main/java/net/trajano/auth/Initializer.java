package net.trajano.auth;

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.message.config.AuthConfigFactory;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class Initializer implements
    ServletContextListener {

    private String registration;

    /**
     * <p>
     * Removes registration from the factory.
     * </p>
     * {@inheritDoc}
     */
    @Override
    public void contextDestroyed(final ServletContextEvent sce) {

        AuthConfigFactory.getFactory().removeRegistration(registration);
    }

    /**
     * <p>
     * Registers the configuration into the factory.
     * </p>
     * {@inheritDoc}
     */
    @Override
    public void contextInitialized(final ServletContextEvent sce) {

        final Map<String, String> options = new HashMap<>();
        registration = AuthConfigFactory.getFactory().registerConfigProvider(AuthModuleConfigProvider.class.getName(),
            options, "HttpServlet", null, null);

    }

}
