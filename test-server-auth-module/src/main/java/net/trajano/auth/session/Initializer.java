package net.trajano.auth.session;

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.message.config.AuthConfigFactory;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

/**
 * <p>
 * This initializes the Server Auth Module Auth Config for the servlet context.
 * It is registered in the web.xml file as a listener.
 * </p>
 *
 * @author Archimedes Trajano
 */
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
