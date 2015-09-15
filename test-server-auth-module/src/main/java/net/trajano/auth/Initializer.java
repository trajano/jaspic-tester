package net.trajano.auth;

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.message.config.AuthConfigFactory;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class Initializer implements ServletContextListener {

	@Override
	public void contextDestroyed(ServletContextEvent sce) {
		AuthConfigFactory.getFactory().removeRegistration(registration);
	}

	@Override
	public void contextInitialized(ServletContextEvent sce) {
		Map<String, String> options = new HashMap<>();
		registration = AuthConfigFactory.getFactory().registerConfigProvider(AuthModuleConfigProvider.class.getName(),
				options, "HttpServlet", null, null);

	}

	private String registration;

}
