/**
 *
 */
package net.trajano.auth.sample;

import java.util.logging.Logger;

import javax.servlet.annotation.WebListener;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

/**
 * @author Archimedes Trajano
 */
@WebListener
public class SessionListener implements
    HttpSessionListener {

    /**
     * Logger.
     */
    private static final Logger LOG = Logger.getLogger(SessionListener.class.getName());

    /**
     * {@inheritDoc}
     */
    @Override
    public void sessionCreated(final HttpSessionEvent hse) {

        LOG.info("session created source=" + hse.getSource() + " session=" + hse.getSession());

    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void sessionDestroyed(final HttpSessionEvent hse) {

        LOG.info("session destroyed=" + hse.getSession());
    }

}
