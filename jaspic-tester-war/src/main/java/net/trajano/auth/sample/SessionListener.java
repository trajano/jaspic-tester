/**
 * 
 */
package net.trajano.auth.sample;

import javax.servlet.annotation.WebListener;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

/**
 * @author Archimedes Trajano
 */
@WebListener
public class SessionListener implements
    HttpSessionListener {

    /*
     * (non-Javadoc)
     * @see
     * javax.servlet.http.HttpSessionListener#sessionCreated(javax.servlet.http
     * .HttpSessionEvent)
     */
    @Override
    public void sessionCreated(HttpSessionEvent hse) {

        System.out.println("session created source=" + hse.getSource());

    }

    /*
     * (non-Javadoc)
     * @see
     * javax.servlet.http.HttpSessionListener#sessionDestroyed(javax.servlet
     * .http.HttpSessionEvent)
     */
    @Override
    public void sessionDestroyed(HttpSessionEvent hse) {

        System.out.println("session destroyed");
    }

}
