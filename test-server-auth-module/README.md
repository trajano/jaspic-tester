Test Server Auth Module
=======================

This is a JASPIC `ServerAuthModule` used for testing purposes.  It is not
meant to be used for a production system.

The module will detect if the user is not yet authenticated to a simple web
form that asks for a user name.  It forms a subject with the pattern

    https://[username]@test-server-auth-module

There are two modes of operation for the module.

* cookie based where the module does not make use of `HttpSession` but 
  instead uses a cookie `X-Subject` to store the subject.  This allows
  better use for RESTful applications.
* session based where the subject is stored in the session and has an
  added security of using a nonce.

### Usage

To use the cookie based module add the following to `web.xml` 

	<listener>
		<listener-class>net.trajano.auth.Initializer</listener-class>
	</listener>

To use the session based module add the following to `web.xml` 

	<listener>
		<listener-class>net.trajano.auth.session.Initializer</listener-class>
	</listener>

Note session based module has only been confirmed to work with Glassfish
and WildFly, it does not work with WebSphere Liberty Profile as it commits
the response at an earlier period thus preventing the session cookie from
being sent correctly in the response.

### Scope

In order to keep this project small as to allow easier bug reports against
JASPIC implementations of various application servers, some things had to be
removed.

Here are a list of things that can be done to allow it to be used on
production systems.

* in `handleLoginEndpoint` make it connect to a data store that verifies
  the identity of the user.  A password can also be passed in.
* use AES encryption using a secret key that is generated in `Initializer`
  and put in a distributed cache such as Hazelcast to allow usage in a
  distributed system.  The key would be passed in via the options `Map`
* if you are already using sessions, you can store the subject as a
  session attribute
* If using a session, handle the `POST` method when a redirect is needed
  by storing the `POST` data into a session variable temporarily and then
  dispatching it later when recovering.
* Encrypting the subject combined with a time based nonce in the cookie.
  At present the implementation will allow anyone who can change the cookie
  to get authenticated as someone else.
