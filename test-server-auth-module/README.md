Test Server Auth Module
=======================

This is a JASPIC `ServerAuthModule` used for testing purposes.  It is not
meant to be used for a production system.

The module will detect if the user is not yet authenticated to a simple web
form that asks for a user name.  It forms a subject with the pattern

    https://[username]@test-server-auth-module

The module does not make use of `HttpSession` but instead uses a cookie 
`X-Subject` to store the subject.

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