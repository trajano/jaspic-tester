Test Server Auth Module
=======================

This is a JASPIC `ServerAuthModule` used for testing purposes.

The module will detect if the user is not yet authenticated to a simple web
form that asks for a user name.  It forms a subject with the pattern

    https://[username]@test-server-auth-module

The module does not make use of `HttpSession` but instead uses a cookie 
`X-Encrypted-Subject` to store an encrypted version of the subject.  The 
encryption key is generated and stored in the `ServletContext`.
