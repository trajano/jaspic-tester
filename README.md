Test Server Auth Module
=======================

This is a JASPIC `ServerAuthModule` used for testing purposes.

The module will detect if the user is not yet authenticated to a simple web
form that asks for a user name.  It forms a subject with the pattern

    https://[username]@test-server-auth-module

