JASPIC Tester Web Application
=============================

This is a simple web application that demonstrates the use of 
[Test Server Auth Module][1].  It has been tested in the following
configurations

### Glassfish 4.1/Payara 4.1.153

* No extra configuration required.  `glassfish-web.xml` registers 
  the mapping from role to group.

### WebSphere Liberty Profile 8.5.5.7

* Requires a Security Role to group binding from `authenticated` to 
  `authenticated`
* A *UserRegistry*, *Basic User Registry* would do.  The user does not need
  to be in the registry, however the group must be `authenticated` as well.
* Automatic redirection to the secure port is not done by WLP when
  `security-constraint` is specified.

### WildFly 9.0.1
* Execute the following commands via jboss-cli.sh from [GitHub][3]

    /subsystem=security/security-domain=jaspitest:add(cache-type=default)
    /subsystem=security/security-domain=jaspitest/authentication=jaspi:add()
    /subsystem=security/security-domain=jaspitest/authentication=jaspi/login-module-stack=dummy:add()
    /subsystem=security/security-domain=jaspitest/authentication=jaspi/login-module-stack=dummy/login-module=dummy:add(code=Dummy, flag=optional)
    /subsystem=security/security-domain=jaspitest/authentication=jaspi/auth-module=jaspi:add(code=org.wildfly.extension.undertow.security.jaspi.modules.HTTPSchemeServerAuthModule, flag=required)

* [Enable SSL in WildFly][2]
* The mapping for the application to the security domain is in `jboss-web.xml`

[1]: http://site.trajano.net/jaspic-tester/test-server-auth-module/
[2]: http://www.trajano.net/2015/08/set-up-ssl-with-wildfly/
[3]: https://github.com/javaee-samples/javaee7-samples/issues/243#issuecomment-127684544
