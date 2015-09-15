<%@ page session="false"%>
<h1>Welcome ${pageContext.request.userPrincipal.name}</h1>
<p>This is an secure page</p>
<p>
	Go to <a href=".">unsecure page</a>.
</p>
<p>
	<%
	java.net.URI postLogoutRedirectUri = java.net.URI.create(request.getRequestURL().toString()).resolve(request.getContextPath());
	%>
	Or <a href="j_logout?post_logout_redirect_uri=<%=postLogoutRedirectUri%>">login again</a>.
</p>