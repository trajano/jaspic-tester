<%@ page session="false"%>
<html>
<body>
	<form method="post" action="j_security_check">
		<input type="hidden" name="state" value="${param['state']}" />
		<div>
			<label for="username">User name:</label> <input type="text"
				name="j_username" />
		</div>
		<div>
			<input type="submit" value="Login" />
		</div>
		<div>
			<a href=".">Back</a>
		</div>
	</form>
</body>
</html>