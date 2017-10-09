# GO with JWT

This is an example project to give you some hints in order to integrate jwt authentication with Buffalo.

There is a [blog post on Medium](https://medium.com/@francescodonzello/jwt-and-go-buffalo-4cce3ae73723) that explains part of the code you'll find here.


## Starting the Application

You can run the app with:

	$ JWT_KEY_PATH=/{project-path}/jwtRS256.key buffalo dev

Two routes are set:

	// Requires email and password. Response contains a JWT token
	$ POST http://127.0.0.1:3000/api/v1/auth/login

	// Requires JWT token set in Authorization header
	$ GET http://127.0.0.1:3000/api/v1/users/me 

## Testing the Application

You can run tests with:

	$ JWT_KEY_PATH=/{project-path}/jwtRS256.key buffalo test

## Contributing

PRs are very welcome to improve the project as it may be used by many developers to get started with a JWT base Buffalo app.
