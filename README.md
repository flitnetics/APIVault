# About
I had a problem at authentication different API endpoints from different services. Looked at [express-gateway](https://www.express-gateway.io/) but i was disappointed that data access is only available on Redis. I wanted to be able to authenticate users from MySQL (or PostgreSQL) so i decided to build one.

This API Gateway returns a token when you send a POST request to /api/auth with a JSON format like below:

```json
{ "email": "youremail",
  "password": "yourpassword"}
```

Then you will get a reply with JSON Web Token in "access_token" field. Use this in your Authorization header (without "Bearer ").

Of course the hashes stored in your DB must be in BCrypt in order for this to work. The important thing is in the database that you should have is "users" table with "email" and "encrypted_password" columns.

There is no user registration endpoint yet, but since everything is redirected, you can register at your normal registration endpoint.

Those using Ruby On Rails with Devise, using APIVault should work with your current database out of the box (users schema is the same) as long your still use Bcrypt (not Argon2)

I am still testing this out on my own to see how if it can solve my problem.

Part of this code is based on Reverse Proxy Demo at: https://github.com/bechurch/reverse-proxy-demo by https://github.com/bechurch
