# About
This API Gateway returns a token when you send a POST request to /api/auth with a JSON format like below:

**Authentication**

POST /api/auth

```json
{ "email": "youremail",
  "password": "yourpassword"}
```

Then you will get a reply with JSON Web Token in "access_token" field. Use this in your Authorization header (with "Bearer ").

Of course the hashes stored in your DB must be in BCrypt in order for this to work. The important thing is in the database that you should have is "users" table with "email" and "encrypted_password" columns.

**Registration**

POST /api/auth/register

```
{"email":"email@domain.com",
 "password: "thepassword"}
```

Those using Ruby On Rails with Devise, using APIVault should work with your current database out of the box (users schema is the same) as long your still use Bcrypt (not Argon2)

Generic configurable setup for customised configuration other than Ruby On Rails/Devise with different users table/schema is still in WIP.

Detailed information [HERE](http://unrealasia.net/index.html#2019-03-22-12)

In a nutshell:

![summary](https://raw.githubusercontent.com/muhammadn/APIVault/master/API_gateway.png)

## Installation steps
1. Clone this repository
2. Edit database.yml, include your database credentials, edit secrets.yml (if you have rails you can run `rake secret` to generate one) - this is needed for JWT Token.
   then edit servers.yml which contains your *hostname* which is used to run APIVault, and the real backend server http://url_backendapi (need http:// or https://) in url_endpoint and your microservice's JWT secrets.

   NOTE: You can use either *mysql*, *postgres* and *mssql* adapters, depending how your current data is stored. sqlite is not supported at the moment but you can modify the source to support it.
3. go build
4. upload APIVault binary to your server and if you want to change the port that binds APIVault runs you can simply run `export PORT="your-port-number"`, example `export PORT="8080"`
5. copy config config/ folder in the same directory as APIVault binary in your server and _run APIVault as a normal user privileges (not root!)_
