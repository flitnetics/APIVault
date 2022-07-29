# About
This API Gateway returns a token when you send a POST request to /api/auth with a JSON format like below:

**Authentication**

> POST /api/auth

```json
{ 
  "email": "youremail",
  "password": "yourpassword"
}
```

Then you will get a reply with JSON Web Token in "access_token" field. Use this in your Authorization header (with "Bearer ").

Of course the hashes stored in your DB must be in BCrypt in order for this to work, although we will make the hash algorithm to be easily configurable in the near future. 

You can also configure any custom *user* table and a custom *column* name for your user login.

For example: some setups users "customers" table - you can customise that. Also *login* maybe stored in `username` column or `email` column

**Registration**

> POST /api/auth/register

```json
{
  "email": "email@domain.com",
  "password: "thepassword"
}
```

Detailed information [HERE](http://unrealasia.net/index.html#2019-03-22-12)

In a nutshell:

![summary](https://raw.githubusercontent.com/muhammadn/APIVault/master/API_gateway.png)

**Docker Image is WIP - We intend to release Kubernetes support as that makes sense**

## Installation steps
1. Clone this repository
2. Edit apivault.yml, include your database credentials, secrets.yml (if you have rails you can run `rake secret` to generate one) - this is needed for JWT Token.
3. Edit microservices.yml which contains your *hostname* which is used to run APIVault, and the real backend server http://url_backendapi (need http:// or https://) in url_endpoint and your microservice's JWT secrets. (NOTE: This is different than APIVault's)
4. go build
5. upload APIVault binary to your server and if you want to change the port that binds APIVault runs you can simply run `export PORT="your-port-number"`, example `export PORT="8080"`

## Configuration
There are two steps: You need to configure APIVault and Microservice-specific configuration

Copy `apivault.yml.example` as `apivault.yml` at the same directory as your APIVault binary

Sample configuration:

```
---
# if you want to use socket, set this to true
# socket will be /tmp/apivault.sock
unixsocket: false
db:
  adapter: mysql         # database adapter can be "mysql", "postgres" or "mssql"
  host: localhost        # your database host
  port: 3306             # change this to your database port, 5432 for postgresql and 1433 for mssql
  name: api-gateway      # your database name
  user: devel            # your database user
  password: yourpassword # your database password
# API Gateway JWT Secret (not microservice!)
jwt:
  secret: abc123
  ttl: 72
# Database user username/email and password column mapping
# set what is your table name, login column (example: "email" or "username")
table:
  name: users
  column:
    login: email
```

Microservice:
Copy `microservices.yml.example` to `microservices.yml` at the same directory as your APIVault binary.

```
---
# Microservice Specific!
# Example:
# I have a website, customer facing running as api.microservice1.domain1.com -
# Do include port number if necessary like: api.microservice1.domain1.com:8080
server:
  - name: first_microservice
    host: api.microservice1.domain1.com
    url_endpoint: https://backendprotectedapi.microservice1.domain.com
    secret: your-microservice-generated-secret-keep-this-secure!
  - name: second_microservice
    host: api.microservice2.domain.com
    url_endpoint: https://backendprotectedapi.microservice2.domain.com
    secret: your-microservice-generated-secret-keep-this-secure!
```
