# Authentication Server

### This is a simple authentication server written in Golang.

![example workflow](https://github.com/th2empty/auth-server/actions/workflows/build.yml/badge.svg)


## Required Software

1. Golang v1.17
2. PostgreSQL


## Installation

### First you need to clone the repository and compile the executable

```shell
$ git clone https://github.com/th2empty/auth-server.git

$ cd auth-server

$ go build
```

### Next, you need to create a configuration file in the configs directory

```
/configs/config.yml
```

### Now you need to configure the server

```yaml
port: 9000

logging:
  format: "text" # if you set value 'json' format will be changed to JSON, else will be used default format
  logfile: false # if you want to put logs to log file set true; if you set 'false' logs will out in console

auth:
  issuer: "your name or nickname"
  audience: "the target audience"
  salt: "your_salt"
  signing_key: "your_signing_key"
  access_token_ttl: 30 # in minutes
  refresh_token_ttl: 720 # in hours

db:
  username: "database_username"
  host: "localhost"
  port: "5432"
  dbname: "database_name"
  sslmode: "disable"
```

### Create an .env file next to the executable and put data:

```dotenv
DB_PASSWORD=your_password
```

### Create a database and tables. 

The necessary tables can be created by executing SQL code from files in the schema folder. 
You can also design your own database, but for this you will have to make changes to the source code

#### If you did everything right, the server will start successfully

## Author

[th2empty](https://github.com/th2empty)

## License
This project is licensed under the MIT license. See the LICENSE file for more info.