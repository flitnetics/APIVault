package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"fmt"
	"time"
	"strings"
        "runtime"
	"golang.org/x/crypto/bcrypt"
        "github.com/dgrijalva/jwt-go"
	"APIVault/pkg/db"
	"APIVault/pkg/config"
        "goji.io"
        "goji.io/pat"
	"gopkg.in/yaml.v2"
        "os/signal"
	"syscall"

	// authenticity checks
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"

	"strconv"
)

/*
	Structs
*/

type requestPayloadStruct struct {
	Username string `json:"username"`
	Email string `json:"email"`
	Password string `json:"password"`
}

type User struct {
  Id int
  Email string
  Username string
  Password string `json:"password"`
}

func (User) TableName() string {
  return config.Config.Table.Name
}

type Token struct {
  AccessToken string `json:"access_token"`
}

type Register struct {
  Status string `json:"status"`
}

type Servers struct {
  Server []struct {
    Name             string   `yaml:"name"`
    SourceHost       string   `yaml:"source_host"`
    TargetURL        string   `yaml:"target_url"`
    Secret           string   `yaml:"secret"`
    Mappings         []Mappings  `yaml:"mapping"`
  }
}

type Mappings struct {
    TargetURL           string `yaml:"target_url"`
    SourceEndpoint      string `yaml:"source_endpoint"`
    DestinationEndpoint string `yaml:"destination_endpoint"`
    Protect             bool   `yaml:"protect",default:"false"`
}

/*
	Utilities
*/

// Get env var or default
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getSecret(secretKey string) []byte {
  var hmacSampleSecret = []byte(secretKey)
  return hmacSampleSecret
}

/*
	Getters
*/

// Get the port to listen on
func getListenAddress() string {
	port := getEnv("PORT", config.Config.Port)
	return ":" + port
}

/*
	Logging
*/

// Log the env variables required for a reverse proxy
func logSetup() {
	if config.Config.UnixSocket {
	        log.Printf("Server runs on UNIX socket /tmp/apivault.sock")
        } else {
                log.Printf("Server will run on: %s\n", getListenAddress())
	}
}

// Log the typeform payload and redirect url
func logRequestPayload(req *http.Request, proxyUrl string) {
        //log.Printf("request for host: %s, proxy_url: %s\n", req.Host, proxyUrl)
}

// API Authenticity Verification
// This check that the requesting client is authentic (iOS/Android) and not some 
// bad actor (doing things like like DoS)
func Authenticity(res http.ResponseWriter, req *http.Request) (bool, error) {
	digest := req.Header.Get("X-Authenticity")
        //sharedKey := config.Config.Verification.SharedKey
	sharedKey := config.Config.Verification.SharedKey
	//log.Println("SharedKey: ", sharedKey)
	timestamp := time.Now().Unix()
	timestampString  := strconv.Itoa(int(timestamp))
	// remove last 3 characters in the unix epoch timestamp so it has a range of acceptable time
	timestampTrimmed  := timestampString[:len(timestampString)-2] // remove 3 last characters
	//log.Println("timestamp: ", timestampTrimmed)

	msg := []byte(timestampTrimmed)

	sig, err := hex.DecodeString(digest)
	if err != nil {
		return false, err
	}

	mac := hmac.New(sha256.New, []byte(sharedKey))
	mac.Write(msg)

	return hmac.Equal(sig, mac.Sum(nil)), nil
}

/*
	Reverse Proxy Logic
*/

// Serve a reverse proxy for a given url
func serveReverseProxy(target string, sourcePath string, destinationPath string, tokenString string, res http.ResponseWriter, req *http.Request) {
	// parse the url
	url, _ := url.Parse(target)

	// remove the prefix of the frontend endpoint
	path := strings.ReplaceAll(req.URL.Path, sourcePath, "")

	// create the reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(url)

	// Update the headers to allow for SSL redirection
	req.URL.Host = url.Host
	req.URL.Scheme = url.Scheme
	req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
	req.Header.Set("Authorization", "Bearer " + tokenString)
	req.Host = url.Host
	req.URL.Path = path + destinationPath

	// Note that ServeHttp is non blocking and uses a go routine under the hood
	proxy.ServeHTTP(res, req)
}

// Get a json decoder for a given requests body
func requestBodyDecoder(request *http.Request) *json.Decoder {
	// Read body to buffer
	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		log.Printf("Error reading body: %v", err)
		panic(err)
	}

	// Because go lang is a pain in the ass if you read the body then any susequent calls
	// are unable to read the body again....
	request.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	return json.NewDecoder(ioutil.NopCloser(bytes.NewBuffer(body)))
}

// Parse the requests body
func parseRequestBody(request *http.Request) requestPayloadStruct {
	decoder := requestBodyDecoder(request)

	var requestPayload requestPayloadStruct
	err := decoder.Decode(&requestPayload)

	if err != nil {
		panic(err)
	}

	return requestPayload
}

// Given a request send it to the appropriate url
func handleRequestAndRedirect(res http.ResponseWriter, req *http.Request) {
        var servers Servers
        data, err := ioutil.ReadFile("microservices.yml")
        if err != nil {
                panic(err)
        }

        err = yaml.Unmarshal(data, &servers)
        if err != nil {
                panic(err)
        }

        incomingRequest := req.Host + req.URL.Path

        for index := 0; index < len(servers.Server); index++ {
                for _, path := range servers.Server[index].Mappings {
                        // if verification of client is enabled, we check whether it is from a good client and not bad actor
                        // for authenticity of the client
                        authenticity, err := Authenticity(res, req)
                        if err != nil {
                                panic(err)
                        }

                        targetRequest := servers.Server[index].SourceHost + path.SourceEndpoint

                        if strings.Contains(incomingRequest, targetRequest) {

 	                        if !authenticity &&
			           path.Protect == true {
                                        res.Header().Set("Content-Type", "application/json")
                                        res.WriteHeader(http.StatusUnauthorized)
	                                return
				}
			}
		}
	}

	tokenString := req.Header.Get("Authorization")
	if tokenString != "" {
	        splitToken := strings.Split(tokenString, "Bearer ")
	        token := splitToken[1]

		// verify the token that is going to be authenticated by APIVault
	        claim, verified := VerifyToken(token)

		// if APIVault verifies it, continue passing the request
	        if verified {

			//incomingRequest := req.Host + req.URL.Path
                        //log.Println("incomingRequest: ", incomingRequest)

                        for index := 0; index < len(servers.Server); index++ {
				//log.Println("Paths: ", servers.Server[index].Mappings)
			        for _, path := range servers.Server[index].Mappings {
                                        targetRequest := servers.Server[index].SourceHost + path.SourceEndpoint
                                        //log.Println("TargetRequest: ", targetRequest)
                                        //log.Println("incomingRequest: ", incomingRequest)

                                        if strings.Contains(incomingRequest, targetRequest) {

                                                url := path.TargetURL
						sourcePath := path.SourceEndpoint
						destinationPath := path.DestinationEndpoint

		                                //log.Println("Host: ", req.Host)
						//log.Println("URL: ", url)

                                                token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
                                                //"nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
                                                        "sub": claim,
                                                        "exp": time.Now().Add(time.Hour * 72).Unix(),
                                                })

                                                hmacSampleSecret := []byte(servers.Server[index].Secret)

                                                // Sign and get the complete encoded token as a string using the secret
                                                tokenString, err := token.SignedString(hmacSampleSecret)
                                                if err != nil {
                                                        panic(err)
                                                }

                                                logRequestPayload(req, url)
                                                serveReverseProxy(url, sourcePath, destinationPath, tokenString, res, req)
			               }
		               }
                       }
	                       //log.Println("%d", index)
               } else {
                       res.Header().Set("Content-Type", "application/json")
                       res.WriteHeader(http.StatusUnauthorized)
		       return
               }
	}
}

// Check Usernamd and Password and Authenticate
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func VerifyToken(tokenString string) (interface{}, bool) {

  // Parse takes the token string and a function for looking up the key. The latter is especially
  // useful if you use multiple keys for your application.  The standard is to use 'kid' in the
  // head of the token to identify which key to use, but the parsed token (head and claims) is provided
  // to the callback, providing flexibility.
  token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
      // Don't forget to validate the alg is what you expect:
      if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
          return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
      }

      // hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
      hmacSampleSecret := getSecret(config.Config.Jwt.Secret)
      return hmacSampleSecret, nil
  })

  if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
    return claims["sub"], true
  } else {
    fmt.Println(err)
    return claims["sub"], false
  }
}

func Registration(res http.ResponseWriter, req *http.Request) {
  var user User
  requestPayload := parseRequestBody(req)
  password := requestPayload.Password
  email := requestPayload.Email

  if db.DBCon.Where(config.Config.Table.Column.Login + " = ?", email).First(&user).RecordNotFound() {
    register := Register{}
    register.Status = "User already registered"

    authJson, err := json.Marshal(register)
    if err != nil {
      panic(err)
    }

    res.Header().Set("Content-Type", "application/json")
    res.WriteHeader(http.StatusOK)
    res.Write(authJson)
  } else {
    encryptedHash, err := bcrypt.GenerateFromPassword([]byte(password), int(11))
    if err != nil {
      panic(err)
    }

    user := User{Email: email, Password: string(encryptedHash), Username: email}
    db.DBCon.NewRecord(user)

    register := Register{}
    register.Status = "Registration successful"

    authJson, err := json.Marshal(register)
    if err != nil {
      panic(err)
    }

    res.Header().Set("Content-Type", "application/json")
    res.WriteHeader(http.StatusOK)
    res.Write(authJson)
  }

} 

// Authenticate
func Authenticate(res http.ResponseWriter, req *http.Request) {
  var user User
  requestPayload := parseRequestBody(req)

  password := requestPayload.Password
  email := requestPayload.Email

  db.DBCon.Where(config.Config.Table.Column.Login + " = ?", email).First(&user)

  match := CheckPasswordHash(password, user.Password)
  //log.Println("Authentication Verified: ", match)

  if match {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
      //"nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
      "sub": user.Id,
      "exp": time.Now().Add(time.Hour * time.Duration(config.Config.Jwt.Ttl)).Unix(),
    })

    hmacSampleSecret := getSecret(config.Config.Jwt.Secret)

    // Sign and get the complete encoded token as a string using the secret
    tokenString, err := token.SignedString(hmacSampleSecret)
    userToken := Token{}
    userToken.AccessToken = tokenString

    authJson, err := json.Marshal(userToken)
    if err != nil {
      panic(err)
    }

    // for debugging
    // log.Println(tokenString, err)
    res.Header().Set("Content-Type", "application/json")
    res.WriteHeader(http.StatusOK)
    res.Write(authJson)
  } else {
    res.Header().Set("Content-Type", "application/json")
    res.WriteHeader(http.StatusUnauthorized)
  }

  // for debugging
  //log.Printf("email: %s, password: %s", requestPayload.Email, requestPayload.Password)
}

/*
	Entry
*/

func main() {
	// Log setup values
	logSetup()
        runtime.GOMAXPROCS(runtime.NumCPU()) // Use all CPU Cores

        mux := goji.NewMux()
	// authentication routes
        mux.HandleFunc(pat.Post("/api/auth"), Authenticate)
        mux.HandleFunc(pat.Post("/api/auth/register"), Registration)

	// all others, proxy it over!
        mux.HandleFunc(pat.Get("/*"), handleRequestAndRedirect)
	mux.HandleFunc(pat.Post("/*"), handleRequestAndRedirect)
	mux.HandleFunc(pat.Options("/*"), handleRequestAndRedirect)
	mux.HandleFunc(pat.Head("/*"), handleRequestAndRedirect)
	mux.HandleFunc(pat.Put("/*"), handleRequestAndRedirect)
	mux.HandleFunc(pat.Delete("/*"), handleRequestAndRedirect)
	mux.HandleFunc(pat.Patch("/*"), handleRequestAndRedirect)
	// start server
	//http.HandleFunc("/*", handleRequestAndRedirect)

	if !config.Config.UnixSocket {
	        if err := http.ListenAndServe(getListenAddress(), mux); err != nil {
		        panic(err)
	        }
        } else {

	        unixListener, err := net.Listen("unix", "/tmp/apivault.sock")
	        if err != nil {
		        panic(err)
	        }

	        sigc := make(chan os.Signal, 1)
                signal.Notify(sigc, os.Interrupt, os.Kill, syscall.SIGTERM)
                go func(c chan os.Signal) {
                        // Wait for a SIGINT or SIGKILL:
                        sig := <-c
                        log.Printf("Caught signal %s: shutting down.", sig)
                        // Stop listening (and unlink the socket if unix type):
                        unixListener.Close()
                        // And we're done:
                        os.Exit(0)
                }(sigc)

	        http.Serve(unixListener, mux)
	}
}
