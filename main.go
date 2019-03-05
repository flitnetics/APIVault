package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"fmt"
	"time"
	"strings"
	"golang.org/x/crypto/bcrypt"
        "github.com/dgrijalva/jwt-go"
	"./db"
        "github.com/julienschmidt/httprouter"
)

/*
	Structs
*/

type requestPayloadStruct struct {
	Email string `json:"email"`
	Password string `json:"password"`
}

type User struct {
  Email string
  EncryptedPassword string `gorm:"column:encrypted_password"`
  Password string `json:"password"`
}

type Token struct {
  AccessToken string `json:"access_token"`
}

const secretKey = "YOLOSWAG"
var hmacSampleSecret = []byte(secretKey)

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

/*
	Getters
*/

// Get the port to listen on
func getListenAddress() string {
	port := getEnv("PORT", "1338")
	return ":" + port
}

/*
	Logging
*/

// Log the env variables required for a reverse proxy
func logSetup() {
	log.Printf("Server will run on: %s\n", getListenAddress())
}

// Log the typeform payload and redirect url
func logRequestPayload(req *http.Request, proxyUrl string) {
        log.Printf("request for host: %s, proxy_url: %s\n", req.Host, proxyUrl)
}

/*
	Reverse Proxy Logic
*/

// Serve a reverse proxy for a given url
func serveReverseProxy(target string, res http.ResponseWriter, req *http.Request) {
	// parse the url
	url, _ := url.Parse(target)

	// create the reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(url)

	// Update the headers to allow for SSL redirection
	req.URL.Host = url.Host
	req.URL.Scheme = url.Scheme
	req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
	req.Host = url.Host

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
func handleRequestAndRedirect(res http.ResponseWriter, req *http.Request, _ httprouter.Params) {

	tokenString := req.Header.Get("Authorization")
	if tokenString != "" {
	  splitToken := strings.Split(tokenString, "Bearer ")
	  token := splitToken[1]

	  verified := VerifyToken(token)

	  if verified == true {
            var url = "localhost:9999"
            switch req.Host {
              case "localhost:1338":
                url = "https://whatshalal.com"
              case "localhost:1339":
                url = "http://localhost:3000"
              default:
                url = "localhost:9999"
            }

            logRequestPayload(req, url)

            serveReverseProxy(url, res, req)
	  } else {
            res.Header().Set("Content-Type", "application/json")
            res.WriteHeader(401)
          }
	}
}

// Check Usernamd and Password and Authenticate
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func VerifyToken(tokenString string) bool {

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
      return hmacSampleSecret, nil
  })

  if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
    fmt.Println(claims["nbf"])
    return true
  } else {
    fmt.Println(err)
    return false
  }
}

// Authenticate
func Authenticate(res http.ResponseWriter, req *http.Request, _ httprouter.Params) {
  var user User
  requestPayload := parseRequestBody(req)

  email := requestPayload.Email
  password := requestPayload.Password

  db.DBCon.First(&user, "email = ?", email)
  match := CheckPasswordHash(password, user.EncryptedPassword)
  log.Println("Authentication Verified: ", match)

  if match {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
      "nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
      "exp": time.Now().Add(time.Hour * 72).Unix(),
    })

    // Sign and get the complete encoded token as a string using the secret
    tokenString, err := token.SignedString(hmacSampleSecret)
    userToken := Token{}
    userToken.AccessToken = tokenString

    authJson, err := json.Marshal(userToken)
    if err != nil {
      panic(err)
    }

    // for debugging
    //log.Println(tokenString, err)
    res.Header().Set("Content-Type", "application/json")
    res.WriteHeader(http.StatusOK)
    res.Write(authJson)
  } else {
    res.Header().Set("Content-Type", "application/json")
    res.WriteHeader(401)
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

        router := httprouter.New()
        router.POST("/api/auth", Authenticate)
	router.GET("/*path", handleRequestAndRedirect)

	// start server
	// http.HandleFunc("/*", handleRequestAndRedirect)
	if err := http.ListenAndServe(getListenAddress(), router); err != nil {
		panic(err)
	}

}
