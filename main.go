package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/alexflint/go-arg"
	"github.com/dgrijalva/jwt-go"
)

type User struct {
	Login           string `json:"login"`
	Email           string `json:"email"`
	Password        string `json:"password"`
	ExprirationTime int64  `json:"expire"`
}

func checkMethod(w http.ResponseWriter, req *http.Request, method string) bool {
	if method != req.Method {
		w.Header().Set("Allow", method)
		http.Error(w, "", http.StatusMethodNotAllowed)
		return false
	} else {
		return true
	}
}
func checkGet(w http.ResponseWriter, req *http.Request) bool {
	return checkMethod(w, req, http.MethodGet)
}

func checkPost(w http.ResponseWriter, req *http.Request) bool {
	return checkMethod(w, req, http.MethodPost)
}

type Login struct {
	Database []User
	JwtKey   string
}

type Err struct {
	Message string `json:"error"`
}

type Success struct {
	Success bool `json:"success"`
}

type Content struct {
	Content string `json:"content"`
}

func (l *Login) login(w http.ResponseWriter, req *http.Request) {
	user := User{}
	err := json.NewDecoder(req.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var authedUser User
	for _, dbUser := range l.Database {
		if user.Email == dbUser.Email {
			if user.Password == dbUser.Password {
				authedUser = user
				break
			} else {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(Err{Message: "Wrong password"})
				return
			}
		}
	}
	if authedUser.Email == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Err{Message: "Cannot find user"})
		return
	}

	if user.ExprirationTime == 0 {
		user.ExprirationTime = time.Now().Add(5 * time.Minute).Unix()
	}
	claims := jwt.StandardClaims{Subject: user.Email, ExpiresAt: user.ExprirationTime}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(l.JwtKey))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Err{Message: "Could not generate token"})
		return
	}
	cookie := &http.Cookie{Name: "houli_token", Value: tokenString, Path: "/", Expires: time.Unix(user.ExprirationTime, 0)}
	http.SetCookie(w, cookie)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Success{Success: true})
}

func (l Login) logout(w http.ResponseWriter, req *http.Request) {
	cookie := &http.Cookie{Name: "houli_token", Value: "", Path: "/"}
	http.SetCookie(w, cookie)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Success{Success: true})
}
func (l *Login) signup(w http.ResponseWriter, req *http.Request) {
	user := User{}
	err := json.NewDecoder(req.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	for _, dbUser := range l.Database {
		if user.Email == dbUser.Email {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(Err{Message: "User with this email exists"})
			return
		}
	}
	if user.ExprirationTime == 0 {
		user.ExprirationTime = time.Now().Add(5 * time.Minute).Unix()
	}
	l.Database = append(l.Database, user)

	// Add cookie so user will be authed right away
	claims := jwt.StandardClaims{Subject: user.Email, ExpiresAt: user.ExprirationTime}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(l.JwtKey))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Err{Message: fmt.Sprintf("Could not generate token: %s", err.Error())})
		return
	}
	cookie := &http.Cookie{Name: "houli_token", Value: tokenString, Path: "/", Expires: time.Unix(user.ExprirationTime, 0)}
	http.SetCookie(w, cookie)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Success{Success: true})
}

func (l *Login) test(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(l.Database)
}

func (l *Login) check(w http.ResponseWriter, req *http.Request) {
	cookie, err := req.Cookie("houli_token")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Err{Message: "Log in or sign up to get content"})
		return
	}
	token, err := jwt.ParseWithClaims(cookie.Value, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(l.JwtKey), nil
	})

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Err{Message: fmt.Sprintf("Invalid auth token: %s", err.Error())})
		cookie := &http.Cookie{Name: "houli_token", Value: "", Path: "/"}
		http.SetCookie(w, cookie)
		return
	}
	claims, ok := token.Claims.(*jwt.StandardClaims)

	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Err{Message: "Invalid auth token."})
		cookie := &http.Cookie{Name: "houli_token", Value: "", Path: "/"}
		http.SetCookie(w, cookie)
		return
	}

	var authedUser User
	for _, dbUser := range l.Database {
		if claims.Subject == dbUser.Email {
			authedUser = dbUser
		}
	}
	if authedUser.Email == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Err{Message: "Cannot find user"})
		cookie := &http.Cookie{Name: "houli_token", Value: "", Path: "/"}
		http.SetCookie(w, cookie)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Content{Content: fmt.Sprintf("Special content for %s: a houli newsline", authedUser.Login)})

}

func (l *Login) serve(w http.ResponseWriter, req *http.Request) {
	switch req.URL.Path {
	case "/login":
		if checkPost(w, req) {
			l.login(w, req)
		}
	case "/logout":
		if checkPost(w, req) {
			l.logout(w, req)
		}
	case "/signup":
		if checkPost(w, req) {
			l.signup(w, req)
		}
	case "/test":
		if checkGet(w, req) {
			l.test(w, req)
		}
	case "/":
		if checkGet(w, req) {
			l.check(w, req)
		}
	default:
		http.NotFound(w, req)
		return
	}
}

func main() {
	var args struct {
		SecretKey string `arg:"env,required" help:"server JWT secret key"`
	}
	arg.MustParse(&args)

	login := Login{
		Database: []User{},
		JwtKey:   args.SecretKey,
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		login.serve(w, r)
	})

	fmt.Println("Server running at localhost:8080")
	http.ListenAndServe(":8080", nil)
}
