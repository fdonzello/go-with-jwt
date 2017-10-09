package actions

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/badoux/checkmail"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gobuffalo/buffalo"
	"github.com/gobuffalo/envy"
	"github.com/sirupsen/logrus"
)

// User represents a user :)
type User struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Password string `json:"-"` // don't serialize password field
}

// in-memory users
var users = []User{
	User{ID: "fceb-adse-dffa-ewop", Email: "fake-email@email.you", Password: encryptPassword("fake-pwd")},
	User{ID: "3adf-32ff-vx0d-pol2", Email: "one-more-fake-email@email.you", Password: encryptPassword("one-more-fake-pwd")},
}

// LoginRequest represents a login form.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// CustomClaims represents custom claims for jwt tokens
type CustomClaims struct {
	User User `json:"user"`
	jwt.StandardClaims
}

// UsersLogin perform a login with the given credentials.
func UsersLogin(c buffalo.Context) error {

	var req LoginRequest
	err := c.Bind(&req)

	if err != nil {
		return c.Error(http.StatusBadRequest, err)
	}

	pwd := req.Password
	if len(pwd) == 0 {
		return c.Error(http.StatusBadRequest, errors.New("Invalid password"))
	}

	email := req.Email
	if checkmail.ValidateFormat(email) != nil {
		return c.Error(http.StatusBadRequest, errors.New("Invalid email"))
	}

	u, err := getUser(email)

	if err != nil || bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(pwd)) != nil {
		return c.Error(http.StatusBadRequest, errors.New("Login failed"))
	}

	claims := CustomClaims{
		u,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(7 * 24 * time.Hour).Unix(), // token lifetime: 1 week
			Issuer:    fmt.Sprintf("%s.api.go-with-jwt.it", envy.Get("GO_ENV", "development")),
			Id:        u.ID,
		},
	}

	signingKey, err := ioutil.ReadFile(envy.Get("JWT_KEY_PATH", ""))

	if err != nil {
		return fmt.Errorf("could not open jwt key, %v", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(signingKey)

	if err != nil {
		return fmt.Errorf("could not sign token, %v", err)
	}

	return c.Render(200, r.JSON(map[string]string{"token": tokenString}))
}

// UsersMe default implementation.
func UsersMe(c buffalo.Context) error {
	return c.Render(200, r.JSON(c.Value("user")))
}

func getUser(email string) (User, error) {
	for _, user := range users {
		if user.Email == email {
			return user, nil
		}
	}

	return User{}, errors.New("User not found")
}

func getUserByID(id string) (User, error) {
	for _, user := range users {
		if user.ID == id {
			return user, nil
		}
	}

	return User{}, errors.New("User not found")
}

func oneWeek() time.Duration {
	return 7 * 24 * time.Hour
}

func encryptPassword(p string) string {
	pwd, err := bcrypt.GenerateFromPassword([]byte(strings.TrimSpace(p)), 8)

	if err != nil {
		panic("could not encrypt password")
	}

	return string(pwd)
}

// RestrictedHandlerMiddleware search and parse the jwt token in order to authenticate
// the request and populate the Context with the user containend in the claims.
func RestrictedHandlerMiddleware(next buffalo.Handler) buffalo.Handler {
	return func(c buffalo.Context) error {
		tokenString := c.Request().Header.Get("Authorization")

		if len(tokenString) == 0 {
			return c.Error(http.StatusUnauthorized, fmt.Errorf("No token set in headers"))
		}

		// parsing token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}

			// key
			mySignedKey, err := ioutil.ReadFile(envy.Get("JWT_KEY_PATH", ""))

			if err != nil {
				return nil, fmt.Errorf("could not open jwt key, %v", err)
			}

			return mySignedKey, nil
		})

		if err != nil {
			return c.Error(http.StatusUnauthorized, fmt.Errorf("Could not parse the token, %v", err))
		}

		// getting claims
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {

			logrus.Errorf("claims: %v", claims)

			// retrieving user from db
			u, err := getUserByID(claims["jti"].(string))

			if err != nil {
				return c.Error(http.StatusUnauthorized, fmt.Errorf("Could not identify the user"))
			}

			c.Set("user", u)

		} else {
			return c.Error(http.StatusUnauthorized, fmt.Errorf("Failed to validate token: %v", claims))
		}

		return next(c)
	}
}
