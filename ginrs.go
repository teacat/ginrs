package ginrs

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

var (
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
)

var (
	ErrNoPrivateKey  = errors.New("ginrs: private key was not loaded")
	ErrNoPublicKey   = errors.New("ginrs: public key was not loaded")
	ErrInvalidToken  = errors.New("ginrs: invalid token")
	ErrInvalidMethod = errors.New("ginrs: invalid signing method")
)

const (
	// KeyToken
	KeyToken = "token"
)

// LoadKeys
func LoadKeys(publicKeyPath, privateKeyPath string) error {
	if err := LoadPublicKey(publicKeyPath); err != nil {
		return err
	}
	privateKeyByte, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return err
	}
	privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateKeyByte)
	if err != nil {
		return err
	}
	return nil
}

// LoadPublicKey
func LoadPublicKey(path string) error {
	publicKeyByte, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	publicKey, err = jwt.ParseRSAPublicKeyFromPEM(publicKeyByte)
	if err != nil {
		return err
	}
	return nil
}

// SignRS256 signs the custom claims with RS256 private key
func SignRS256(t jwt.Claims) (string, error) {
	if privateKey == nil {
		return "", ErrNoPrivateKey
	}
	return jwt.NewWithClaims(jwt.SigningMethodRS256, t).SignedString(privateKey)
}

// Parse parses the token into destination struct.
func Parse(t string, dest interface{}) error {
	if publicKey == nil {
		return ErrNoPublicKey
	}
	token, err := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, ErrInvalidMethod
		}
		return publicKey, nil
	})
	if err != nil {
		return err
	}
	if !token.Valid {
		return ErrInvalidToken
	}
	b, err := json.Marshal(token.Claims.(jwt.MapClaims))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dest)
}

// Middleware gets the JWT from the Authorization header and put it into the *gin.Context for the model to validate.
func Middleware(typ interface{}) func(*gin.Context) {
	return func(c *gin.Context) {
		str := strings.Split(c.Request.Header.Get("Authorization"), " ")
		if len(str) != 2 {
			c.Next()
			return
		}
		if err := Parse(str[1], &typ); err != nil {
			c.AbortWithError(http.StatusBadRequest, err)
			return
		}
		c.Set(KeyToken, typ)
		c.Next()
	}
}

// Get gets the Token from the *gin.Context, type cast is required.
func Get(c *gin.Context) interface{} {
	return c.MustGet(KeyToken)
}
