package jwt

import (
	"github.com/gin-gonic/gin/binding"
	"github.com/gin-gonic/gin"
	"time"
	"net/http"
	"gopkg.in/dgrijalva/jwt-go.v3"
)

// Login form structure.
type FirstStepLogin struct {
	PhoneNumber string `form:"phoneNumber" json:"phoneNumber" binding:"required"`
}

type FirstStepJWTMiddleware struct {
	GinJWTMiddleware
	Registrator func(phone string, c *gin.Context) (string, string, bool)
}

func (mw *FirstStepJWTMiddleware) LoginHandler(c *gin.Context) {
	// Initial middleware default setting.
	if err := mw.MiddlewareInit(); err != nil {
		mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(err, c))
		return
	}

	var loginVals FirstStepLogin

	if c.ShouldBindWith(&loginVals, binding.JSON) != nil {
		mw.unauthorized(c, http.StatusBadRequest, mw.HTTPStatusMessageFunc(ErrMissingLoginValues, c))
		return
	}

	id, phone, ok := mw.Registrator(loginVals.PhoneNumber, c)

	if !ok {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrFailedAuthentication, c))
		return
	}

	// Create the token
	token := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	claims := token.Claims.(jwt.MapClaims)

	if mw.PayloadFunc != nil {
		for key, value := range mw.PayloadFunc(loginVals.PhoneNumber) {
			claims[key] = value
		}
	}

	if phone == "" {
		phone = loginVals.PhoneNumber
	}

	expire := mw.TimeFunc().Add(mw.Timeout)
	claims["id"] = id
	claims["phone"] = phone
	claims["exp"] = expire.Unix()
	claims["orig_iat"] = mw.TimeFunc().Unix()
	tokenString, err := mw.signedString(token)

	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrFailedTokenCreation, c))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":   http.StatusOK,
		"token":  tokenString,
		"expire": expire.Format(time.RFC3339),
	})
}
