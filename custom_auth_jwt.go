package jwt

import (
	"github.com/gin-gonic/gin/binding"
	"github.com/gin-gonic/gin"
	"time"
	"net/http"
	"gopkg.in/dgrijalva/jwt-go.v3"
	"errors"
	"regexp"
)

type FirstStepLogin struct {
	PhoneNumber string `json:"phoneNumber" binding:"required"`
	DeviceID    string `json:"deviceID" binding:"required"`
}

type FirstStepLoginResponse struct {
	Success bool `json:"success"`
	Data struct {
		Token   string `json:"token"`
		Expired string `json:"expired"`
	} `json:"data"`
	Error string `json:"error"`
}

func normalizeNumber(phone string) string {
	trimPhone := ""
	re := regexp.MustCompile("[0-9]+")
	submatchall := re.FindAllString(phone, -1)
	for _, element := range submatchall {
		trimPhone += element
	}
	return trimPhone
}

type FirstStepJWTMiddleware struct {
	GinJWTMiddleware
	Registrator func(phone, deviceID string, c *gin.Context) (string, bool)
}

func (mw *FirstStepJWTMiddleware) LoginHandler(c *gin.Context) {
	// Initial middleware default setting.
	if err := mw.MiddlewareInit(); err != nil {
		mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(err, c))
		return
	}

	var loginVals FirstStepLogin

	if c.ShouldBindWith(&loginVals, binding.JSON) != nil {
		mw.unauthorized(c, http.StatusBadRequest, mw.HTTPStatusMessageFunc(errors.New("missing phoneNumber or deviceID"), c))
		return
	}

	loginVals.PhoneNumber = normalizeNumber(loginVals.PhoneNumber)

	id, ok := mw.Registrator(loginVals.PhoneNumber, loginVals.DeviceID, c)

	if !ok {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(errors.New("failed to get or create user"), c))
		return
	}

	// Create the token
	token := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	claims := token.Claims.(jwt.MapClaims)

	if mw.PayloadFunc != nil {
		for key, value := range mw.PayloadFunc("") {
			claims[key] = value
		}
	}

	expire := mw.TimeFunc().Add(mw.Timeout)
	claims["id"] = id
	claims["phone"] = loginVals.PhoneNumber
	claims["deviceID"] = loginVals.DeviceID
	claims["exp"] = expire.Unix()
	claims["orig_iat"] = mw.TimeFunc().Unix()
	tokenString, err := mw.signedString(token)

	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrFailedTokenCreation, c))
		return
	}

	response := FirstStepLoginResponse{}
	response.Success = true
	response.Data.Token = "Bearer " + tokenString
	response.Data.Expired = expire.UTC().Format(time.RFC3339)

	c.JSON(http.StatusOK, response)
}

type SecondStepLogin struct {
	Otp string `json:"otp" binding:"required"`
}

type SecondStepLoginResponse struct {
	Success bool `json:"success"`
	Data struct {
		Token   string `json:"token"`
		Expired string `json:"expired"`
	} `json:"data"`
	Error string `json:"error"`
}

type SecondStepJWTMiddleware struct {
	GinJWTMiddleware
	OtpValidator func(otp string, c *gin.Context) (string, bool)
}

func (mw *SecondStepJWTMiddleware) LoginHandler(c *gin.Context) {
	// Initial middleware default setting.
	if err := mw.MiddlewareInit(); err != nil {
		mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(err, c))
		return
	}

	var loginVals SecondStepLogin

	if c.ShouldBindWith(&loginVals, binding.JSON) != nil {
		mw.unauthorized(c, http.StatusBadRequest, mw.HTTPStatusMessageFunc(errors.New("missing otp"), c))
		return
	}

	msg, ok := mw.OtpValidator(loginVals.Otp, c)

	if !ok {
		mw.unauthorized(c, http.StatusForbidden, mw.HTTPStatusMessageFunc(errors.New(msg), c))
		return
	}

	// Create the token
	token := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	claims := token.Claims.(jwt.MapClaims)

	if mw.PayloadFunc != nil {
		for key, value := range mw.PayloadFunc("") {
			claims[key] = value
		}
	}

	payload := ExtractClaims(c)

	expire := mw.TimeFunc().Add(mw.Timeout)
	claims["id"] = payload["id"]
	claims["phone"] = payload["phone"]
	claims["deviceID"] = payload["deviceID"]
	claims["exp"] = expire.Unix()
	claims["orig_iat"] = mw.TimeFunc().Unix()
	tokenString, err := mw.signedString(token)

	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrFailedTokenCreation, c))
		return
	}

	response := SecondStepLoginResponse{}
	response.Success = true
	response.Data.Token = "Bearer " + tokenString
	response.Data.Expired = expire.UTC().Format(time.RFC3339)

	c.JSON(http.StatusOK, response)
}

func (mw *SecondStepJWTMiddleware) RefreshHandler(c *gin.Context) {
	token, err := mw.parseToken(c)
	if err != nil && err.(*jwt.ValidationError).Errors != jwt.ValidationErrorExpired {
		mw.unauthorized(c, http.StatusBadRequest, mw.HTTPStatusMessageFunc(ErrInvalidAuthHeader, c))
		return
	}
	claims := token.Claims.(jwt.MapClaims)

	origIat := int64(claims["orig_iat"].(float64))

	if origIat < mw.TimeFunc().Add(-mw.MaxRefresh).Unix() {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrExpiredToken, c))
		return
	}

	// Create the token
	newToken := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	newClaims := newToken.Claims.(jwt.MapClaims)

	for key := range claims {
		newClaims[key] = claims[key]
	}

	expire := mw.TimeFunc().Add(mw.Timeout)
	newClaims["id"] = claims["id"]
	newClaims["exp"] = expire.Unix()
	newClaims["orig_iat"] = origIat
	tokenString, err := mw.signedString(newToken)

	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrFailedTokenCreation, c))
		return
	}

	response := SecondStepLoginResponse{}
	response.Success = true
	response.Data.Token = "Bearer " + tokenString
	response.Data.Expired = expire.UTC().Format(time.RFC3339)

	c.JSON(http.StatusOK, response)
}
