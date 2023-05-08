package main

import (
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/random"
	"net/http"
	"time"
)

var secret = []byte("secret-key-here")

func registerRoutes(e *echo.Echo) {
	e.POST("/api/login", Login)

	restricted := e.Group("/api")
	restricted.Use(echojwt.WithConfig(echojwt.Config{
		TokenLookup: "header:Authorization", // this is the default value, check docs for other options
		ContextKey:  "user",                 // this is the default value
		SigningKey:  secret,
	}))
	restricted.Use(validateToken)

	restricted.GET("/ping", func(c echo.Context) error {
		return c.String(http.StatusOK, "pong")
	})
}

func Login(c echo.Context) error {
	type login struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	var loginRequest login

	if err := c.Bind(&loginRequest); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "malformed request")
	}

	// TODO: validate login request

	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 4)),
			ID:        random.String(32), // TODO: use a UUID and store it in a DB
		},
	)
	signedToken, _ := token.SignedString(secret)

	c.JSON(http.StatusOK, echo.Map{
		"token": signedToken,
	})

	return nil

}

func validateToken(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {

		claims := c.Get("user").(*jwt.Token).Claims.(jwt.MapClaims)
		fmt.Printf("JWT received: %s", claims["jti"])

		// TODO: check if claims["jti"].(string) is in the DB

		return next(c)
	}
}
