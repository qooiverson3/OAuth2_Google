package main

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type GoogleOAuthConfig struct {
	OAuth2Config *oauth2.Config
}

// UserInfo 使用者資訊
type UserInfo struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Picture string `json:"picture"`
	Hd      string `json:"hd"`
}

func main() {
	r := gin.Default()
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowMethods = []string{"GET", "POST", "PUT"}
	corsConfig.AllowHeaders = []string{"Authorization", "Origin"}
	corsConfig.AllowCredentials = true
	corsConfig.AllowOrigins = []string{"http://127.0.0.1:3000", "http://localhost:3000"}

	// Store session
	store := cookie.NewStore([]byte("secret"))

	r.Use(cors.New(corsConfig), sessions.Sessions("theMix-session", store))

	config := &GoogleOAuthConfig{
		OAuth2Config: &oauth2.Config{
			ClientID:     "1041776308737-2gcg55niljq4ti1tm3p5kh2mvsod7n26.apps.googleusercontent.com",
			ClientSecret: "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",
			RedirectURL:  "http://localhost:9096/token",
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
			Endpoint: google.Endpoint,
		},
	}

	r.GET("/oauth", config.UserConfirmation)
	r.GET("/token", config.GetToken)
	r.GET("/user", GetUser)
	r.Run(":9096")
}

// GetToken _
func (c *GoogleOAuthConfig) GetToken(r *gin.Context) {
	if r.Query("state") != "lab" {
		r.AbortWithError(http.StatusUnauthorized, errors.New("不合法的使用!"))
		return
	}

	code := r.Query("code")
	token, err := c.OAuth2Config.Exchange(oauth2.NoContext, code)
	if err != nil {
		r.AbortWithError(http.StatusUnauthorized, errors.New("不合法的 OAuth2 登入!"))
		return
	}

	client := c.OAuth2Config.Client(oauth2.NoContext, token)
	response, _ := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	data, _ := ioutil.ReadAll(response.Body)

	var userInfo UserInfo
	json.Unmarshal(data, &userInfo)

	// session
	session := sessions.Default(r)
	session.Set("name", userInfo.Name)
	session.Set("email", userInfo.Email)
	session.Set("picture", userInfo.Picture)
	session.Options(sessions.Options{
		MaxAge: 3600 * 8,
	})
	session.Save()

	r.Redirect(http.StatusSeeOther, "http://localhost:3000/")
	// r.JSON(http.StatusOK, userInfo)
}

// UserConfirmation _
func (c *GoogleOAuthConfig) UserConfirmation(r *gin.Context) {
	redirect := c.OAuth2Config.AuthCodeURL("lab")
	r.Redirect(http.StatusSeeOther, redirect)
}

// GetUser 取得 Session 資訊
func GetUser(r *gin.Context) {
	// cookie := r.Request.Cookies()
	session := sessions.Default(r)
	r.JSON(http.StatusOK, gin.H{
		// "cookie":  cookie[0].Value,
		"name":    session.Get("name"),
		"email":   session.Get("email"),
		"picture": session.Get("picture"),
	})
}
