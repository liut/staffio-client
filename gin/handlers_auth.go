package admin

import (
	// "context"
	// "log"
	"net/http"

	"github.com/gin-gonic/gin"
	staffio "github.com/liut/staffio-client"
)

const (
	sKeyUser = "user"
	KeyOper  = "oper"
)

// User ...
type User = staffio.User

// vars
var (
	LoginHandler = gin.WrapF(staffio.LoginHandler)
	SetLoginPath = staffio.SetLoginPath
	SetAdminPath = staffio.SetAdminPath
)

// AuthMiddleware ... Dreprecated by Middleware()
func AuthMiddleware(redirect bool) gin.HandlerFunc {
	if redirect {
		return Middleware(staffio.WithURI(staffio.LoginPath), staffio.WithRefresh())
	}
	return Middleware(staffio.WithRefresh())
}

// Middleware ...
func Middleware(opts ...staffio.OptFunc) gin.HandlerFunc {
	mw := staffio.Middleware(opts...)
	return func(c *gin.Context) {
		mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// c.Request = r
			c.Next()
		})).ServeHTTP(c.Writer, c.Request)
	}
}

// UserFromContext ...
func UserFromContext(c *gin.Context) (user *User, ok bool) {
	return staffio.UserFromContext(c.Request.Context())
}

// AuthCodeCallback Handler for Check auth with role[s] when auth-code callback
func AuthCodeCallback(roleName ...string) gin.HandlerFunc {
	return gin.WrapH(staffio.AuthCodeCallback(roleName...))
}

// HandlerShowMe ...
func HandlerShowMe(c *gin.Context) {
	user, ok := UserFromContext(c)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	token, _ := user.Encode()
	c.JSON(http.StatusOK, gin.H{
		"me":    user,
		"token": token,
	})
}
