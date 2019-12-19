Staffio client
===


Example
---

```go
package main

import (
	"fmt"
	"net/http"

	staffio "github.com/liut/staffio-client"
)

func main() {

	loginPath := "/auth/login"
	staffio.SetLoginPath(loginPath)
	staffio.SetAdminPath("/admin")

	http.HandleFunc(loginPath, staffio.LoginHandler)
	http.Handle("/auth/callback", staffio.AuthCodeCallback("admin"))

	authF1 := staffio.Middleware()
	authF1 := staffio.Middleware(staffio.WithRefresh()) // auto refresh token time
	authF1 := staffio.Middleware(staffio.WithRefresh(), staffio.WithURI(loginPath)) // auto refresh and redirect
	http.Handle("/admin", authF1(http.HandlerFunc(handlerAdminWelcome)))
	// more handlers
}

func handlerAdminWelcome(w http.ResponseWriter, r *http.Request) {
	user := staffio.UserFromContext(r.Context())
	fmt.Fprintf(w, "welcome %s", user.Name)
}


// Middleware for gin
func Middleware(opts ...staffio.OptFunc) gin.HandlerFunc {
	option := staffio.NewOption(opts...)
	return func(c *gin.Context) {
		user, err := staffio.UserFromRequest(c.Request)
		if err != nil {
			if option.URI != "" {
				c.Redirect(http.StatusFound, option.URI)
			} else {
				c.AbortWithStatus(http.StatusUnauthorized)
			}
			return
		}
		if option.Refresh && user.NeedRefresh() {
			user.Refresh()
			user.Signin(c.Writer)
		}
		req := c.Request
		c.Request = req.WithContext(staffio.ContextWithUser(req.Context(), user))
		c.Next()
	}
}

```
