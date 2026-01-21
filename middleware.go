package authlib

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	serviceconfig "github.com/SnackLog/service-config-lib"
	"github.com/gin-gonic/gin"
)

type authServiceResponse struct {
	Username string `json:"username"`
}

func bypassLogic(c *gin.Context) {
	log.Println("\033[1;31mWARNING: DEBUG_BYPASS_AUTH_MIDDLEWARE is enabled, bypassing authentication and setting user to 'foo'!\033[0m")
	c.Set("username", "foo")
	c.Next()
}

func Authentication(c *gin.Context) {
	if serviceconfig.GetConfig().DebugBypassAuthMiddleware {
		bypassLogic(c)
		return
	}
	authHeader := c.GetHeader("Authorization")
	requestUrl := fmt.Sprintf("%s/%s", serviceconfig.GetConfig().ApiRootUrl, "auth/session")
	request, err := http.NewRequest("GET", requestUrl, nil)
	if err != nil {
		log.Printf("Failed to contacft auth service at %s: %v", requestUrl, err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	request.Header.Set("Authorization", authHeader)
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil || response.StatusCode != http.StatusOK {
		log.Printf("Failed to validate session with auth service at %s: %v", requestUrl, err)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Printf("Failed to read response from auth service at %s: %v", requestUrl, err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read response body"})
		return
	}

	var authResp authServiceResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		log.Printf("Failed to parse response from auth service at %s: %v", requestUrl, err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse response"})
		return
	}

	c.Set("username", authResp.Username)

	c.Next()
}
