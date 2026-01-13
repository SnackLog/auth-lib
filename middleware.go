package authlib

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	serviceconfig "github.com/SnackLog/service-config-lib"
	"github.com/gin-gonic/gin"
)

type authServiceResponse struct {
	Username string `json:"username"`
}

func Authentication(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	requestUrl := fmt.Sprintf("%s/%s", serviceconfig.GetConfig().ApiRootUrl, "auth/session")
	request, err := http.NewRequest("GET", requestUrl, nil)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	request.Header.Set("Authorization", authHeader)
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil || response.StatusCode != http.StatusOK {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read response body"})
		return
	}

	var authResp authServiceResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse response"})
		return
	}

	c.Set("username", authResp.Username)

	c.Next()
}
