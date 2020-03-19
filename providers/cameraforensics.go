package providers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/dgrijalva/jwt-go"
)

// CameraForensicsProvider represents an CameraForensics based Identity Provider
type CameraForensicsProvider struct {
	*ProviderData
}

type Claims struct {
	Username string `json:"username"`
	Email string `json:"email"`
	jwt.StandardClaims
}

var jwtKey = []byte("my_secret_key")

// NewCameraForensicsProvider initiates a new CameraForensicsProvider
func NewCameraForensicsProvider(p *ProviderData) *CameraForensicsProvider {
	p.ProviderName = "CameraForensics"
	if p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{Scheme: "https",
			Host: "www.cameraforensics.com",
			Path: "/api/v1/oauth/authorize"}
	}
	if p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{Scheme: "https",
			Host: "www.cameraforensics.com",
			Path: "/api/v1/oauth/token"}
	}
	// if p.ProfileURL.String() == "" {
	// 	p.ProfileURL = &url.URL{Scheme: "https",
	// 		Host: "www.cameraforensics.com",
	// 		Path: "/v1/people/~/email-address"}
	// }
	// if p.ValidateURL.String() == "" {
	// 	p.ValidateURL = p.ProfileURL
	// }
	if p.Scope == "" {
		p.Scope = "profile"
	}
	return &CameraForensicsProvider{ProviderData: p}
}

func getCameraForensicsHeader(accessToken string) http.Header {
	header := make(http.Header)
	header.Set("Accept", "application/json")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	return header
}

// GetEmailAddress returns the Account email address
func (p *CameraForensicsProvider) GetEmailAddress(s *sessions.SessionState) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}

	claims := &Claims{}

	// TODO: Decode email address from the AccessToken which is JWT
	token, err := jwt.ParseWithClaims(s.AccessToken, claims, func(token *jwt.Token) (interface{}, error) {
    // Don't forget to validate the alg is what you expect:
    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
        return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

    // hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
    return jwtKey, nil
	})
	if err != nil {
		fmt.Println("Error returned from jwt.Parse:", err)
	}

	fmt.Println(claims)
	fmt.Println(token)
	return claims.Email, nil
}

// ValidateSessionState validates the AccessToken
func (p *CameraForensicsProvider) ValidateSessionState(s *sessions.SessionState) bool {
	return validateToken(p, s.AccessToken, getCameraForensicsHeader(s.AccessToken))
}
