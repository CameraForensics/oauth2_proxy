package providers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/stretchr/testify/assert"
)

func testCameraForensicsProvider(hostname string) *CameraForensicsProvider {
	p := NewCameraForensicsProvider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			// ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""})
	if hostname != "" {
		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		// updateURL(p.Data().ProfileURL, hostname)
	}
	return p
}

func TestCameraForensicsProviderDefaults(t *testing.T) {
	p := testCameraForensicsProvider("")
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "CameraForensics", p.Data().ProviderName)
	assert.Equal(t, "https://www.cameraforensics.com/api/v1/oauth/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://www.cameraforensics.com/api/v1/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "profile", p.Data().Scope)
}

func TestCameraForensicsProviderOverrides(t *testing.T) {
	p := NewCameraForensicsProvider(
		&ProviderData{
			LoginURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/auth"},
			RedeemURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/token"},

				ValidateURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/tokeninfo"},
			Scope: "profile"})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "CameraForensics", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/oauth/auth",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://example.com/oauth/profile",
		p.Data().ProfileURL.String())
	assert.Equal(t, "https://example.com/oauth/tokeninfo",
		p.Data().ValidateURL.String())
	assert.Equal(t, "profile", p.Data().Scope)
}

func TestCameraForensicsProviderGetEmailAddress(t *testing.T) {
	b := testCameraForensicsBackend(`"user@cameraforensics.com"`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testCameraForensicsProvider(bURL.Host)

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "user@cameraforensics.com", email)
}

func TestCameraForensicsProviderGetEmailAddressFailedRequest(t *testing.T) {
	b := testCameraForensicsBackend("unused payload")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testCameraForensicsProvider(bURL.Host)

	// We'll trigger a request failure by using an unexpected access
	// token. Alternatively, we could allow the parsing of the payload as
	// JSON to fail.
	session := &sessions.SessionState{AccessToken: "unexpected_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}

func TestCameraForensicsProviderGetEmailAddressEmailNotPresentInPayload(t *testing.T) {
	b := testCameraForensicsBackend("{\"foo\": \"bar\"}")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testCameraForensicsProvider(bURL.Host)

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}
