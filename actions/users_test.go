package actions_test

import (
	"encoding/json"
	"go-with-jwt/actions"
	"net/http"
)

func (as *ActionSuite) Test_Users_Login() {

	// table driven tests
	var tests = []struct {
		email                   string
		password                string
		expectedStatusCode      int
		expectedOutputContained string
	}{
		{"fake-email@email.you", "fake-pwd", http.StatusOK, "token"},
		{"fake-email@email.you", "bad-pwd", http.StatusBadRequest, "Login failed"},
		{"unknown_user@email.unknown", "dev", http.StatusBadRequest, "Login failed"},
		{"", "dev", http.StatusBadRequest, "Invalid email"},
		{"one-more-fake-email@email.you", "one-more-fake-pwd", http.StatusOK, "token"},
		{"asdfas.net", "dev", http.StatusBadRequest, "Invalid email"},
		{"fakemail@.", "dev", http.StatusBadRequest, "Invalid email"},
	}

	for _, t := range tests {
		res := as.JSON("/v1/auth/login").Post(actions.LoginRequest{
			Email:    t.email,
			Password: t.password,
		})
		as.Equal(t.expectedStatusCode, res.Code)

		if len(t.expectedOutputContained) > 0 {
			as.Contains(res.Body.String(), t.expectedOutputContained)
		}
	}
}

func (as *ActionSuite) Test_Users_Me() {
	// table driven tests
	var tests = []struct {
		email              string
		password           string
		expectedStatusCode int
	}{
		{"fake-email@email.you", "fake-pwd", http.StatusOK},
		{"fake-email@email.you", "bad-pwd", http.StatusBadRequest},
		{"unknown_user@email.unknown", "dev", http.StatusBadRequest},
		{"", "dev", http.StatusBadRequest},
		{"one-more-fake-email@email.you", "one-more-fake-pwd", http.StatusOK},
		{"asdfas.net", "dev", http.StatusBadRequest},
		{"fakemail@.", "dev", http.StatusBadRequest},
	}

	for _, t := range tests {
		res := as.JSON("/v1/auth/login").Post(actions.LoginRequest{
			Email:    t.email,
			Password: t.password,
		})

		as.Equal(t.expectedStatusCode, res.Code)

		if t.expectedStatusCode == http.StatusBadRequest {
			return
		}

		var response map[string]string
		json.Unmarshal(res.Body.Bytes(), &response)

		as.True(len(response["token"]) > 0)

		req := as.JSON("/v1/users/me")
		req.Headers["Authorization"] = response["token"]
		res = req.Get()

		as.Equal(http.StatusOK, res.Code)

		body := res.Body.String()
		as.Contains(body, t.email)
		as.NotContains(body, t.password)
	}

}
