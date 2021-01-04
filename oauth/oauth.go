package oauth

import (
	"encoding/json"
	"fmt"
	"github.com/ferza17/bookstore_oauth_library-go/oauth/errors"
	"github.com/mercadolibre/golang-restclient/rest"
	"net/http"
	"strconv"
	"time"
)

const (
	headerXPublic    = "X-Public"
	headerXClientId  = "X-Client-Id"
	headerXCallerId  = "X-Caller-Id"
	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8080",
		Timeout: 200 * time.Millisecond,
	}
)

type AccessTokenStruct struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64 `json:"client_id"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request)  int64 {
	if request == nil {
		return 0
	}

	calledId, err := strconv.ParseInt(request.Header.Get(headerXCallerId),10,64)
	if err != nil {
		return 0
	}
	return calledId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId),10,64)
	if err != nil {
		return 0
	}
	return clientId
}

func AuthenticateRequest(request *http.Request) *errors.RestError {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenId := request.URL.Query().Get(paramAccessToken)

	// http://localhost:8081/api/v1/users/id?access_token=asdasd
	if accessTokenId == "" {
		return nil
	}

	at, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Status == http.StatusNotFound {
			return nil
		}
		return err
	}

	request.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))
	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))

	return nil
}

func cleanRequest(request *http.Request)  {
	if request == nil {
		return
	}

	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)

}

func getAccessToken(accessTokenId string)(*AccessTokenStruct, *errors.RestError)  {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenId))

	if response == nil || response.Response == nil{
		return nil, errors.NewInternalServerError("Invalid client response when trying to access token")
	}

	if response.StatusCode > 299 {
		var restErr errors.RestError
		if err := json.Unmarshal(response.Bytes(), &restErr); err != nil {
			return nil, errors.NewInternalServerError("Invalid error interface when trying to get access token")
		}
		return nil, &restErr
	}

	var at AccessTokenStruct
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, errors.NewInternalServerError("Error when trying to unmarshal user response")
	}

	return &at, nil
}
