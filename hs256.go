package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

const (
	pkg         = "github.com/riotemergence/jwt"
	headerHs256 = `{"alg":"HS256","typ":"JWT"}`
)

var (
	ErrJWTMustBeNotEmpty      = errors.New("jwt: JWT must be not empty")
	ErrClaimsMustBeNotEmpty   = errors.New("jwt: claims must be not empty")
	ErrSecretMustBeNotEmpty   = errors.New("jwt: secret must be not empty")
	ErrErrorMarshallingClaims = errors.New("jwt: an error occurred during marshalling of claims")
	ErrErrorSigningJWT        = errors.New("jwt: an error occurred during signing the JWT")
	ErrJWTSignaturesNotMatch  = errors.New("jwt: an error occurred during signing the JWT")
)

func signHs256(hdrPld64 string, secret []byte) (string, error) {
	mac := hmac.New(sha256.New, secret)
	if _, err := mac.Write([]byte(hdrPld64)); err != nil {
		return "", err
	}
	sMac := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sMac), nil
}

func CreateHS256(claims interface{}, secret []byte) (string, error) {
	if claims == nil {
		return "", ErrClaimsMustBeNotEmpty
	}

	if secret == nil {
		return "", ErrSecretMustBeNotEmpty
	}

	pld, err := json.Marshal(claims)
	if err != nil {
		return "", ErrErrorMarshallingClaims
	}

	hdr64 := base64.RawURLEncoding.EncodeToString([]byte(headerHs256))
	pld64 := base64.RawURLEncoding.EncodeToString(pld)

	hdrPld64 := hdr64 + "." + pld64

	s64, err := signHs256(hdrPld64, secret)
	if err != nil {
		return "", ErrErrorSigningJWT
	}

	return hdrPld64 + "." + s64, nil
}

func ValidateHS256(jwt string, secret []byte) (*map[string]interface{}, error) {
	if jwt == "" {
		return nil, ErrJWTMustBeNotEmpty
	}

	if secret == nil {
		return nil, ErrSecretMustBeNotEmpty
	}

	hdrPld64, claims, err := parseJwtHdrPld(jwt, headerHs256)
	if err != nil {
		return nil, err
	}

	parts := strings.Split(jwt, ".")
	jwtSign64 := parts[2]

	calcSign64, err := signHs256(hdrPld64, secret)
	if err != nil {
		return nil, ErrErrorSigningJWT
	}

	if jwtSign64 != calcSign64 {
		return nil, ErrJWTSignaturesNotMatch
	}

	return claims, nil
}
