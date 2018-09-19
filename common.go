package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

var (
	ErrJWTMustContainHeaderPayloadAndSignature = errors.New("jwt: JWT must contain header, playload and Signature")
	ErrJWTMustBeBase64Enconded                 = errors.New("jwt: JWT must be base64 encoded")
	ErrExpectedHeaderNotFound                  = errors.New("jwt: expected header not found")
	ErrJWTPayloadMustBeJSONObject              = errors.New("jwt: JWT payload must be JSON object")
)

func parseJwtHdrPld(jwt, expectedHeader string) (hdrPld64 string, claims *map[string]interface{}, err error) {
	const (
		mtd         = pkg + " parseFormat"
		p1          = mtd + " jwt"
		p1Header    = p1 + " Header"
		p1Payload   = p1 + " Payload"
		p1Signature = p1 + " Signature"
	)

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return "", nil, ErrJWTMustContainHeaderPayloadAndSignature
	}
	hdr64 := parts[0]
	hdr, err := base64.RawURLEncoding.DecodeString(hdr64)
	if err != nil {
		return "", nil, ErrJWTMustBeBase64Enconded
	}

	if string(hdr) != expectedHeader {
		return "", nil, ErrExpectedHeaderNotFound
	}

	pld64 := parts[1]
	pld, err := base64.RawURLEncoding.DecodeString(pld64)
	if err != nil {
		return "", nil, ErrExpectedHeaderNotFound
	}

	claims = &map[string]interface{}{}
	err = json.Unmarshal(pld, claims)
	if err != nil {
		return "", nil, ErrJWTPayloadMustBeJSONObject
	}

	hdrPld64 = hdr64 + "." + pld64

	return hdrPld64, claims, nil
}
