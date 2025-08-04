package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type SpiffeAuthenticator struct {
	SpiffeIDs []string `yaml:"spiffe_ids"`
	Audiences []string `yaml:"audiences"`
	Endpoint  string   `yaml:"endpoint"`
	jwtSource *workloadapi.JWTSource
}

func (s *SpiffeAuthenticator) Type() string {
	return "spiffe"
}

func (s *SpiffeAuthenticator) Init(ctx context.Context, config map[string]interface{}) error {
	spiffeIDsRaw, ok := config["spiffe_ids"].([]interface{})
	if !ok || len(spiffeIDsRaw) == 0 {
		return fmt.Errorf("spiffe_ids is required")
	}
	for _, id := range spiffeIDsRaw {
		spiffeID, ok := id.(string)
		if !ok {
			return fmt.Errorf("spiffe_ids must contain only strings")
		}
		s.SpiffeIDs = append(s.SpiffeIDs, spiffeID)
	}

	endpoint, ok := config["endpoint"].(string)
	if !ok {
		return fmt.Errorf("endpoint is required")
	}
	s.Endpoint = endpoint

	audiencesRaw, ok := config["audiences"].([]interface{})
	if !ok || len(audiencesRaw) == 0 {
		return fmt.Errorf("audiences is required")
	}
	for _, a := range audiencesRaw {
		audience, ok := a.(string)
		if !ok {
			return fmt.Errorf("audiences must contain only strings")
		}
		s.Audiences = append(s.Audiences, audience)
	}

	clientOptions := workloadapi.WithClientOptions(workloadapi.WithAddr(s.Endpoint))
	jwtSource, err := workloadapi.NewJWTSource(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("failed to initialise JWT source: %w", err)
	}

	s.jwtSource = jwtSource

	return nil
}

func (s *SpiffeAuthenticator) Authenticate(ctx context.Context, credentials interface{}) (*AuthenticationResult, error) {
	token, err := s.extractToken(credentials)
	if err != nil {
		return nil, err
	}

	svid, err := jwtsvid.ParseAndValidate(token, s.jwtSource, s.Audiences)
	if err != nil {
		return &AuthenticationResult{
			Authenticated: false,
		}, fmt.Errorf("invalid token: %w", err)
	}

	return s.validateSVID(svid)
}

func (s *SpiffeAuthenticator) extractToken(credentials interface{}) (string, error) {
	token, ok := credentials.(string)
	if !ok {
		return "", fmt.Errorf("credentials must be a string token")
	}

	const prefix = "Bearer "
	return strings.TrimPrefix(token, prefix), nil
}

func (s *SpiffeAuthenticator) validateSVID(svid *jwtsvid.SVID) (*AuthenticationResult, error) {
	for _, allowedID := range s.SpiffeIDs {
		if svid.ID.String() == allowedID {
			claims := make(map[string]interface{})
			for k, v := range svid.Claims {
				claims[k] = v
			}

			return &AuthenticationResult{
				Authenticated: true,
				Subject:       svid.ID.String(),
				Claims:        claims,
				Expiration:    svid.Expiry,
			}, nil
		}
	}

	return &AuthenticationResult{
		Authenticated: false,
	}, fmt.Errorf("invalid SPIFFE ID: %s not in allowed list %v", svid.ID.String(), s.SpiffeIDs)
}

func (s *SpiffeAuthenticator) Close() error {
	if s.jwtSource != nil {
		return s.jwtSource.Close()
	}
	return nil
}
