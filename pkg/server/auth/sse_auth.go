package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"go.uber.org/zap"
)

// authKey is a custom context key for storing the auth token.
type authKey struct{}

// withAuthKey adds an auth key to the context.
func withAuthKey(ctx context.Context, auth string) context.Context {
	return context.WithValue(ctx, authKey{}, auth)
}

// Authenticate checks if the request is authenticated based on the provided context.
func validateToken(ctx context.Context, logger *zap.Logger) (bool, error) {
	// no configured token means no authentication
	keyA := os.Getenv("SLACK_MCP_SSE_API_KEY")
	jwtSecret := os.Getenv("SLACK_MCP_JWT_SECRET")
	if keyA == "" {
		if jwtSecret == "" {
			logger.Debug("No SSE authentication configured, skipping")
			return true, nil
		}
	}

	keyB, ok := ctx.Value(authKey{}).(string)
	if !ok {
		logger.Warn("Missing auth token in context",
			zap.String("context", "http"),
		)
		return false, fmt.Errorf("missing auth")
	}

	logger.Debug("Validating auth token",
		zap.String("context", "http"),
		zap.Bool("has_bearer_prefix", strings.HasPrefix(keyB, "Bearer ")),
	)

	if strings.HasPrefix(keyB, "Bearer ") {
		keyB = strings.TrimPrefix(keyB, "Bearer ")
	}

	// Try JWT validation first if secret is configured
	if jwtSecret != "" {
		if err := validateJWTToken(keyB, jwtSecret); err == nil {
			logger.Debug("JWT token validated successfully",
				zap.String("context", "http"),
			)
			return true, nil
		}
		logger.Debug("JWT validation failed, trying simple token",
			zap.String("context", "http"),
		)
	}

	// Fallback to simple token validation
	if keyA != "" {
		if subtle.ConstantTimeCompare([]byte(keyA), []byte(keyB)) != 1 {
			logger.Warn("Invalid auth token provided",
				zap.String("context", "http"),
			)
			return false, fmt.Errorf("invalid auth token")
		}

		logger.Debug("Auth token validated successfully",
			zap.String("context", "http"),
		)
		return true, nil
	}

	return false, fmt.Errorf("no valid authentication method")
}

// AuthFromRequest extracts the auth token from the request headers.
func AuthFromRequest(logger *zap.Logger) func(context.Context, *http.Request) context.Context {
	return func(ctx context.Context, r *http.Request) context.Context {
		authHeader := r.Header.Get("Authorization")
		return withAuthKey(ctx, authHeader)
	}
}

// BuildMiddleware creates a middleware function that ensures authentication based on the provided transport type.
func BuildMiddleware(transport string, logger *zap.Logger) server.ToolHandlerMiddleware {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			logger.Debug("Auth middleware invoked",
				zap.String("context", "http"),
				zap.String("transport", transport),
				zap.String("tool", req.Params.Name),
			)

			if authenticated, err := IsAuthenticated(ctx, transport, logger); !authenticated {
				logger.Error("Authentication failed",
					zap.String("context", "http"),
					zap.String("transport", transport),
					zap.String("tool", req.Params.Name),
					zap.Error(err),
				)
				return nil, err
			}

			logger.Debug("Authentication successful",
				zap.String("context", "http"),
				zap.String("transport", transport),
				zap.String("tool", req.Params.Name),
			)

			return next(ctx, req)
		}
	}
}

// IsAuthenticated public api
func IsAuthenticated(ctx context.Context, transport string, logger *zap.Logger) (bool, error) {
	switch transport {
	case "stdio":
		return true, nil

	case "sse":
		authenticated, err := validateToken(ctx, logger)

		if err != nil {
			logger.Error("HTTP/SSE authentication error",
				zap.String("context", "http"),
				zap.Error(err),
			)
			return false, fmt.Errorf("authentication error: %w", err)
		}

		if !authenticated {
			logger.Warn("HTTP/SSE unauthorized request",
				zap.String("context", "http"),
			)
			return false, fmt.Errorf("unauthorized request")
		}

		return true, nil

	default:
		logger.Error("Unknown transport type",
			zap.String("context", "http"),
			zap.String("transport", transport),
		)
		return false, fmt.Errorf("unknown transport type: %s", transport)
	}
}

func validateJWTToken(token, secret string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid token format")
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("invalid header encoding")
	}

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("invalid header format")
	}

	if header.Alg != "HS256" {
		return fmt.Errorf("unsupported algorithm: %s", header.Alg)
	}

	// Verify signature
	message := parts[0] + "." + parts[1]
	expectedSignature := base64.RawURLEncoding.EncodeToString(hmacSHA256([]byte(message), []byte(secret)))
	if expectedSignature != parts[2] {
		return fmt.Errorf("invalid signature")
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("invalid payload encoding")
	}

	var payload struct {
		Exp int64  `json:"exp"`
		Aud string `json:"aud"`
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return fmt.Errorf("invalid payload format")
	}

	// Check expiration
	if payload.Exp > 0 && time.Now().Unix() > payload.Exp {
		return fmt.Errorf("token expired")
	}

	// Check audience if configured
	if expectedAud := os.Getenv("SLACK_MCP_JWT_AUDIENCE"); expectedAud != "" {
		if payload.Aud != expectedAud {
			return fmt.Errorf("invalid audience")
		}
	}

	// Check issuer if configured
	if expectedIss := os.Getenv("SLACK_MCP_JWT_ISSUER"); expectedIss != "" {
		if payload.Iss != expectedIss {
			return fmt.Errorf("invalid issuer")
		}
	}

	return nil
}

func hmacSHA256(data, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
