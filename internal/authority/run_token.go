package authority

import (
	"context"
	"fmt"
	"net/http"
)

const RunTokenHeader = "X-Run-Token"

// ReadRunToken parses only the header envelope. Tether admission verifies the
// signature, current session binding and expiry; parsing confers no trust.
func ReadRunToken(h http.Header) (string, error) {
	values := h.Values(RunTokenHeader)
	if len(values) == 0 {
		return "", nil
	}
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > 4096 {
		return "", fmt.Errorf("invalid run token")
	}
	for _, c := range values[0] {
		if c <= 0x20 || c >= 0x7f || c == ',' {
			return "", fmt.Errorf("invalid run token")
		}
	}
	return values[0], nil
}

type verifiedRunTokenKey struct{}

// WithVerifiedRunToken is called only after fresh Tether admission of this exact
// token and bearer. The value stays out of attribution, metadata and telemetry.
func WithVerifiedRunToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, verifiedRunTokenKey{}, token)
}
func VerifiedRunToken(ctx context.Context) string {
	token, _ := ctx.Value(verifiedRunTokenKey{}).(string)
	return token
}
