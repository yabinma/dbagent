package presto

import "strings"

// parseAuthConfig extracts `http-server.authentication.type` and
// `http-server.https.enabled` from a coordinator config.properties blob
// (design.md Section 8.4 step 4). Defaults match Presto's own defaults:
// authentication NONE, HTTPS disabled, when the keys are absent.
func parseAuthConfig(configText string) (scheme string, https bool) {
	scheme = "NONE"
	for _, line := range strings.Split(configText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexAny(line, "=:")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		switch key {
		case "http-server.authentication.type":
			if val != "" {
				scheme = strings.ToUpper(val)
			}
		case "http-server.https.enabled":
			https = strings.EqualFold(val, "true")
		}
	}
	return scheme, https
}

// resolveCA implements design.md Section 8.4's "TLS notes" CA resolution
// order: deployment parameter first, then `ca.crt` in the credentials
// Secret.
func resolveCA(deploymentCA []byte, credentialCA []byte, haveCredentialCA bool) []byte {
	if len(deploymentCA) > 0 {
		return deploymentCA
	}
	if haveCredentialCA {
		return credentialCA
	}
	return nil
}
