package presto

import (
	"crypto/x509"
	"encoding/json"
)

func marshalSchema(schema map[string]any) (string, error) {
	if schema == nil {
		return "", nil
	}
	raw, err := json.Marshal(schema)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func newCertPoolFromPEM(pemBytes []byte) *x509.CertPool {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil
	}
	return pool
}
