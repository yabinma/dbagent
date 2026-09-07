package presto

import "testing"

func TestParseAuthConfig_DefaultsToNoneWhenAbsent(t *testing.T) {
	scheme, https := parseAuthConfig("coordinator=true\nnode.environment=production\n")
	if scheme != "NONE" || https {
		t.Fatalf("got scheme=%s https=%v", scheme, https)
	}
}

func TestParseAuthConfig_PasswordWithHTTPS(t *testing.T) {
	cfg := "coordinator=true\n" +
		"http-server.authentication.type=PASSWORD\n" +
		"http-server.https.enabled=true\n" +
		"http-server.https.port=8443\n"
	scheme, https := parseAuthConfig(cfg)
	if scheme != "PASSWORD" || !https {
		t.Fatalf("got scheme=%s https=%v", scheme, https)
	}
}

func TestParseAuthConfig_LDAP(t *testing.T) {
	scheme, _ := parseAuthConfig("http-server.authentication.type=LDAP\n")
	if scheme != "LDAP" {
		t.Fatalf("got scheme=%s", scheme)
	}
}

func TestParseAuthConfig_Kerberos(t *testing.T) {
	scheme, _ := parseAuthConfig("http-server.authentication.type=KERBEROS\n")
	if scheme != "KERBEROS" {
		t.Fatalf("got scheme=%s", scheme)
	}
}

func TestParseAuthConfig_CaseInsensitiveValue(t *testing.T) {
	scheme, _ := parseAuthConfig("http-server.authentication.type=password\n")
	if scheme != "PASSWORD" {
		t.Fatalf("got scheme=%s", scheme)
	}
}

func TestParseAuthConfig_IgnoresCommentsAndBlankLines(t *testing.T) {
	cfg := "# this is a comment\n\nhttp-server.authentication.type=NONE\n"
	scheme, _ := parseAuthConfig(cfg)
	if scheme != "NONE" {
		t.Fatalf("got scheme=%s", scheme)
	}
}

func TestResolveCA_DeploymentParamTakesPriority(t *testing.T) {
	ca := resolveCA([]byte("deployment-ca"), []byte("secret-ca"), true)
	if string(ca) != "deployment-ca" {
		t.Fatalf("got %s", ca)
	}
}

func TestResolveCA_FallsBackToCredentialSecret(t *testing.T) {
	ca := resolveCA(nil, []byte("secret-ca"), true)
	if string(ca) != "secret-ca" {
		t.Fatalf("got %s", ca)
	}
}

func TestResolveCA_NoneAvailable(t *testing.T) {
	ca := resolveCA(nil, nil, false)
	if ca != nil {
		t.Fatalf("expected nil, got %s", ca)
	}
}
