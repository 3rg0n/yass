package scanner

import (
	"strings"
	"testing"

	"github.com/3rg0n/yass/internal/config"
)

// Synthetic values only, built at runtime so no credential-shaped literal
// sits in the source. None of them is a real credential.
func rep(unit string, n int) string {
	var b strings.Builder
	for b.Len() < n {
		b.WriteString(unit)
	}
	return b.String()[:n]
}

func alnum(n int) string { return rep("Qz7kLm2pXw9R", n) }

func loadRules(t *testing.T) *Scanner {
	t.Helper()
	// An explicit path, so a user's own yass.json never changes the result.
	cfg, err := config.Load("../config/settings.json")
	if err != nil {
		t.Fatalf("load settings: %v", err)
	}
	return New(cfg, false)
}

func found(s *Scanner, text string) []string {
	var out []string
	for _, f := range s.findInText(text, "test", "") {
		out = append(out, f.Rule+"="+f.Secret)
	}
	return out
}

func TestRedactsRealSecretsTheAllowlistUsedToKeep(t *testing.T) {
	s := loadRules(t)
	myPassword := "My" + alnum(10)
	cases := []struct {
		name, text, secret string
	}{
		{"password starting with my", `password = "` + myPassword + `"`, myPassword},
		{"password starting with test", `password = "testing-Qz7kLm2p"`, "testing-Qz7kLm2p"},
		{"password containing $WORD", `password = "Pa$$W0RD!x"`, "Pa$$W0RD!x"},
		{"admin user in a connection string", "postgres://admin:Qz7kLm2pXw@prod-pg.corp.net/app", "Qz7kLm2pXw"},
		{"username user in a connection string", "mysql://username:Qz7kLm2pXw@db1.corp.net/app", "Qz7kLm2pXw"},
		{"localhost connection string", "postgres://svc:Qz7kLm2pXw@localhost:5432/app", "Qz7kLm2pXw"},
	}
	for _, c := range cases {
		got := found(s, c.text)
		hit := false
		for _, g := range got {
			if strings.HasSuffix(g, "="+c.secret) {
				hit = true
			}
		}
		if !hit {
			t.Errorf("%s: secret not found, got %v", c.name, got)
		}
	}
}

func TestKeepsWholeValuePlaceholders(t *testing.T) {
	s := loadRules(t)
	kept := []string{
		`password = "${DB_PASSWORD}"`,
		`password = "{{db_password}}"`,
		`password = "<your-password>"`,
		`password = "%DB_PASSWORD%"`,
		`password = "$DB_PASSWORD"`,
		`password = "example-password"`,
		`password = "your_password_here"`,
		`password = "changeme"`,
		`password = "........"`,
		"postgres://user:password@host/db",
		"postgres://svc:${DB_PASS}@prod-pg.corp.net/app",
		"postgres://svc:changeme@prod-pg.corp.net/app",
		"ghp_" + rep("x", 36),
		"AKIA" + rep("X", 16),
	}
	for _, text := range kept {
		if got := found(s, text); len(got) != 0 {
			t.Errorf("placeholder was flagged: %q -> %v", text, got)
		}
	}
}

func TestConnectionStringRedactsOnlyThePassword(t *testing.T) {
	s := loadRules(t)
	text := "DATABASE_URL=postgres://svc:Qz7kLm2pXw@prod-pg.corp.net/app"
	got := found(s, text)
	if len(got) != 1 || got[0] != "db-conn-str=Qz7kLm2pXw" {
		t.Fatalf("want only the password, got %v", got)
	}
}

func TestFindsTokenFormatsThatHadNoRule(t *testing.T) {
	s := loadRules(t)
	cases := map[string]string{
		"atlassian-api-token": "ATATT3" + rep("xFfGF0Qz7kLm2pXw9R-_", 186) + "=" + "1A2B3C4D",
		"vault-token":         "hvs." + alnum(90),
		"google-oauth-access": "ya29." + rep("a0B1c2D3_-", 120),
		"aws-session-token":   "IQoJ" + "b3JpZ2lu" + "X2Vj" + rep("EBAaCXVzLWVhc3QtMSJHMEUCIQ/+=", 300),
	}
	for rule, secret := range cases {
		got := found(s, "token: "+secret+" end")
		want := rule + "=" + secret
		hit := false
		for _, g := range got {
			if g == want {
				hit = true
			}
		}
		if !hit {
			t.Errorf("%s not found, got %v", rule, got)
		}
	}
}

func TestAwsSecretKeyEndingInSlashOrPlus(t *testing.T) {
	s := loadRules(t)
	for _, end := range []string{"/", "+"} {
		secret := alnum(39) + end
		got := found(s, "aws_secret_access_key = "+secret+"\n")
		hit := false
		for _, g := range got {
			if g == "aws-secret-access-key="+secret {
				hit = true
			}
		}
		if !hit {
			t.Errorf("key ending in %q not found, got %v", end, got)
		}
	}
}

func TestEnvFileSecretAssignment(t *testing.T) {
	s := loadRules(t)
	dbPassword, stripeSecret := alnum(10), rep("Kp3vLm9qRw2x", 12)
	text := "APP_NAME=demo\nexport DB_PASSWORD=" + dbPassword + "\nSTRIPE_SECRET=" + stripeSecret + "\nLOG_LEVEL=debug\n"
	got := found(s, text)
	want := map[string]bool{"env-secret-assignment=" + dbPassword: false, "env-secret-assignment=" + stripeSecret: false}
	for _, g := range got {
		if _, ok := want[g]; ok {
			want[g] = true
		}
	}
	for k, v := range want {
		if !v {
			t.Errorf("missing %s, got %v", k, got)
		}
	}
	for _, g := range got {
		if strings.Contains(g, "demo") || strings.Contains(g, "debug") {
			t.Errorf("non-secret flagged: %s", g)
		}
	}
}

func TestEnvFilePlaceholderAssignmentIsKept(t *testing.T) {
	s := loadRules(t)
	for _, text := range []string{"DB_PASSWORD=${DB_PASSWORD}\n", "API_TOKEN=changeme\n", "DB_PASSWORD=\n", "GITHUB_TOKEN=$GITHUB_TOKEN\n"} {
		if got := found(s, text); len(got) != 0 {
			t.Errorf("placeholder flagged: %q -> %v", text, got)
		}
	}
}
