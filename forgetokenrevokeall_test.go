package main

import (
	"strings"
	"testing"
)

// --all-for-user revokes every token on the account, so it must be spelled out twice
// (--user and the same name) and can never be combined with another selector.
func TestForgeTokenRevokeAllForUserGuards(t *testing.T) {
	for name, args := range map[string][]string{
		"without --user":       {"revoke", "--all-for-user", "grantonly"},
		"name differs":         {"revoke", "--user", "sasha", "--all-for-user", "grantonly"},
		"with --session":       {"revoke", "--user", "grantonly", "--all-for-user", "grantonly", "--session", "s"},
		"with --id":            {"revoke", "--user", "grantonly", "--all-for-user", "grantonly", "--id", "3"},
		"prefix of the --user": {"revoke", "--user", "grantonly2", "--all-for-user", "grantonly"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := runForgeToken(t, args...); err == nil {
				t.Fatalf("%v accepted", args)
			}
		})
	}
}

// A matching name gets PAST validation; the next complaint is the missing endpoint.
func TestForgeTokenRevokeAllForUserReachesTheEndpointStep(t *testing.T) {
	_, err := runForgeToken(t, "revoke", "--user", "grantonly", "--all-for-user", "grantonly")
	if err == nil || !strings.Contains(err.Error(), "forge API endpoint") {
		t.Fatalf("want the endpoint complaint, got %v", err)
	}
}
