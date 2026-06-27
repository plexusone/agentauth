package identity

import (
	"context"
	"testing"
	"time"
)

// mockAAuthVerifier implements AAuthVerifier for testing.
type mockAAuthVerifier struct {
	returnIdentity *AgentIdentity
	returnError    error
}

func (m *mockAAuthVerifier) VerifyAAuth(ctx context.Context, token string) (*AgentIdentity, error) {
	if m.returnError != nil {
		return nil, m.returnError
	}
	return m.returnIdentity, nil
}

// mockIDJAGVerifier implements IDJAGVerifier for testing.
type mockIDJAGVerifier struct {
	returnIdentity *HumanIdentity
	returnError    error
}

func (m *mockIDJAGVerifier) VerifyIDJAG(ctx context.Context, assertion string) (*HumanIdentity, error) {
	if m.returnError != nil {
		return nil, m.returnError
	}
	return m.returnIdentity, nil
}

func TestComposer_ComposeAgentOnly(t *testing.T) {
	agent := &AgentIdentity{
		AgentID:      "test-agent",
		Issuer:       "https://auth.example.com",
		Capabilities: []string{"read", "write"},
		VerifiedAt:   time.Now(),
	}

	composer := NewComposer(
		WithAAuthVerifier(&mockAAuthVerifier{returnIdentity: agent}),
	)

	identity, err := composer.Compose(context.Background(), ComposeOptions{
		AAuthToken: "test-token",
		TraceID:    "trace-123",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if identity.Agent == nil {
		t.Fatal("expected agent identity")
	}

	if identity.Agent.AgentID != "test-agent" {
		t.Errorf("expected agent ID 'test-agent', got %s", identity.Agent.AgentID)
	}

	if identity.Human != nil {
		t.Error("expected no human identity")
	}

	if identity.BindingID == "" {
		t.Error("expected binding ID")
	}

	if identity.TraceID != "trace-123" {
		t.Errorf("expected trace ID 'trace-123', got %s", identity.TraceID)
	}
}

func TestComposer_ComposeWithHuman(t *testing.T) {
	agent := &AgentIdentity{
		AgentID: "test-agent",
		Issuer:  "https://auth.example.com",
	}

	human := &HumanIdentity{
		Subject: "user@example.com",
		Issuer:  "https://idp.example.com",
		Email:   "user@example.com",
		Name:    "Test User",
	}

	composer := NewComposer(
		WithAAuthVerifier(&mockAAuthVerifier{returnIdentity: agent}),
		WithIDJAGVerifier(&mockIDJAGVerifier{returnIdentity: human}),
	)

	identity, err := composer.Compose(context.Background(), ComposeOptions{
		AAuthToken:     "test-token",
		IDJAGAssertion: "test-assertion",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if identity.Agent == nil {
		t.Fatal("expected agent identity")
	}

	if identity.Human == nil {
		t.Fatal("expected human identity")
	}

	if identity.Human.Subject != "user@example.com" {
		t.Errorf("expected human subject 'user@example.com', got %s", identity.Human.Subject)
	}
}

func TestComposer_RequiresAAuthToken(t *testing.T) {
	composer := NewComposer()

	_, err := composer.Compose(context.Background(), ComposeOptions{})

	if err != ErrAgentIdentityRequired {
		t.Errorf("expected ErrAgentIdentityRequired, got %v", err)
	}
}

func TestComposedIdentity_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		identity *ComposedIdentity
		want     bool
	}{
		{
			name:     "nil identity",
			identity: nil,
			want:     false,
		},
		{
			name:     "nil agent",
			identity: &ComposedIdentity{BindingID: "test"},
			want:     false,
		},
		{
			name: "empty agent ID",
			identity: &ComposedIdentity{
				Agent:     &AgentIdentity{},
				BindingID: "test",
			},
			want: false,
		},
		{
			name: "empty binding ID",
			identity: &ComposedIdentity{
				Agent: &AgentIdentity{AgentID: "test"},
			},
			want: false,
		},
		{
			name: "valid identity",
			identity: &ComposedIdentity{
				Agent:     &AgentIdentity{AgentID: "test"},
				BindingID: "bind-123",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.identity.IsValid(); got != tt.want {
				t.Errorf("IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestComposedIdentity_AuditString(t *testing.T) {
	identity := &ComposedIdentity{
		Agent: &AgentIdentity{
			AgentID: "research-agent",
		},
		Human: &HumanIdentity{
			Subject: "alice@example.com",
		},
		Workload: &WorkloadIdentity{
			SPIFFEID: "spiffe://example.com/prod/research",
		},
		BindingID: "bind-xyz",
	}

	audit := identity.AuditString()
	expected := "agent:research-agent for-human:alice@example.com on-workload:spiffe://example.com/prod/research binding:bind-xyz"

	if audit != expected {
		t.Errorf("AuditString() = %q, want %q", audit, expected)
	}
}

func TestContext(t *testing.T) {
	identity := &ComposedIdentity{
		Agent:     &AgentIdentity{AgentID: "test"},
		BindingID: "bind-123",
	}

	ctx := WithContext(context.Background(), identity)

	retrieved, ok := FromContext(ctx)
	if !ok {
		t.Fatal("expected to retrieve identity from context")
	}

	if retrieved.BindingID != identity.BindingID {
		t.Errorf("expected binding ID %q, got %q", identity.BindingID, retrieved.BindingID)
	}

	// Test missing identity
	_, ok = FromContext(context.Background())
	if ok {
		t.Error("expected false for context without identity")
	}
}
