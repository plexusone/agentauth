//go:build dynamodb

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/google/uuid"
)

// DynamoDBStore provides DynamoDB-backed persistence for AWS Lambda deployments.
type DynamoDBStore struct {
	client      *dynamodb.Client
	tablePrefix string
}

// Verify DynamoDBStore implements Storer at compile time.
var _ Storer = (*DynamoDBStore)(nil)

// Table names
func (s *DynamoDBStore) usersTable() string    { return s.tablePrefix + "-users" }
func (s *DynamoDBStore) agentsTable() string   { return s.tablePrefix + "-agents" }
func (s *DynamoDBStore) missionsTable() string { return s.tablePrefix + "-missions" }
func (s *DynamoDBStore) tokensTable() string   { return s.tablePrefix + "-tokens" }
func (s *DynamoDBStore) preAuthTable() string  { return s.tablePrefix + "-preauth" }
func (s *DynamoDBStore) policiesTable() string { return s.tablePrefix + "-policies" }

// NewDynamoDB creates a new DynamoDB-backed store.
func NewDynamoDB(ctx context.Context, tablePrefix string) (*DynamoDBStore, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	client := dynamodb.NewFromConfig(cfg)

	return &DynamoDBStore{
		client:      client,
		tablePrefix: tablePrefix,
	}, nil
}

// NewDynamoDBWithClient creates a store with a custom DynamoDB client.
func NewDynamoDBWithClient(client *dynamodb.Client, tablePrefix string) *DynamoDBStore {
	return &DynamoDBStore{
		client:      client,
		tablePrefix: tablePrefix,
	}
}

// Close is a no-op for DynamoDB (connection is managed by AWS SDK).
func (s *DynamoDBStore) Close() error {
	return nil
}

// ============================================================================
// User operations
// ============================================================================

// dynamoUser is the DynamoDB representation of a User.
type dynamoUser struct {
	ID        string `dynamodbav:"id"`
	Email     string `dynamodbav:"email"`
	Name      string `dynamodbav:"name"`
	CreatedAt int64  `dynamodbav:"created_at"`
	UpdatedAt int64  `dynamodbav:"updated_at"`
}

func (s *DynamoDBStore) CreateUser(ctx context.Context, user *User) error {
	if user.ID == "" {
		user.ID = uuid.New().String()
	}
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	item := dynamoUser{
		ID:        user.ID,
		Email:     user.Email,
		Name:      user.Name,
		CreatedAt: now.Unix(),
		UpdatedAt: now.Unix(),
	}

	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return err
	}

	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.usersTable()),
		Item:                av,
		ConditionExpression: aws.String("attribute_not_exists(id)"),
	})
	if err != nil {
		var condErr *types.ConditionalCheckFailedException
		if errors.As(err, &condErr) {
			return ErrAlreadyExists
		}
		return err
	}

	return nil
}

func (s *DynamoDBStore) GetUser(ctx context.Context, id string) (*User, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.usersTable()),
		Key: map[string]types.AttributeValue{
			"id": &types.AttributeValueMemberS{Value: id},
		},
	})
	if err != nil {
		return nil, err
	}

	if result.Item == nil {
		return nil, ErrNotFound
	}

	var item dynamoUser
	if err := attributevalue.UnmarshalMap(result.Item, &item); err != nil {
		return nil, err
	}

	return &User{
		ID:        item.ID,
		Email:     item.Email,
		Name:      item.Name,
		CreatedAt: time.Unix(item.CreatedAt, 0),
		UpdatedAt: time.Unix(item.UpdatedAt, 0),
	}, nil
}

func (s *DynamoDBStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	result, err := s.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(s.usersTable()),
		IndexName:              aws.String("email-index"),
		KeyConditionExpression: aws.String("email = :email"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":email": &types.AttributeValueMemberS{Value: email},
		},
		Limit: aws.Int32(1),
	})
	if err != nil {
		return nil, err
	}

	if len(result.Items) == 0 {
		return nil, ErrNotFound
	}

	var item dynamoUser
	if err := attributevalue.UnmarshalMap(result.Items[0], &item); err != nil {
		return nil, err
	}

	return &User{
		ID:        item.ID,
		Email:     item.Email,
		Name:      item.Name,
		CreatedAt: time.Unix(item.CreatedAt, 0),
		UpdatedAt: time.Unix(item.UpdatedAt, 0),
	}, nil
}

func (s *DynamoDBStore) ListUsers(ctx context.Context) ([]*User, error) {
	result, err := s.client.Scan(ctx, &dynamodb.ScanInput{
		TableName: aws.String(s.usersTable()),
	})
	if err != nil {
		return nil, err
	}

	users := make([]*User, 0, len(result.Items))
	for _, item := range result.Items {
		var du dynamoUser
		if err := attributevalue.UnmarshalMap(item, &du); err != nil {
			continue
		}
		users = append(users, &User{
			ID:        du.ID,
			Email:     du.Email,
			Name:      du.Name,
			CreatedAt: time.Unix(du.CreatedAt, 0),
			UpdatedAt: time.Unix(du.UpdatedAt, 0),
		})
	}

	return users, nil
}

// ============================================================================
// Agent operations
// ============================================================================

type dynamoAgent struct {
	ID          string `dynamodbav:"id"`
	Name        string `dynamodbav:"name"`
	Description string `dynamodbav:"description"`
	PublicKey   string `dynamodbav:"public_key"`
	RedirectURI string `dynamodbav:"redirect_uri"`
	Trusted     bool   `dynamodbav:"trusted"`
	CreatedAt   int64  `dynamodbav:"created_at"`
	UpdatedAt   int64  `dynamodbav:"updated_at"`
}

func (s *DynamoDBStore) CreateAgent(ctx context.Context, agent *Agent) error {
	if agent.ID == "" {
		agent.ID = uuid.New().String()
	}
	now := time.Now()
	agent.CreatedAt = now
	agent.UpdatedAt = now

	item := dynamoAgent{
		ID:          agent.ID,
		Name:        agent.Name,
		Description: agent.Description,
		PublicKey:   agent.PublicKey,
		RedirectURI: agent.RedirectURI,
		Trusted:     agent.Trusted,
		CreatedAt:   now.Unix(),
		UpdatedAt:   now.Unix(),
	}

	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return err
	}

	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.agentsTable()),
		Item:                av,
		ConditionExpression: aws.String("attribute_not_exists(id)"),
	})
	if err != nil {
		var condErr *types.ConditionalCheckFailedException
		if errors.As(err, &condErr) {
			return ErrAlreadyExists
		}
		return err
	}

	return nil
}

func (s *DynamoDBStore) GetAgent(ctx context.Context, id string) (*Agent, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.agentsTable()),
		Key: map[string]types.AttributeValue{
			"id": &types.AttributeValueMemberS{Value: id},
		},
	})
	if err != nil {
		return nil, err
	}

	if result.Item == nil {
		return nil, ErrNotFound
	}

	var item dynamoAgent
	if err := attributevalue.UnmarshalMap(result.Item, &item); err != nil {
		return nil, err
	}

	return &Agent{
		ID:          item.ID,
		Name:        item.Name,
		Description: item.Description,
		PublicKey:   item.PublicKey,
		RedirectURI: item.RedirectURI,
		Trusted:     item.Trusted,
		CreatedAt:   time.Unix(item.CreatedAt, 0),
		UpdatedAt:   time.Unix(item.UpdatedAt, 0),
	}, nil
}

func (s *DynamoDBStore) ListAgents(ctx context.Context) ([]*Agent, error) {
	result, err := s.client.Scan(ctx, &dynamodb.ScanInput{
		TableName: aws.String(s.agentsTable()),
	})
	if err != nil {
		return nil, err
	}

	agents := make([]*Agent, 0, len(result.Items))
	for _, item := range result.Items {
		var da dynamoAgent
		if err := attributevalue.UnmarshalMap(item, &da); err != nil {
			continue
		}
		agents = append(agents, &Agent{
			ID:          da.ID,
			Name:        da.Name,
			Description: da.Description,
			PublicKey:   da.PublicKey,
			RedirectURI: da.RedirectURI,
			Trusted:     da.Trusted,
			CreatedAt:   time.Unix(da.CreatedAt, 0),
			UpdatedAt:   time.Unix(da.UpdatedAt, 0),
		})
	}

	return agents, nil
}

// ============================================================================
// Mission operations
// ============================================================================

type dynamoMission struct {
	ID              string `dynamodbav:"id"`
	AgentID         string `dynamodbav:"agent_id"`
	UserID          string `dynamodbav:"user_id"`
	Name            string `dynamodbav:"name"`
	Description     string `dynamodbav:"description"`
	Scopes          string `dynamodbav:"scopes"`
	InteractionType string `dynamodbav:"interaction_type"`
	Status          string `dynamodbav:"status"`
	Duration        int64  `dynamodbav:"duration"`
	ExpiresAt       int64  `dynamodbav:"expires_at,omitempty"`
	ApprovedAt      int64  `dynamodbav:"approved_at,omitempty"`
	DeniedAt        int64  `dynamodbav:"denied_at,omitempty"`
	DenialReason    string `dynamodbav:"denial_reason,omitempty"`
	CreatedAt       int64  `dynamodbav:"created_at"`
	UpdatedAt       int64  `dynamodbav:"updated_at"`
}

func (s *DynamoDBStore) CreateMission(ctx context.Context, mission *Mission) error {
	if mission.ID == "" {
		mission.ID = uuid.New().String()
	}
	now := time.Now()
	mission.CreatedAt = now
	mission.UpdatedAt = now
	if mission.Status == "" {
		mission.Status = MissionStatusPending
	}

	item := dynamoMission{
		ID:              mission.ID,
		AgentID:         mission.AgentID,
		UserID:          mission.UserID,
		Name:            mission.Name,
		Description:     mission.Description,
		Scopes:          mission.Scopes,
		InteractionType: mission.InteractionType,
		Status:          string(mission.Status),
		Duration:        mission.Duration,
		CreatedAt:       now.Unix(),
		UpdatedAt:       now.Unix(),
	}

	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return err
	}

	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.missionsTable()),
		Item:      av,
	})

	return err
}

func (s *DynamoDBStore) GetMission(ctx context.Context, id string) (*Mission, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.missionsTable()),
		Key: map[string]types.AttributeValue{
			"id": &types.AttributeValueMemberS{Value: id},
		},
	})
	if err != nil {
		return nil, err
	}

	if result.Item == nil {
		return nil, ErrNotFound
	}

	var item dynamoMission
	if err := attributevalue.UnmarshalMap(result.Item, &item); err != nil {
		return nil, err
	}

	mission := &Mission{
		ID:              item.ID,
		AgentID:         item.AgentID,
		UserID:          item.UserID,
		Name:            item.Name,
		Description:     item.Description,
		Scopes:          item.Scopes,
		InteractionType: item.InteractionType,
		Status:          MissionStatus(item.Status),
		Duration:        item.Duration,
		DenialReason:    item.DenialReason,
		CreatedAt:       time.Unix(item.CreatedAt, 0),
		UpdatedAt:       time.Unix(item.UpdatedAt, 0),
	}

	if item.ExpiresAt > 0 {
		t := time.Unix(item.ExpiresAt, 0)
		mission.ExpiresAt = &t
	}
	if item.ApprovedAt > 0 {
		t := time.Unix(item.ApprovedAt, 0)
		mission.ApprovedAt = &t
	}
	if item.DeniedAt > 0 {
		t := time.Unix(item.DeniedAt, 0)
		mission.DeniedAt = &t
	}

	return mission, nil
}

func (s *DynamoDBStore) ApproveMission(ctx context.Context, id string, duration time.Duration) error {
	now := time.Now()
	expiresAt := now.Add(duration)

	_, err := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.missionsTable()),
		Key: map[string]types.AttributeValue{
			"id": &types.AttributeValueMemberS{Value: id},
		},
		UpdateExpression: aws.String("SET #status = :status, approved_at = :approved, expires_at = :expires, updated_at = :updated"),
		ExpressionAttributeNames: map[string]string{
			"#status": "status",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":status":   &types.AttributeValueMemberS{Value: string(MissionStatusApproved)},
			":approved": &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", now.Unix())},
			":expires":  &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", expiresAt.Unix())},
			":updated":  &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", now.Unix())},
		},
		ConditionExpression: aws.String("attribute_exists(id)"),
	})

	if err != nil {
		var condErr *types.ConditionalCheckFailedException
		if errors.As(err, &condErr) {
			return ErrNotFound
		}
		return err
	}

	return nil
}

func (s *DynamoDBStore) DenyMission(ctx context.Context, id, reason string) error {
	now := time.Now()

	_, err := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.missionsTable()),
		Key: map[string]types.AttributeValue{
			"id": &types.AttributeValueMemberS{Value: id},
		},
		UpdateExpression: aws.String("SET #status = :status, denied_at = :denied, denial_reason = :reason, updated_at = :updated"),
		ExpressionAttributeNames: map[string]string{
			"#status": "status",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":status":  &types.AttributeValueMemberS{Value: string(MissionStatusDenied)},
			":denied":  &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", now.Unix())},
			":reason":  &types.AttributeValueMemberS{Value: reason},
			":updated": &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", now.Unix())},
		},
		ConditionExpression: aws.String("attribute_exists(id)"),
	})

	if err != nil {
		var condErr *types.ConditionalCheckFailedException
		if errors.As(err, &condErr) {
			return ErrNotFound
		}
		return err
	}

	return nil
}

func (s *DynamoDBStore) ListPendingMissions(ctx context.Context) ([]*Mission, error) {
	// Use scan with filter for pending status
	// In production, consider using a GSI on status
	result, err := s.client.Scan(ctx, &dynamodb.ScanInput{
		TableName:        aws.String(s.missionsTable()),
		FilterExpression: aws.String("#status = :status"),
		ExpressionAttributeNames: map[string]string{
			"#status": "status",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":status": &types.AttributeValueMemberS{Value: string(MissionStatusPending)},
		},
	})
	if err != nil {
		return nil, err
	}

	return s.unmarshalMissions(result.Items)
}

func (s *DynamoDBStore) ListMissionsByUser(ctx context.Context, userID string) ([]*Mission, error) {
	result, err := s.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(s.missionsTable()),
		IndexName:              aws.String("user-status-index"),
		KeyConditionExpression: aws.String("user_id = :user_id"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":user_id": &types.AttributeValueMemberS{Value: userID},
		},
	})
	if err != nil {
		return nil, err
	}

	return s.unmarshalMissions(result.Items)
}

func (s *DynamoDBStore) unmarshalMissions(items []map[string]types.AttributeValue) ([]*Mission, error) {
	missions := make([]*Mission, 0, len(items))
	for _, item := range items {
		var dm dynamoMission
		if err := attributevalue.UnmarshalMap(item, &dm); err != nil {
			continue
		}
		mission := &Mission{
			ID:              dm.ID,
			AgentID:         dm.AgentID,
			UserID:          dm.UserID,
			Name:            dm.Name,
			Description:     dm.Description,
			Scopes:          dm.Scopes,
			InteractionType: dm.InteractionType,
			Status:          MissionStatus(dm.Status),
			Duration:        dm.Duration,
			CreatedAt:       time.Unix(dm.CreatedAt, 0),
			UpdatedAt:       time.Unix(dm.UpdatedAt, 0),
		}
		if dm.ExpiresAt > 0 {
			t := time.Unix(dm.ExpiresAt, 0)
			mission.ExpiresAt = &t
		}
		if dm.ApprovedAt > 0 {
			t := time.Unix(dm.ApprovedAt, 0)
			mission.ApprovedAt = &t
		}
		if dm.DeniedAt > 0 {
			t := time.Unix(dm.DeniedAt, 0)
			mission.DeniedAt = &t
		}
		if dm.DenialReason != "" {
			mission.DenialReason = dm.DenialReason
		}
		missions = append(missions, mission)
	}
	return missions, nil
}

// ============================================================================
// Token operations
// ============================================================================

type dynamoToken struct {
	ID        string `dynamodbav:"id"`
	MissionID string `dynamodbav:"mission_id,omitempty"`
	AgentID   string `dynamodbav:"agent_id"`
	UserID    string `dynamodbav:"user_id"`
	Scopes    string `dynamodbav:"scopes"`
	TokenType string `dynamodbav:"token_type"`
	Protocol  string `dynamodbav:"protocol"`
	IssuedAt  int64  `dynamodbav:"issued_at"`
	ExpiresAt int64  `dynamodbav:"expires_at"`
	RevokedAt int64  `dynamodbav:"revoked_at,omitempty"`
}

func (s *DynamoDBStore) CreateToken(ctx context.Context, token *Token) error {
	if token.ID == "" {
		token.ID = uuid.New().String()
	}
	if token.IssuedAt.IsZero() {
		token.IssuedAt = time.Now()
	}
	if token.TokenType == "" {
		token.TokenType = "access_token"
	}
	if token.Protocol == "" {
		token.Protocol = "aauth"
	}

	item := dynamoToken{
		ID:        token.ID,
		MissionID: token.MissionID,
		AgentID:   token.AgentID,
		UserID:    token.UserID,
		Scopes:    token.Scopes,
		TokenType: token.TokenType,
		Protocol:  token.Protocol,
		IssuedAt:  token.IssuedAt.Unix(),
		ExpiresAt: token.ExpiresAt.Unix(),
	}

	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return err
	}

	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.tokensTable()),
		Item:      av,
	})

	return err
}

func (s *DynamoDBStore) GetToken(ctx context.Context, id string) (*Token, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tokensTable()),
		Key: map[string]types.AttributeValue{
			"id": &types.AttributeValueMemberS{Value: id},
		},
	})
	if err != nil {
		return nil, err
	}

	if result.Item == nil {
		return nil, ErrNotFound
	}

	var item dynamoToken
	if err := attributevalue.UnmarshalMap(result.Item, &item); err != nil {
		return nil, err
	}

	token := &Token{
		ID:        item.ID,
		MissionID: item.MissionID,
		AgentID:   item.AgentID,
		UserID:    item.UserID,
		Scopes:    item.Scopes,
		TokenType: item.TokenType,
		Protocol:  item.Protocol,
		IssuedAt:  time.Unix(item.IssuedAt, 0),
		ExpiresAt: time.Unix(item.ExpiresAt, 0),
	}

	if item.RevokedAt > 0 {
		t := time.Unix(item.RevokedAt, 0)
		token.RevokedAt = &t
	}

	return token, nil
}

func (s *DynamoDBStore) RevokeToken(ctx context.Context, id string) error {
	now := time.Now()

	_, err := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.tokensTable()),
		Key: map[string]types.AttributeValue{
			"id": &types.AttributeValueMemberS{Value: id},
		},
		UpdateExpression: aws.String("SET revoked_at = :revoked"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":revoked": &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", now.Unix())},
		},
		ConditionExpression: aws.String("attribute_exists(id)"),
	})

	if err != nil {
		var condErr *types.ConditionalCheckFailedException
		if errors.As(err, &condErr) {
			return ErrNotFound
		}
		return err
	}

	return nil
}

func (s *DynamoDBStore) ListTokens(ctx context.Context) ([]*Token, error) {
	result, err := s.client.Scan(ctx, &dynamodb.ScanInput{
		TableName: aws.String(s.tokensTable()),
	})
	if err != nil {
		return nil, err
	}

	tokens := make([]*Token, 0, len(result.Items))
	for _, item := range result.Items {
		var dt dynamoToken
		if err := attributevalue.UnmarshalMap(item, &dt); err != nil {
			continue
		}
		token := &Token{
			ID:        dt.ID,
			MissionID: dt.MissionID,
			AgentID:   dt.AgentID,
			UserID:    dt.UserID,
			Scopes:    dt.Scopes,
			TokenType: dt.TokenType,
			Protocol:  dt.Protocol,
			IssuedAt:  time.Unix(dt.IssuedAt, 0),
			ExpiresAt: time.Unix(dt.ExpiresAt, 0),
		}
		if dt.RevokedAt > 0 {
			t := time.Unix(dt.RevokedAt, 0)
			token.RevokedAt = &t
		}
		tokens = append(tokens, token)
	}

	return tokens, nil
}

// ============================================================================
// Pre-authorization operations
// ============================================================================

type dynamoPreAuth struct {
	ID        string `dynamodbav:"id"`
	UserID    string `dynamodbav:"user_id"`
	AgentID   string `dynamodbav:"agent_id"`
	Scopes    string `dynamodbav:"scopes"`
	CreatedAt int64  `dynamodbav:"created_at"`
	ExpiresAt int64  `dynamodbav:"expires_at,omitempty"`
}

func (s *DynamoDBStore) CreatePreAuthorization(ctx context.Context, preAuth *PreAuthorization) error {
	if preAuth.ID == "" {
		preAuth.ID = uuid.New().String()
	}
	now := time.Now()
	preAuth.CreatedAt = now

	item := dynamoPreAuth{
		ID:        preAuth.ID,
		UserID:    preAuth.UserID,
		AgentID:   preAuth.AgentID,
		Scopes:    preAuth.Scopes,
		CreatedAt: now.Unix(),
	}
	if preAuth.ExpiresAt != nil {
		item.ExpiresAt = preAuth.ExpiresAt.Unix()
	}

	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return err
	}

	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.preAuthTable()),
		Item:      av,
	})

	return err
}

func (s *DynamoDBStore) GetPreAuthorization(ctx context.Context, userID, agentID string) (*PreAuthorization, error) {
	// Use composite key lookup
	result, err := s.client.Scan(ctx, &dynamodb.ScanInput{
		TableName:        aws.String(s.preAuthTable()),
		FilterExpression: aws.String("user_id = :user_id AND agent_id = :agent_id"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":user_id":  &types.AttributeValueMemberS{Value: userID},
			":agent_id": &types.AttributeValueMemberS{Value: agentID},
		},
		Limit: aws.Int32(1),
	})
	if err != nil {
		return nil, err
	}

	if len(result.Items) == 0 {
		return nil, ErrNotFound
	}

	var item dynamoPreAuth
	if err := attributevalue.UnmarshalMap(result.Items[0], &item); err != nil {
		return nil, err
	}

	preAuth := &PreAuthorization{
		ID:        item.ID,
		UserID:    item.UserID,
		AgentID:   item.AgentID,
		Scopes:    item.Scopes,
		CreatedAt: time.Unix(item.CreatedAt, 0),
	}
	if item.ExpiresAt > 0 {
		t := time.Unix(item.ExpiresAt, 0)
		preAuth.ExpiresAt = &t
	}

	return preAuth, nil
}

func (s *DynamoDBStore) DeletePreAuthorization(ctx context.Context, userID, agentID string) error {
	// First find the item to get its ID
	preAuth, err := s.GetPreAuthorization(ctx, userID, agentID)
	if err != nil {
		return err
	}

	_, err = s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(s.preAuthTable()),
		Key: map[string]types.AttributeValue{
			"id": &types.AttributeValueMemberS{Value: preAuth.ID},
		},
	})

	return err
}

// ============================================================================
// Scope policy operations
// ============================================================================

type dynamoPolicy struct {
	ID              string `dynamodbav:"id"`
	Pattern         string `dynamodbav:"pattern"`
	Protocol        string `dynamodbav:"protocol"`
	InteractionType string `dynamodbav:"interaction_type,omitempty"`
	Description     string `dynamodbav:"description,omitempty"`
	Priority        int    `dynamodbav:"priority"`
	CreatedAt       int64  `dynamodbav:"created_at"`
}

func (s *DynamoDBStore) CreateScopePolicy(ctx context.Context, policy *ScopePolicy) error {
	if policy.ID == "" {
		policy.ID = uuid.New().String()
	}
	now := time.Now()
	policy.CreatedAt = now

	item := dynamoPolicy{
		ID:              policy.ID,
		Pattern:         policy.Pattern,
		Protocol:        policy.Protocol,
		InteractionType: policy.InteractionType,
		Description:     policy.Description,
		Priority:        policy.Priority,
		CreatedAt:       now.Unix(),
	}

	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return err
	}

	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.policiesTable()),
		Item:      av,
	})

	return err
}

func (s *DynamoDBStore) GetScopePolicy(ctx context.Context, id string) (*ScopePolicy, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.policiesTable()),
		Key: map[string]types.AttributeValue{
			"id": &types.AttributeValueMemberS{Value: id},
		},
	})
	if err != nil {
		return nil, err
	}

	if result.Item == nil {
		return nil, ErrNotFound
	}

	var item dynamoPolicy
	if err := attributevalue.UnmarshalMap(result.Item, &item); err != nil {
		return nil, err
	}

	return &ScopePolicy{
		ID:              item.ID,
		Pattern:         item.Pattern,
		Protocol:        item.Protocol,
		InteractionType: item.InteractionType,
		Description:     item.Description,
		Priority:        item.Priority,
		CreatedAt:       time.Unix(item.CreatedAt, 0),
	}, nil
}

func (s *DynamoDBStore) ListScopePolicies(ctx context.Context) ([]*ScopePolicy, error) {
	result, err := s.client.Scan(ctx, &dynamodb.ScanInput{
		TableName: aws.String(s.policiesTable()),
	})
	if err != nil {
		return nil, err
	}

	policies := make([]*ScopePolicy, 0, len(result.Items))
	for _, item := range result.Items {
		var dp dynamoPolicy
		if err := attributevalue.UnmarshalMap(item, &dp); err != nil {
			continue
		}
		policies = append(policies, &ScopePolicy{
			ID:              dp.ID,
			Pattern:         dp.Pattern,
			Protocol:        dp.Protocol,
			InteractionType: dp.InteractionType,
			Description:     dp.Description,
			Priority:        dp.Priority,
			CreatedAt:       time.Unix(dp.CreatedAt, 0),
		})
	}

	return policies, nil
}

func (s *DynamoDBStore) DeleteScopePolicy(ctx context.Context, id string) error {
	_, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(s.policiesTable()),
		Key: map[string]types.AttributeValue{
			"id": &types.AttributeValueMemberS{Value: id},
		},
	})
	return err
}
