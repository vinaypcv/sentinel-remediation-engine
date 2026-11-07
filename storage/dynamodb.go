package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type DynamoDBAPI interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	DeleteItem(context.Context, *dynamodb.DeleteItemInput, ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
}

type DynamoDBStateStore struct {
	Client         DynamoDBAPI
	TableName      string
	IdempotencyTTL time.Duration
	ClaimLease     time.Duration
	mu             sync.Mutex
	claimTokens    map[string]string
}

func NewDynamoDBStateStore(client DynamoDBAPI, tableName string) (*DynamoDBStateStore, error) {
	if client == nil || tableName == "" {
		return nil, fmt.Errorf("DynamoDB client and table name are required")
	}
	return &DynamoDBStateStore{
		Client:         client,
		TableName:      tableName,
		IdempotencyTTL: 90 * 24 * time.Hour,
		ClaimLease:     2 * time.Minute,
		claimTokens:    make(map[string]string),
	}, nil
}

func (s *DynamoDBStateStore) Load(ctx context.Context, stream, shard string) (string, bool, error) {
	if err := s.validate(); err != nil {
		return "", false, err
	}
	output, err := s.Client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(s.TableName),
		ConsistentRead: aws.Bool(true),
		Key:            stateKey(checkpointRecordKey(stream, shard)),
	})
	if err != nil {
		return "", false, fmt.Errorf("load DynamoDB checkpoint: %w", err)
	}
	sequence := stringAttribute(output.Item, "sequence_number")
	return sequence, sequence != "", nil
}

func (s *DynamoDBStateStore) Save(ctx context.Context, stream, shard, sequence string) error {
	if err := s.validate(); err != nil {
		return err
	}
	if stream == "" || shard == "" || sequence == "" {
		return fmt.Errorf("stream, shard, and sequence are required for checkpoint")
	}
	_, err := s.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                aws.String(s.TableName),
		Key:                      stateKey(checkpointRecordKey(stream, shard)),
		UpdateExpression:         aws.String("SET #record_type = :record_type, sequence_number = :sequence, updated_at = :updated_at"),
		ExpressionAttributeNames: map[string]string{"#record_type": "record_type"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":record_type": &types.AttributeValueMemberS{Value: "checkpoint"},
			":sequence":    &types.AttributeValueMemberS{Value: sequence},
			":updated_at":  &types.AttributeValueMemberN{Value: strconv.FormatInt(time.Now().Unix(), 10)},
		},
	})
	if err != nil {
		return fmt.Errorf("save DynamoDB checkpoint: %w", err)
	}
	return nil
}

func (s *DynamoDBStateStore) AcquireLease(ctx context.Context, stream, shard, owner string, duration time.Duration) (bool, error) {
	if err := s.validateLease(stream, shard, owner, duration); err != nil {
		return false, err
	}
	if duration < 5*time.Second {
		return false, fmt.Errorf("DynamoDB shard lease duration must be at least five seconds")
	}
	now := time.Now().Unix()
	_, err := s.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                aws.String(s.TableName),
		Key:                      stateKey(checkpointRecordKey(stream, shard)),
		UpdateExpression:         aws.String("SET #record_type = :record_type, lease_owner = :owner, lease_until = :lease_until"),
		ConditionExpression:      aws.String("attribute_not_exists(lease_owner) OR lease_until < :now OR lease_owner = :owner"),
		ExpressionAttributeNames: map[string]string{"#record_type": "record_type"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":record_type": &types.AttributeValueMemberS{Value: "checkpoint"},
			":owner":       &types.AttributeValueMemberS{Value: owner},
			":now":         &types.AttributeValueMemberN{Value: strconv.FormatInt(now, 10)},
			":lease_until": &types.AttributeValueMemberN{Value: strconv.FormatInt(time.Now().Add(duration).Unix(), 10)},
		},
	})
	if isConditionalFailure(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("acquire DynamoDB shard lease: %w", err)
	}
	return true, nil
}

func (s *DynamoDBStateStore) SaveOwned(ctx context.Context, stream, shard, owner, sequence string) error {
	if err := s.validateLease(stream, shard, owner, 0); err != nil {
		return err
	}
	if sequence == "" {
		return fmt.Errorf("checkpoint sequence is required")
	}
	_, err := s.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(s.TableName),
		Key:                 stateKey(checkpointRecordKey(stream, shard)),
		UpdateExpression:    aws.String("SET sequence_number = :sequence, updated_at = :updated_at"),
		ConditionExpression: aws.String("lease_owner = :owner AND lease_until > :now"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":owner":      &types.AttributeValueMemberS{Value: owner},
			":sequence":   &types.AttributeValueMemberS{Value: sequence},
			":now":        &types.AttributeValueMemberN{Value: strconv.FormatInt(time.Now().Unix(), 10)},
			":updated_at": &types.AttributeValueMemberN{Value: strconv.FormatInt(time.Now().Unix(), 10)},
		},
	})
	if isConditionalFailure(err) {
		return fmt.Errorf("shard lease lost before checkpoint: %w", err)
	}
	if err != nil {
		return fmt.Errorf("save owned DynamoDB checkpoint: %w", err)
	}
	return nil
}

func (s *DynamoDBStateStore) ReleaseLease(ctx context.Context, stream, shard, owner string) error {
	if err := s.validateLease(stream, shard, owner, 0); err != nil {
		return err
	}
	_, err := s.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.TableName),
		Key:                       stateKey(checkpointRecordKey(stream, shard)),
		UpdateExpression:          aws.String("REMOVE lease_owner, lease_until"),
		ConditionExpression:       aws.String("lease_owner = :owner"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":owner": &types.AttributeValueMemberS{Value: owner}},
	})
	if isConditionalFailure(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("release DynamoDB shard lease: %w", err)
	}
	return nil
}

func (s *DynamoDBStateStore) Claim(ctx context.Context, id string) (bool, error) {
	if err := s.validate(); err != nil {
		return false, err
	}
	if id == "" || len(id) > 256 {
		return false, fmt.Errorf("idempotency event ID must be between 1 and 256 bytes")
	}
	token, err := randomToken()
	if err != nil {
		return false, fmt.Errorf("create idempotency claim token: %w", err)
	}
	lease := s.ClaimLease
	if lease <= 0 {
		lease = 2 * time.Minute
	}
	now := time.Now()
	leaseUntil := now.Add(lease).Unix()
	_, err = s.Client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.TableName),
		Item: map[string]types.AttributeValue{
			"record_key":  &types.AttributeValueMemberS{Value: eventRecordKey(id)},
			"record_type": &types.AttributeValueMemberS{Value: "idempotency"},
			"status":      &types.AttributeValueMemberS{Value: "inflight"},
			"claim_token": &types.AttributeValueMemberS{Value: token},
			"lease_until": &types.AttributeValueMemberN{Value: strconv.FormatInt(leaseUntil, 10)},
			"expires_at":  &types.AttributeValueMemberN{Value: strconv.FormatInt(leaseUntil, 10)},
			"event_id":    &types.AttributeValueMemberS{Value: id},
		},
		ConditionExpression:      aws.String("attribute_not_exists(record_key) OR (#status = :inflight AND lease_until < :now)"),
		ExpressionAttributeNames: map[string]string{"#status": "status"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":inflight": &types.AttributeValueMemberS{Value: "inflight"},
			":now":      &types.AttributeValueMemberN{Value: strconv.FormatInt(now.Unix(), 10)},
		},
	})
	if isConditionalFailure(err) {
		output, getErr := s.Client.GetItem(ctx, &dynamodb.GetItemInput{
			TableName:      aws.String(s.TableName),
			ConsistentRead: aws.Bool(true),
			Key:            stateKey(eventRecordKey(id)),
		})
		if getErr != nil {
			return false, fmt.Errorf("inspect existing DynamoDB idempotency claim: %w", getErr)
		}
		if stringAttribute(output.Item, "status") == "completed" {
			return false, nil
		}
		return false, ErrEventInFlight
	}
	if err != nil {
		return false, fmt.Errorf("claim DynamoDB idempotency key: %w", err)
	}
	s.mu.Lock()
	s.claimTokens[id] = token
	s.mu.Unlock()
	return true, nil
}

func (s *DynamoDBStateStore) Release(id string) {
	if s == nil || id == "" {
		return
	}
	s.mu.Lock()
	token, ok := s.claimTokens[id]
	delete(s.claimTokens, id)
	s.mu.Unlock()
	if !ok || s.validate() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _ = s.Client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                aws.String(s.TableName),
		Key:                      stateKey(eventRecordKey(id)),
		ConditionExpression:      aws.String("#status = :inflight AND claim_token = :token"),
		ExpressionAttributeNames: map[string]string{"#status": "status"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":inflight": &types.AttributeValueMemberS{Value: "inflight"},
			":token":    &types.AttributeValueMemberS{Value: token},
		},
	})
}

func (s *DynamoDBStateStore) CompleteContext(ctx context.Context, id string, eventTime time.Time) error {
	if err := s.validate(); err != nil {
		return err
	}
	s.mu.Lock()
	token := s.claimTokens[id]
	s.mu.Unlock()
	if id == "" || token == "" {
		return fmt.Errorf("no active DynamoDB idempotency claim for event %q", id)
	}
	retention := s.IdempotencyTTL
	if retention <= 0 {
		retention = 90 * 24 * time.Hour
	}
	now := time.Now()
	_, err := s.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                aws.String(s.TableName),
		Key:                      stateKey(eventRecordKey(id)),
		UpdateExpression:         aws.String("SET #status = :completed, completed_at = :now, event_time = :event_time, expires_at = :expires_at REMOVE lease_until, claim_token"),
		ConditionExpression:      aws.String("#status = :inflight AND claim_token = :token AND lease_until >= :now"),
		ExpressionAttributeNames: map[string]string{"#status": "status"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":completed":  &types.AttributeValueMemberS{Value: "completed"},
			":inflight":   &types.AttributeValueMemberS{Value: "inflight"},
			":token":      &types.AttributeValueMemberS{Value: token},
			":now":        &types.AttributeValueMemberN{Value: strconv.FormatInt(now.Unix(), 10)},
			":event_time": &types.AttributeValueMemberN{Value: strconv.FormatInt(eventTime.Unix(), 10)},
			":expires_at": &types.AttributeValueMemberN{Value: strconv.FormatInt(now.Add(retention).Unix(), 10)},
		},
	})
	if err != nil {
		return fmt.Errorf("complete DynamoDB idempotency key: %w", err)
	}
	s.mu.Lock()
	delete(s.claimTokens, id)
	s.mu.Unlock()
	return nil
}

func (s *DynamoDBStateStore) RenewClaim(ctx context.Context, id string) error {
	if err := s.validate(); err != nil {
		return err
	}
	s.mu.Lock()
	token := s.claimTokens[id]
	s.mu.Unlock()
	if id == "" || token == "" {
		return fmt.Errorf("no active DynamoDB idempotency claim for event %q", id)
	}
	lease := s.ClaimLease
	if lease <= 0 {
		lease = 2 * time.Minute
	}
	now := time.Now()
	leaseUntil := now.Add(lease).Unix()
	_, err := s.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                aws.String(s.TableName),
		Key:                      stateKey(eventRecordKey(id)),
		UpdateExpression:         aws.String("SET lease_until = :lease_until, expires_at = :lease_until"),
		ConditionExpression:      aws.String("#status = :inflight AND claim_token = :token AND lease_until >= :now"),
		ExpressionAttributeNames: map[string]string{"#status": "status"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":inflight":    &types.AttributeValueMemberS{Value: "inflight"},
			":token":       &types.AttributeValueMemberS{Value: token},
			":now":         &types.AttributeValueMemberN{Value: strconv.FormatInt(now.Unix(), 10)},
			":lease_until": &types.AttributeValueMemberN{Value: strconv.FormatInt(leaseUntil, 10)},
		},
	})
	if err != nil {
		return fmt.Errorf("renew DynamoDB idempotency claim: %w", err)
	}
	return nil
}

func (s *DynamoDBStateStore) ClaimHeartbeatInterval() time.Duration {
	lease := s.ClaimLease
	if lease <= 0 {
		lease = 2 * time.Minute
	}
	interval := lease / 3
	if interval < time.Second {
		return time.Second
	}
	return interval
}

func (s *DynamoDBStateStore) validate() error {
	if s == nil || s.Client == nil || s.TableName == "" {
		return fmt.Errorf("DynamoDB client and table name are required")
	}
	return nil
}

func (s *DynamoDBStateStore) validateLease(stream, shard, owner string, duration time.Duration) error {
	if err := s.validate(); err != nil {
		return err
	}
	if stream == "" || shard == "" || owner == "" || duration < 0 {
		return fmt.Errorf("stream, shard, owner, and a non-negative lease duration are required")
	}
	return nil
}

func checkpointRecordKey(stream, shard string) string { return "checkpoint#" + stream + "#" + shard }
func eventRecordKey(id string) string                 { return "event#" + id }

func stateKey(key string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{"record_key": &types.AttributeValueMemberS{Value: key}}
}

func stringAttribute(item map[string]types.AttributeValue, key string) string {
	if value, ok := item[key].(*types.AttributeValueMemberS); ok {
		return value.Value
	}
	return ""
}

func isConditionalFailure(err error) bool {
	var conditional *types.ConditionalCheckFailedException
	return errors.As(err, &conditional)
}

func randomToken() (string, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(token[:]), nil
}

func NewConsumerOwnerID() (string, error) { return randomToken() }
