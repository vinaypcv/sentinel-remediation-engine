package storage

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type fakeDynamoDBClient struct {
	gets    []*dynamodb.GetItemInput
	puts    []*dynamodb.PutItemInput
	updates []*dynamodb.UpdateItemInput
	deletes []*dynamodb.DeleteItemInput
}

func (c *fakeDynamoDBClient) GetItem(_ context.Context, input *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	c.gets = append(c.gets, input)
	return &dynamodb.GetItemOutput{Item: map[string]types.AttributeValue{}}, nil
}

func (c *fakeDynamoDBClient) PutItem(_ context.Context, input *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	c.puts = append(c.puts, input)
	return &dynamodb.PutItemOutput{}, nil
}

func (c *fakeDynamoDBClient) UpdateItem(_ context.Context, input *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	c.updates = append(c.updates, input)
	return &dynamodb.UpdateItemOutput{}, nil
}

func (c *fakeDynamoDBClient) DeleteItem(_ context.Context, input *dynamodb.DeleteItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	c.deletes = append(c.deletes, input)
	return &dynamodb.DeleteItemOutput{}, nil
}

func TestDynamoDBStateStoreUsesConditionalShardLeases(t *testing.T) {
	client := &fakeDynamoDBClient{}
	store, err := NewDynamoDBStateStore(client, "state")
	if err != nil {
		t.Fatal(err)
	}
	acquired, err := store.AcquireLease(context.Background(), "events", "shard-1", "consumer-a", 30*time.Second)
	if err != nil || !acquired {
		t.Fatalf("AcquireLease() = (%v, %v), want (true, nil)", acquired, err)
	}
	if len(client.updates) != 1 || !strings.Contains(*client.updates[0].ConditionExpression, "lease_until < :now") {
		t.Fatalf("lease acquisition is not conditional: %+v", client.updates)
	}
	if err := store.SaveOwned(context.Background(), "events", "shard-1", "consumer-a", "123"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(*client.updates[1].ConditionExpression, "lease_owner = :owner") || !strings.Contains(*client.updates[1].ConditionExpression, "lease_until > :now") {
		t.Fatalf("owned checkpoint is not fenced by owner: %+v", client.updates[1])
	}
	if strings.Contains(*client.updates[0].UpdateExpression, "expires_at") {
		t.Fatal("DynamoDB TTL must not expire durable shard checkpoints")
	}
}

func TestDynamoDBIdempotencyUsesConditionalClaimAndRetentionTTL(t *testing.T) {
	client := &fakeDynamoDBClient{}
	store, err := NewDynamoDBStateStore(client, "state")
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.Claim(context.Background(), "event-1")
	if err != nil || !claimed {
		t.Fatalf("Claim() = (%v, %v), want (true, nil)", claimed, err)
	}
	if len(client.puts) != 1 || !strings.Contains(*client.puts[0].ConditionExpression, "attribute_not_exists(record_key)") {
		t.Fatalf("idempotency claim is not conditional: %+v", client.puts)
	}
	if _, ok := client.puts[0].Item["expires_at"]; !ok {
		t.Fatal("idempotency claim does not set a DynamoDB TTL attribute")
	}
	if err := store.CompleteContext(context.Background(), "event-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(client.updates) != 1 || !strings.Contains(*client.updates[0].ConditionExpression, "claim_token = :token") || !strings.Contains(*client.updates[0].ConditionExpression, "lease_until >= :now") {
		t.Fatalf("idempotency completion is not fenced by active claim: %+v", client.updates)
	}
}

func TestDynamoDBIdempotencyClaimCanBeRenewed(t *testing.T) {
	client := &fakeDynamoDBClient{}
	store, err := NewDynamoDBStateStore(client, "state")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Claim(context.Background(), "event-long-running"); err != nil {
		t.Fatal(err)
	}
	if err := store.RenewClaim(context.Background(), "event-long-running"); err != nil {
		t.Fatal(err)
	}
	if len(client.updates) != 1 || !strings.Contains(*client.updates[0].ConditionExpression, "claim_token = :token") || !strings.Contains(*client.updates[0].UpdateExpression, "expires_at = :lease_until") {
		t.Fatalf("claim renewal is not fenced/TTL-aware: %+v", client.updates)
	}
	if store.ClaimHeartbeatInterval() <= 0 {
		t.Fatal("DynamoDB claim heartbeat interval must be positive")
	}
}
