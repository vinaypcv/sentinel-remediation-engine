package storage

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

func TestAWSIntegrationConfiguredStagingResources(t *testing.T) {
	if os.Getenv("SENTINEL_ENABLE_AWS_INTEGRATION_TESTS") != "1" {
		t.Skip("set SENTINEL_ENABLE_AWS_INTEGRATION_TESTS=1 to use dedicated AWS staging resources")
	}
	stream := os.Getenv("SENTINEL_TEST_KINESIS_STREAM")
	table := os.Getenv("SENTINEL_TEST_DYNAMODB_TABLE")
	queueURL := os.Getenv("SENTINEL_TEST_DLQ_URL")
	if stream == "" || table == "" || queueURL == "" {
		t.Fatal("SENTINEL_TEST_KINESIS_STREAM, SENTINEL_TEST_DYNAMODB_TABLE, and SENTINEL_TEST_DLQ_URL must identify dedicated staging resources")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	awsConfig, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatalf("load AWS configuration: %v", err)
	}
	if _, err := kinesis.NewFromConfig(awsConfig).ListShards(ctx, &kinesis.ListShardsInput{StreamName: &stream}); err != nil {
		t.Fatalf("list staging Kinesis stream shards: %v", err)
	}

	stateStore, err := NewDynamoDBStateStore(dynamodb.NewFromConfig(awsConfig), table)
	if err != nil {
		t.Fatal(err)
	}
	eventID := fmt.Sprintf("integration-%d", time.Now().UnixNano())
	testShard := "integration-" + eventID
	leaseOwner := "integration-owner-" + eventID
	acquired, err := stateStore.AcquireLease(ctx, stream, testShard, leaseOwner, 30*time.Second)
	if err != nil || !acquired {
		t.Fatalf("acquire staging shard lease = (%v, %v), want (true, nil)", acquired, err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cleanupCancel()
		_ = stateStore.ReleaseLease(cleanupCtx, stream, testShard, leaseOwner)
		_, _ = stateStore.Client.DeleteItem(cleanupCtx, &dynamodb.DeleteItemInput{
			TableName: &table,
			Key:       stateKey(checkpointRecordKey(stream, testShard)),
		})
		_, _ = stateStore.Client.DeleteItem(cleanupCtx, &dynamodb.DeleteItemInput{
			TableName: &table,
			Key:       stateKey(eventRecordKey(eventID)),
		})
	}()
	if err := stateStore.SaveOwned(ctx, stream, testShard, leaseOwner, "integration-sequence"); err != nil {
		t.Fatalf("save staging checkpoint under lease: %v", err)
	}
	claimed, err := stateStore.Claim(ctx, eventID)
	if err != nil || !claimed {
		t.Fatalf("claim staging idempotency key = (%v, %v), want (true, nil)", claimed, err)
	}
	if err := stateStore.CompleteContext(ctx, eventID, time.Now().UTC()); err != nil {
		t.Fatalf("complete staging idempotency key: %v", err)
	}
	claimed, err = stateStore.Claim(ctx, eventID)
	if err != nil || claimed {
		t.Fatalf("replayed staging idempotency key = (%v, %v), want (false, nil)", claimed, err)
	}

	sink := SQSKinesisDeadLetterSink{Client: sqs.NewFromConfig(awsConfig), QueueURL: queueURL}
	if err := sink.SendFailure(ctx, KinesisDeadLetterRecord{
		StreamName: stream, ShardID: "integration-test", Sequence: eventID,
		RawRecord: []byte("integration-test-only"), Attempts: 1,
		Error: "staging integration check", FailedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("send staging DLQ marker: %v", err)
	}
}
