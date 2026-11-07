package storage

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

type fakeSQSClient struct {
	input *sqs.SendMessageInput
	err   error
}

func (c *fakeSQSClient) SendMessage(_ context.Context, input *sqs.SendMessageInput, _ ...func(*sqs.Options)) (*sqs.SendMessageOutput, error) {
	c.input = input
	return &sqs.SendMessageOutput{}, c.err
}

func TestSQSKinesisDeadLetterSinkPreservesFailedRecord(t *testing.T) {
	client := &fakeSQSClient{}
	record := KinesisDeadLetterRecord{
		StreamName: "stream", ShardID: "shard-1", Sequence: "42", RawRecord: []byte("raw-record"),
		Attempts: 3, Error: "verification failed",
	}
	if err := (SQSKinesisDeadLetterSink{Client: client, QueueURL: "https://sqs.example/queue"}).SendFailure(context.Background(), record); err != nil {
		t.Fatalf("SendFailure() error = %v", err)
	}
	if client.input == nil || aws.ToString(client.input.QueueUrl) != "https://sqs.example/queue" {
		t.Fatalf("unexpected SQS input: %+v", client.input)
	}
	var got KinesisDeadLetterRecord
	if err := json.Unmarshal([]byte(aws.ToString(client.input.MessageBody)), &got); err != nil {
		t.Fatalf("decode SQS message body: %v", err)
	}
	if got.Sequence != record.Sequence || got.Attempts != record.Attempts || base64.StdEncoding.EncodeToString(got.RawRecord) != base64.StdEncoding.EncodeToString(record.RawRecord) {
		t.Fatalf("dead-letter message lost source details: %+v", got)
	}
	if got.FailedAt.IsZero() {
		t.Fatal("dead-letter timestamp was not populated")
	}
}
