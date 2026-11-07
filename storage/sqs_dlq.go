package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

type KinesisDeadLetterRecord struct {
	StreamName string                  `json:"stream_name"`
	ShardID    string                  `json:"shard_id"`
	Sequence   string                  `json:"sequence_number"`
	Event      *SecurityTelemetryEvent `json:"event,omitempty"`
	RawRecord  []byte                  `json:"raw_record"`
	Attempts   int                     `json:"attempts"`
	Error      string                  `json:"error"`
	FailedAt   time.Time               `json:"failed_at"`
}

type KinesisFailureSink interface {
	SendFailure(context.Context, KinesisDeadLetterRecord) error
}

type SQSAPI interface {
	SendMessage(context.Context, *sqs.SendMessageInput, ...func(*sqs.Options)) (*sqs.SendMessageOutput, error)
}

type SQSKinesisDeadLetterSink struct {
	Client   SQSAPI
	QueueURL string
}

func (s SQSKinesisDeadLetterSink) SendFailure(ctx context.Context, record KinesisDeadLetterRecord) error {
	if s.Client == nil || s.QueueURL == "" {
		return fmt.Errorf("SQS client and dead-letter queue URL are required")
	}
	if record.FailedAt.IsZero() {
		record.FailedAt = time.Now().UTC()
	}
	body, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode dead-letter record: %w", err)
	}
	if len(body) > 1024*1024 {
		return fmt.Errorf("dead-letter record is %d bytes; SQS message limit is 1 MiB", len(body))
	}
	_, err = s.Client.SendMessage(ctx, &sqs.SendMessageInput{
		QueueUrl:    aws.String(s.QueueURL),
		MessageBody: aws.String(string(body)),
	})
	if err != nil {
		return fmt.Errorf("send record to SQS dead-letter queue: %w", err)
	}
	return nil
}
