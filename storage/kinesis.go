package storage

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/kinesis/types"
)

type KinesisAPI interface {
	ListShards(context.Context, *kinesis.ListShardsInput, ...func(*kinesis.Options)) (*kinesis.ListShardsOutput, error)
	GetShardIterator(context.Context, *kinesis.GetShardIteratorInput, ...func(*kinesis.Options)) (*kinesis.GetShardIteratorOutput, error)
	GetRecords(context.Context, *kinesis.GetRecordsInput, ...func(*kinesis.Options)) (*kinesis.GetRecordsOutput, error)
	PutRecord(context.Context, *kinesis.PutRecordInput, ...func(*kinesis.Options)) (*kinesis.PutRecordOutput, error)
}

type KinesisPublisher struct {
	Client     KinesisAPI
	StreamName string
}

func (p KinesisPublisher) Publish(ctx context.Context, event SecurityTelemetryEvent) error {
	if p.Client == nil || p.StreamName == "" {
		return fmt.Errorf("Kinesis client and stream name are required")
	}
	if event.EventID == "" {
		return fmt.Errorf("event ID is required")
	}
	if len(event.EventID) > 256 {
		return fmt.Errorf("event ID exceeds 256 bytes")
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode telemetry event: %w", err)
	}
	partitionKey := event.AWSAccountID
	if partitionKey == "" {
		partitionKey = event.Microservice
	}
	if partitionKey == "" {
		partitionKey = event.EventID
	}
	_, err = p.Client.PutRecord(ctx, &kinesis.PutRecordInput{
		Data:         data,
		PartitionKey: aws.String(partitionKey),
		StreamName:   aws.String(p.StreamName),
	})
	if err != nil {
		return fmt.Errorf("publish event %q to Kinesis: %w", event.EventID, err)
	}
	return nil
}

type KinesisCheckpointStore interface {
	Load(context.Context, string, string) (string, bool, error)
	Save(context.Context, string, string, string) error
}

type FileKinesisCheckpointStore struct {
	mu          sync.Mutex
	Path        string
	loaded      bool
	loadErr     error
	checkpoints map[string]string
}

func NewFileKinesisCheckpointStore(path string) (*FileKinesisCheckpointStore, error) {
	if path == "" {
		return nil, fmt.Errorf("checkpoint path is required")
	}
	return &FileKinesisCheckpointStore{Path: path}, nil
}

func (s *FileKinesisCheckpointStore) Load(ctx context.Context, stream, shard string) (string, bool, error) {
	if err := ctx.Err(); err != nil {
		return "", false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		return "", false, err
	}
	sequence, found := s.checkpoints[checkpointKey(stream, shard)]
	return sequence, found, nil
}

func (s *FileKinesisCheckpointStore) Save(ctx context.Context, stream, shard, sequence string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if stream == "" || shard == "" || sequence == "" {
		return fmt.Errorf("stream, shard, and sequence are required for checkpoint")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		return err
	}
	file, err := os.OpenFile(s.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	record := struct {
		Stream   string    `json:"stream"`
		Shard    string    `json:"shard"`
		Sequence string    `json:"sequence"`
		SavedAt  time.Time `json:"saved_at"`
	}{Stream: stream, Shard: shard, Sequence: sequence, SavedAt: time.Now().UTC()}
	data, err := json.Marshal(record)
	if err == nil {
		_, err = file.Write(append(data, '\n'))
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	s.checkpoints[checkpointKey(stream, shard)] = sequence
	return nil
}

func (s *FileKinesisCheckpointStore) loadLocked() error {
	if s.loaded {
		return s.loadErr
	}
	s.loaded = true
	s.checkpoints = make(map[string]string)
	file, err := os.Open(s.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		s.loadErr = err
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		var record struct {
			Stream   string `json:"stream"`
			Shard    string `json:"shard"`
			Sequence string `json:"sequence"`
		}
		if json.Unmarshal(scanner.Bytes(), &record) == nil && record.Stream != "" && record.Shard != "" && record.Sequence != "" {
			s.checkpoints[checkpointKey(record.Stream, record.Shard)] = record.Sequence
		}
	}
	s.loadErr = scanner.Err()
	return s.loadErr
}

func checkpointKey(stream, shard string) string {
	return stream + "\x00" + shard
}

type KinesisConsumer struct {
	Client           KinesisAPI
	StreamName       string
	Buffer           *TelemetryBuffer
	Checkpoints      KinesisCheckpointStore
	FailureSink      KinesisFailureSink
	OwnerID          string
	LeaseDuration    time.Duration
	MaxAttempts      int
	RetryBackoff     time.Duration
	PollInterval     time.Duration
	MaxRecords       int32
	StartingPosition types.ShardIteratorType
}

type kinesisShardCursor struct {
	iterator string
	sequence string
	started  bool
	done     bool
}

type KinesisShardLeaseStore interface {
	AcquireLease(context.Context, string, string, string, time.Duration) (bool, error)
	SaveOwned(context.Context, string, string, string, string) error
	ReleaseLease(context.Context, string, string, string) error
}

func (c *KinesisConsumer) Run(ctx context.Context) error {
	if c.Client == nil || c.Buffer == nil || c.Checkpoints == nil || c.StreamName == "" {
		return fmt.Errorf("Kinesis client, stream, telemetry buffer, and checkpoint store are required")
	}
	pollInterval := c.PollInterval
	if pollInterval <= 0 {
		pollInterval = time.Second
	}
	maxRecords := c.MaxRecords
	if maxRecords <= 0 || maxRecords > 10000 {
		maxRecords = 1000
	}
	startPosition := c.StartingPosition
	if startPosition == "" {
		startPosition = types.ShardIteratorTypeTrimHorizon
	}
	if startPosition != types.ShardIteratorTypeTrimHorizon && startPosition != types.ShardIteratorTypeLatest {
		return fmt.Errorf("unsupported initial Kinesis position %q; use TRIM_HORIZON or LATEST", startPosition)
	}
	leaseStore, usesLeases := c.Checkpoints.(KinesisShardLeaseStore)
	ownerID := c.OwnerID
	if usesLeases && ownerID == "" {
		var err error
		ownerID, err = randomToken()
		if err != nil {
			return fmt.Errorf("create consumer owner ID: %w", err)
		}
	}
	leaseDuration := c.LeaseDuration
	if leaseDuration <= 0 {
		leaseDuration = time.Minute
	}
	maxAttempts := c.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 3
	}
	if maxAttempts > 10 {
		return fmt.Errorf("maximum record attempts cannot exceed 10")
	}
	retryBackoff := c.RetryBackoff
	if retryBackoff <= 0 {
		retryBackoff = time.Second
	}

	cursors := make(map[string]*kinesisShardCursor)
	var leaseManager *shardLeaseManager
	if usesLeases {
		leaseManager = newShardLeaseManager(ctx, leaseStore, c.StreamName, ownerID, leaseDuration)
		leaseManager.Start()
		defer leaseManager.ReleaseAll()
	}
	lastDiscovery := time.Time{}
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		if lastDiscovery.IsZero() || time.Since(lastDiscovery) >= 30*time.Second {
			shards, err := c.listShards(ctx)
			if err != nil {
				return err
			}
			for _, shard := range shards {
				shardID := aws.ToString(shard.ShardId)
				if shardID == "" || cursors[shardID] != nil {
					continue
				}
				sequence, found, err := c.Checkpoints.Load(ctx, c.StreamName, shardID)
				if err != nil {
					return fmt.Errorf("load checkpoint for shard %s: %w", shardID, err)
				}
				cursor := &kinesisShardCursor{sequence: sequence, started: found}
				cursors[shardID] = cursor
			}
			lastDiscovery = time.Now()
		}

		shardIDs := make([]string, 0, len(cursors))
		for shardID := range cursors {
			shardIDs = append(shardIDs, shardID)
		}
		for _, shardID := range shardIDs {
			cursor := cursors[shardID]
			if cursor.done {
				continue
			}
			recordCtx := ctx
			if usesLeases {
				acquired, reacquired, err := leaseManager.Acquire(ctx, shardID)
				if err != nil {
					return fmt.Errorf("acquire lease for shard %s: %w", shardID, err)
				}
				if !acquired {
					cursor.iterator = ""
					continue
				}
				recordCtx = leaseManager.Context(shardID)
				if reacquired {
					sequence, found, err := c.Checkpoints.Load(ctx, c.StreamName, shardID)
					if err != nil {
						return fmt.Errorf("reload checkpoint after acquiring shard %s lease: %w", shardID, err)
					}
					cursor.sequence = sequence
					cursor.started = found
					cursor.iterator = ""
				}
			}
			if cursor.iterator == "" {
				iterator, err := c.createIterator(recordCtx, shardID, cursor, startPosition)
				if err != nil {
					return fmt.Errorf("create iterator for shard %s: %w", shardID, err)
				}
				if iterator == "" {
					cursor.done = true
					if usesLeases {
						_ = leaseManager.Release(context.Background(), shardID)
					}
					continue
				}
				cursor.iterator = iterator
			}
			output, err := c.Client.GetRecords(recordCtx, &kinesis.GetRecordsInput{
				Limit: aws.Int32(maxRecords), ShardIterator: aws.String(cursor.iterator),
			})
			if err != nil {
				cursor.iterator = ""
				return fmt.Errorf("read Kinesis shard %s: %w", shardID, err)
			}
			for _, record := range output.Records {
				sequence := aws.ToString(record.SequenceNumber)
				GlobalMetrics.IncrementIngest()
				event, processErr := decodeTelemetryRecord(record.Data, record.ApproximateArrivalTimestamp, c.StreamName, shardID, sequence)
				processed := false
				attempts := maxAttempts
				if processErr == nil {
					processed, attempts, processErr = c.processWithRetries(recordCtx, event, maxAttempts, retryBackoff)
				} else {
					attempts = 1
				}
				if processErr != nil {
					if c.FailureSink == nil {
						cursor.iterator = ""
						return fmt.Errorf("process Kinesis record %s/%s: %w", shardID, sequence, processErr)
					}
					failure := KinesisDeadLetterRecord{
						StreamName: c.StreamName,
						ShardID:    shardID,
						Sequence:   sequence,
						RawRecord:  record.Data,
						Attempts:   attempts,
						Error:      processErr.Error(),
						FailedAt:   time.Now().UTC(),
					}
					if event.EventID != "" {
						failure.Event = &event
					}
					if err := c.FailureSink.SendFailure(recordCtx, failure); err != nil {
						cursor.iterator = ""
						return fmt.Errorf("process Kinesis record %s/%s failed and DLQ handoff failed: %w (processing error: %v)", shardID, sequence, err, processErr)
					}
					GlobalMetrics.RecordDeadLetter()
					fmt.Fprintf(os.Stderr, "Kinesis record sent to DLQ after %d attempts: %s/%s\n", attempts, shardID, sequence)
				}
				if !processed && processErr == nil {
					fmt.Fprintf(os.Stderr, "Kinesis duplicate event skipped: %s\n", event.EventID)
				}
				var checkpointErr error
				if usesLeases {
					checkpointErr = leaseStore.SaveOwned(recordCtx, c.StreamName, shardID, ownerID, sequence)
				} else {
					checkpointErr = c.Checkpoints.Save(ctx, c.StreamName, shardID, sequence)
				}
				if checkpointErr != nil {
					cursor.iterator = ""
					return fmt.Errorf("save checkpoint for shard %s at %s: %w", shardID, sequence, checkpointErr)
				}
				cursor.sequence = sequence
				cursor.started = true
			}
			cursor.iterator = aws.ToString(output.NextShardIterator)
			if cursor.iterator == "" {
				cursor.done = true
				if usesLeases {
					_ = leaseManager.Release(context.Background(), shardID)
				}
			}
		}
		if err := sleepContext(ctx, pollInterval); err != nil {
			return nil
		}
	}
}

func (c *KinesisConsumer) processWithRetries(ctx context.Context, event SecurityTelemetryEvent, maxAttempts int, backoff time.Duration) (bool, int, error) {
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		processed, err := c.Buffer.processEventWithResult(ctx, event, false)
		if err == nil {
			return processed, attempt, nil
		}
		lastErr = err
		if attempt == maxAttempts {
			break
		}
		delay := backoff * time.Duration(1<<(attempt-1))
		if delay > 30*time.Second {
			delay = 30 * time.Second
		}
		if err := sleepContext(ctx, delay); err != nil {
			return false, attempt, err
		}
	}
	return false, maxAttempts, lastErr
}

func decodeTelemetryRecord(data []byte, arrival *time.Time, stream, shard, sequence string) (SecurityTelemetryEvent, error) {
	var event SecurityTelemetryEvent
	if err := json.Unmarshal(data, &event); err != nil {
		return event, fmt.Errorf("decode Kinesis record %s/%s: %w", shard, sequence, err)
	}
	if event.EventID == "" {
		event.EventID = stableKinesisEventID(stream, shard, sequence)
	}
	if event.Timestamp.IsZero() && arrival != nil {
		event.Timestamp = *arrival
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	return event, nil
}

func (c *KinesisConsumer) listShards(ctx context.Context) ([]types.Shard, error) {
	var shards []types.Shard
	var nextToken *string
	for {
		input := &kinesis.ListShardsInput{StreamName: aws.String(c.StreamName)}
		if nextToken != nil {
			input = &kinesis.ListShardsInput{NextToken: nextToken}
		}
		output, err := c.Client.ListShards(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("list Kinesis shards: %w", err)
		}
		shards = append(shards, output.Shards...)
		nextToken = output.NextToken
		if nextToken == nil {
			return shards, nil
		}
	}
}

func (c *KinesisConsumer) createIterator(ctx context.Context, shardID string, cursor *kinesisShardCursor, startPosition types.ShardIteratorType) (string, error) {
	input := &kinesis.GetShardIteratorInput{
		StreamName: aws.String(c.StreamName),
		ShardId:    aws.String(shardID),
	}
	if cursor.started {
		input.ShardIteratorType = types.ShardIteratorTypeAfterSequenceNumber
		input.StartingSequenceNumber = aws.String(cursor.sequence)
	} else {
		input.ShardIteratorType = startPosition
	}
	output, err := c.Client.GetShardIterator(ctx, input)
	if err != nil {
		return "", err
	}
	return aws.ToString(output.ShardIterator), nil
}

func stableKinesisEventID(stream, shard, sequence string) string {
	digest := sha256.Sum256([]byte(stream + "\x00" + shard + "\x00" + sequence))
	return "kinesis-" + hex.EncodeToString(digest[:])
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
