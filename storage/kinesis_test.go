package storage

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/kinesis/types"
	"twitch-security/domain"
)

type fakeKinesisClient struct {
	putInput      *kinesis.PutRecordInput
	getRecords    *kinesis.GetRecordsOutput
	iteratorType  types.ShardIteratorType
	startSequence string
}

func (c *fakeKinesisClient) ListShards(context.Context, *kinesis.ListShardsInput, ...func(*kinesis.Options)) (*kinesis.ListShardsOutput, error) {
	return &kinesis.ListShardsOutput{Shards: []types.Shard{{ShardId: aws.String("shard-1")}}}, nil
}

func (c *fakeKinesisClient) GetShardIterator(_ context.Context, input *kinesis.GetShardIteratorInput, _ ...func(*kinesis.Options)) (*kinesis.GetShardIteratorOutput, error) {
	c.iteratorType = input.ShardIteratorType
	c.startSequence = aws.ToString(input.StartingSequenceNumber)
	return &kinesis.GetShardIteratorOutput{ShardIterator: aws.String("iterator-1")}, nil
}

type rotatingLeaseCheckpointStore struct {
	loads    int
	acquires int
	saves    int
	sequence string
	cancel   context.CancelFunc
}

type recordingLeaseStore struct {
	mu       sync.Mutex
	acquires int
	saves    int
	cancel   context.CancelFunc
}

func (s *recordingLeaseStore) Load(context.Context, string, string) (string, bool, error) {
	return "", false, nil
}
func (s *recordingLeaseStore) Save(context.Context, string, string, string) error {
	return errors.New("Save should not be used when shard leasing is enabled")
}
func (s *recordingLeaseStore) AcquireLease(context.Context, string, string, string, time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acquires++
	return true, nil
}
func (s *recordingLeaseStore) SaveOwned(context.Context, string, string, string, string) error {
	s.saves++
	s.cancel()
	return nil
}
func (s *recordingLeaseStore) ReleaseLease(context.Context, string, string, string) error { return nil }

type delayedRemediator struct{ delay time.Duration }

func (r delayedRemediator) ProcessAlert(ctx context.Context, vuln domain.Vulnerability) (*domain.AgentState, error) {
	timer := time.NewTimer(r.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return &domain.AgentState{TaskID: vuln.ID, CurrentPhase: "COMPLETED"}, nil
	}
}

func (s *rotatingLeaseCheckpointStore) Load(context.Context, string, string) (string, bool, error) {
	s.loads++
	if s.loads == 1 {
		return "100", true, nil
	}
	return "200", true, nil
}

func (s *rotatingLeaseCheckpointStore) Save(context.Context, string, string, string) error {
	return errors.New("Save should not be used when shard leasing is enabled")
}

func (s *rotatingLeaseCheckpointStore) AcquireLease(context.Context, string, string, string, time.Duration) (bool, error) {
	s.acquires++
	return s.acquires > 1, nil
}

func (s *rotatingLeaseCheckpointStore) SaveOwned(_ context.Context, _, _, _, sequence string) error {
	s.saves++
	s.sequence = sequence
	s.cancel()
	return nil
}

func (s *rotatingLeaseCheckpointStore) ReleaseLease(context.Context, string, string, string) error {
	return nil
}

func TestKinesisConsumerReloadsCheckpointAfterAcquiringLease(t *testing.T) {
	data, err := json.Marshal(SecurityTelemetryEvent{EventID: "TX-lease", Payload: "alert"})
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeKinesisClient{getRecords: &kinesis.GetRecordsOutput{
		Records: []types.Record{{Data: data, SequenceNumber: aws.String("201")}},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	checkpoints := &rotatingLeaseCheckpointStore{cancel: cancel}
	consumer := &KinesisConsumer{
		Client: client, StreamName: "security-events", Buffer: &TelemetryBuffer{Remediator: &captureRemediator{}},
		Checkpoints: checkpoints, OwnerID: "consumer-1", LeaseDuration: time.Minute,
		PollInterval: time.Millisecond,
	}
	if err := consumer.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if checkpoints.loads < 2 || checkpoints.sequence != "201" || client.startSequence != "200" || client.iteratorType != types.ShardIteratorTypeAfterSequenceNumber {
		t.Fatalf("lease takeover did not resume from latest checkpoint: loads=%d saved=%q iterator=%q sequence=%q", checkpoints.loads, checkpoints.sequence, client.iteratorType, client.startSequence)
	}
}

func TestKinesisConsumerRenewsLeaseDuringLongRemediation(t *testing.T) {
	data, err := json.Marshal(SecurityTelemetryEvent{EventID: "TX-lease-heartbeat", Payload: "alert"})
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeKinesisClient{getRecords: &kinesis.GetRecordsOutput{
		Records: []types.Record{{Data: data, SequenceNumber: aws.String("301")}},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	checkpoints := &recordingLeaseStore{cancel: cancel}
	consumer := &KinesisConsumer{
		Client: client, StreamName: "security-events", Buffer: &TelemetryBuffer{Remediator: delayedRemediator{delay: 1200 * time.Millisecond}},
		Checkpoints: checkpoints, OwnerID: "consumer-lease-heartbeat", LeaseDuration: 30 * time.Millisecond,
		MaxAttempts: 1,
	}
	if err := consumer.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	checkpoints.mu.Lock()
	acquires := checkpoints.acquires
	checkpoints.mu.Unlock()
	if acquires < 2 || checkpoints.saves != 1 {
		t.Fatalf("lease renewals=%d saves=%d, want heartbeat renewal and one checkpoint", acquires-1, checkpoints.saves)
	}
}

func (c *fakeKinesisClient) GetRecords(context.Context, *kinesis.GetRecordsInput, ...func(*kinesis.Options)) (*kinesis.GetRecordsOutput, error) {
	return c.getRecords, nil
}

func (c *fakeKinesisClient) PutRecord(_ context.Context, input *kinesis.PutRecordInput, _ ...func(*kinesis.Options)) (*kinesis.PutRecordOutput, error) {
	c.putInput = input
	return &kinesis.PutRecordOutput{}, nil
}

type captureRemediator struct {
	got domain.Vulnerability
}

func (r *captureRemediator) ProcessAlert(_ context.Context, vuln domain.Vulnerability) (*domain.AgentState, error) {
	r.got = vuln
	return &domain.AgentState{TaskID: vuln.ID, CurrentPhase: "COMPLETED"}, nil
}

type cancelingCheckpointStore struct {
	cancel      context.CancelFunc
	sequence    string
	saves       int
	cancelAfter int
}

type recordingCheckpointStore struct {
	saves int
}

func (s *recordingCheckpointStore) Load(context.Context, string, string) (string, bool, error) {
	return "", false, nil
}

func (s *recordingCheckpointStore) Save(context.Context, string, string, string) error {
	s.saves++
	return nil
}

type failingRemediator struct{}

func (failingRemediator) ProcessAlert(context.Context, domain.Vulnerability) (*domain.AgentState, error) {
	return nil, errors.New("test remediation failure")
}

func (s *cancelingCheckpointStore) Load(context.Context, string, string) (string, bool, error) {
	return "", false, nil
}

func (s *cancelingCheckpointStore) Save(_ context.Context, _, _, sequence string) error {
	s.sequence = sequence
	s.saves++
	if s.cancelAfter == 0 || s.saves >= s.cancelAfter {
		s.cancel()
	}
	return nil
}

func TestKinesisPublisherEncodesTelemetryRecord(t *testing.T) {
	client := &fakeKinesisClient{}
	event := SecurityTelemetryEvent{EventID: "TX-1", AWSAccountID: "123456789012", Payload: "finding"}
	if err := (KinesisPublisher{Client: client, StreamName: "security-events"}).Publish(context.Background(), event); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if client.putInput == nil || aws.ToString(client.putInput.PartitionKey) != event.AWSAccountID {
		t.Fatalf("unexpected PutRecord input: %#v", client.putInput)
	}
	var got SecurityTelemetryEvent
	if err := json.Unmarshal(client.putInput.Data, &got); err != nil {
		t.Fatalf("published data is not an event: %v", err)
	}
	if got.EventID != event.EventID || got.Timestamp.IsZero() {
		t.Fatalf("published event was not normalized: %+v", got)
	}
}

func TestKinesisConsumerCheckpointsOnlyAfterSuccessfulProcessing(t *testing.T) {
	data, err := json.Marshal(SecurityTelemetryEvent{
		EventID: "TX-42", Payload: "dependency alert", Dependency: "example.com/lib", FixedVersion: "v1.1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeKinesisClient{getRecords: &kinesis.GetRecordsOutput{
		Records:           []types.Record{{Data: data, SequenceNumber: aws.String("123"), ApproximateArrivalTimestamp: aws.Time(time.Now())}},
		NextShardIterator: aws.String("iterator-2"),
	}}
	remediator := &captureRemediator{}
	ctx, cancel := context.WithCancel(context.Background())
	checkpoints := &cancelingCheckpointStore{cancel: cancel}
	consumer := &KinesisConsumer{
		Client: client, StreamName: "security-events", Buffer: &TelemetryBuffer{Remediator: remediator},
		Checkpoints: checkpoints, PollInterval: time.Millisecond,
	}
	if err := consumer.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if checkpoints.sequence != "123" || remediator.got.ID != "TX-42" {
		t.Fatalf("record was not processed and checkpointed: sequence=%q vuln=%+v", checkpoints.sequence, remediator.got)
	}
	if client.iteratorType != types.ShardIteratorTypeTrimHorizon {
		t.Fatalf("new shard started at %q, want TRIM_HORIZON", client.iteratorType)
	}
}

func TestKinesisConsumerCheckpointsDuplicateWithoutRemediatingAgain(t *testing.T) {
	data, err := json.Marshal(SecurityTelemetryEvent{
		EventID: "TX-duplicate", Payload: "dependency alert", Dependency: "example.com/lib", FixedVersion: "v1.1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeKinesisClient{getRecords: &kinesis.GetRecordsOutput{
		Records: []types.Record{
			{Data: data, SequenceNumber: aws.String("123")},
			{Data: data, SequenceNumber: aws.String("124")},
		},
		NextShardIterator: aws.String("iterator-2"),
	}}
	remediator := &countingRemediator{}
	ctx, cancel := context.WithCancel(context.Background())
	checkpoints := &cancelingCheckpointStore{cancel: cancel, cancelAfter: 2}
	index, err := NewIdempotencyIndex(t.TempDir() + "/idempotency.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	consumer := &KinesisConsumer{
		Client: client, StreamName: "security-events",
		Buffer:      &TelemetryBuffer{Remediator: remediator, Idempotency: index},
		Checkpoints: checkpoints, PollInterval: time.Millisecond,
	}
	if err := consumer.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if remediator.calls != 1 {
		t.Fatalf("remediator calls = %d, want 1 for the duplicate delivery", remediator.calls)
	}
	if checkpoints.saves != 2 || checkpoints.sequence != "124" {
		t.Fatalf("duplicate record checkpoint state: saves=%d sequence=%q, want 2 and 124", checkpoints.saves, checkpoints.sequence)
	}
}

func TestFileKinesisCheckpointStorePersistsLatestSequence(t *testing.T) {
	store, err := NewFileKinesisCheckpointStore(t.TempDir() + "/checkpoints.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := store.Save(ctx, "stream", "shard", "100"); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, "stream", "shard", "101"); err != nil {
		t.Fatal(err)
	}
	sequence, found, err := store.Load(ctx, "stream", "shard")
	if err != nil || !found || sequence != "101" {
		t.Fatalf("Load() = (%q, %v, %v), want (101, true, nil)", sequence, found, err)
	}
}

func TestKinesisConsumerDoesNotCheckpointFailedEvent(t *testing.T) {
	data, err := json.Marshal(SecurityTelemetryEvent{EventID: "TX-fail", Payload: "alert"})
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeKinesisClient{getRecords: &kinesis.GetRecordsOutput{
		Records: []types.Record{{Data: data, SequenceNumber: aws.String("456")}},
	}}
	checkpoints := &recordingCheckpointStore{}
	consumer := &KinesisConsumer{
		Client: client, StreamName: "security-events", Buffer: &TelemetryBuffer{Remediator: failingRemediator{}},
		Checkpoints: checkpoints, MaxAttempts: 1,
	}
	if err := consumer.Run(context.Background()); err == nil {
		t.Fatal("Run() succeeded despite remediation failure")
	}
	if checkpoints.saves != 0 {
		t.Fatalf("failed event was checkpointed %d times", checkpoints.saves)
	}
}

type recordingFailureSink struct {
	records []KinesisDeadLetterRecord
	err     error
}

func (s *recordingFailureSink) SendFailure(_ context.Context, record KinesisDeadLetterRecord) error {
	s.records = append(s.records, record)
	return s.err
}

func TestKinesisConsumerRetriesAndDeadLettersBeforeCheckpoint(t *testing.T) {
	data, err := json.Marshal(SecurityTelemetryEvent{EventID: "TX-poison", Payload: "alert"})
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeKinesisClient{getRecords: &kinesis.GetRecordsOutput{
		Records: []types.Record{{Data: data, SequenceNumber: aws.String("789")}},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	checkpoints := &cancelingCheckpointStore{cancel: cancel}
	sink := &recordingFailureSink{}
	remediator := &countingRemediator{fail: true}
	consumer := &KinesisConsumer{
		Client: client, StreamName: "security-events", Buffer: &TelemetryBuffer{Remediator: remediator},
		Checkpoints: checkpoints, FailureSink: sink, MaxAttempts: 3, RetryBackoff: time.Nanosecond,
		PollInterval: time.Millisecond,
	}
	if err := consumer.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if remediator.calls != 3 || len(sink.records) != 1 {
		t.Fatalf("processing attempts=%d DLQ records=%d, want 3 and 1", remediator.calls, len(sink.records))
	}
	if sink.records[0].Sequence != "789" || sink.records[0].Event == nil || sink.records[0].Attempts != 3 {
		t.Fatalf("unexpected DLQ record: %+v", sink.records[0])
	}
	if checkpoints.saves != 1 || checkpoints.sequence != "789" {
		t.Fatalf("DLQ record was not checkpointed after handoff: saves=%d sequence=%q", checkpoints.saves, checkpoints.sequence)
	}
}

func TestKinesisConsumerDoesNotCheckpointWhenDeadLetterHandoffFails(t *testing.T) {
	data, err := json.Marshal(SecurityTelemetryEvent{EventID: "TX-dlq-fail", Payload: "alert"})
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeKinesisClient{getRecords: &kinesis.GetRecordsOutput{
		Records: []types.Record{{Data: data, SequenceNumber: aws.String("790")}},
	}}
	checkpoints := &recordingCheckpointStore{}
	sink := &recordingFailureSink{err: errors.New("SQS unavailable")}
	consumer := &KinesisConsumer{
		Client: client, StreamName: "security-events", Buffer: &TelemetryBuffer{Remediator: failingRemediator{}},
		Checkpoints: checkpoints, FailureSink: sink, MaxAttempts: 1,
	}
	if err := consumer.Run(context.Background()); err == nil {
		t.Fatal("Run() succeeded despite failed DLQ handoff")
	}
	if checkpoints.saves != 0 {
		t.Fatalf("checkpoint saves=%d after failed DLQ handoff, want 0", checkpoints.saves)
	}
}

func TestIdempotencyIndexDistinguishesInflightAndCompletedEvents(t *testing.T) {
	path := t.TempDir() + "/idempotency.jsonl"
	index, err := NewIdempotencyIndex(path)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := index.Begin("event-1")
	if err != nil || !claimed {
		t.Fatalf("first Begin() = (%v, %v), want (true, nil)", claimed, err)
	}
	if _, err := index.Begin("event-1"); !errors.Is(err, ErrEventInFlight) {
		t.Fatalf("concurrent Begin() error = %v, want ErrEventInFlight", err)
	}
	if err := index.Complete("event-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewIdempotencyIndex(path)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err = reloaded.Begin("event-1")
	if err != nil || claimed {
		t.Fatalf("Begin() after reload = (%v, %v), want (false, nil)", claimed, err)
	}
}
