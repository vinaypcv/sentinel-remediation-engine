package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/kinesis/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"twitch-security/controller"
	"twitch-security/domain"
	"twitch-security/storage"
	"twitch-security/workflow"
)

type Runner struct {
	Engine    *workflow.RemediationEngine
	Generator workflow.PatchGenerator
	Verifier  workflow.PatchVerifier
	Ledger    *storage.ImmutableLedger
}

func (r *Runner) ProcessAlert(ctx context.Context, vuln domain.Vulnerability) (*domain.AgentState, error) {
	state, remediationErr := r.Engine.ExecuteGeneratedRemediation(ctx, vuln, r.Generator, r.Verifier)
	if state != nil && r.Ledger != nil {
		if err := r.Ledger.CommitStateToLedger(ctx, state); err != nil {
			return state, fmt.Errorf("remediation error: %v; commit audit record: %w", remediationErr, err)
		}
	}
	return state, remediationErr
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	metricsAddr := flag.String("metrics-addr", ":9090", "Prometheus metrics address; empty disables metrics.")
	simulate := flag.Bool("simulate", false, "Run one local remediation simulation or publish it to Kinesis.")
	simulatePoisoned := flag.Bool("simulate-poisoned", false, "Simulate invalid remediation metadata and record a rollback.")
	simulateForceFailure := flag.Bool("simulate-force-failure", false, "Simulate a missing dependency and record a rollback.")
	simulateRollbacks := flag.Bool("simulate-rollbacks", false, "Run both rollback simulations.")
	ledgerPath := flag.String("ledger", "twitch_security_audit.log", "Path to the human-readable and JSONL audit ledgers.")
	truncateLedger := flag.Bool("truncate-ledger", false, "Truncate both audit ledger files on startup.")
	workspace := flag.String("workspace", ".", "Go workspace to inspect and sandbox-test; never modified by remediation.")
	sandboxPrewarm := flag.Bool("sandbox-prewarm", false, "Run the isolated Go test suite without a remediation to warm the Docker build cache.")
	sandboxTimeout := flag.Duration("sandbox-timeout", 30*time.Minute, "Maximum duration for isolated Docker sandbox tests.")
	sandboxDebug := flag.Bool("sandbox-debug", false, "Print Go build commands from isolated sandbox tests.")
	dependency := flag.String("dependency", "", "Existing go.mod dependency to upgrade during --simulate.")
	fixedVersion := flag.String("fixed-version", "", "Higher canonical Go module version for --dependency.")
	kinesisStream := flag.String("kinesis-stream", "", "Kinesis stream name for consuming or publishing simulations.")
	kinesisConsume := flag.Bool("kinesis-consume", false, "Consume the configured Kinesis stream until interrupted.")
	productionMode := flag.Bool("production-mode", false, "Require shared DynamoDB state and a durable SQS dead-letter queue for Kinesis consumption.")
	awsRegion := flag.String("aws-region", "", "AWS region; defaults to the AWS SDK credential/config chain.")
	checkpointPath := flag.String("kinesis-checkpoint", "kinesis_checkpoints.jsonl", "Durable Kinesis shard checkpoint JSONL path.")
	idempotencyPath := flag.String("idempotency-path", "telemetry_idempotency.jsonl", "Durable processed-event index JSONL path.")
	dynamodbTable := flag.String("dynamodb-table", "", "DynamoDB table for shared checkpoints, leases, and idempotency records.")
	dlqURL := flag.String("dlq-url", "", "SQS dead-letter queue URL for records that exceed retry attempts.")
	maxRecordAttempts := flag.Int("max-record-attempts", 3, "Maximum attempts to process each Kinesis record before DLQ handoff.")
	retryBackoff := flag.Duration("retry-backoff", time.Second, "Initial exponential backoff between Kinesis record attempts.")
	leaseDuration := flag.Duration("shard-lease-duration", time.Minute, "DynamoDB shard lease duration; renewed while the consumer polls.")
	startPosition := flag.String("kinesis-start-position", "TRIM_HORIZON", "Initial position for new Kinesis shards: TRIM_HORIZON or LATEST.")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", flag.Args())
	}
	if *simulateRollbacks {
		*simulatePoisoned = true
		*simulateForceFailure = true
	}
	if *kinesisConsume && *kinesisStream == "" {
		return errors.New("--kinesis-consume requires --kinesis-stream")
	}
	if *kinesisConsume && (*simulate || *simulatePoisoned || *simulateForceFailure) {
		return errors.New("simulation flags cannot be combined with --kinesis-consume")
	}
	if *productionMode && (!*kinesisConsume || *dynamodbTable == "" || *dlqURL == "" || *metricsAddr == "") {
		return errors.New("--production-mode requires --kinesis-consume, --dynamodb-table, --dlq-url, and an enabled metrics listener")
	}
	if *maxRecordAttempts < 1 || *maxRecordAttempts > 10 {
		return errors.New("--max-record-attempts must be between 1 and 10")
	}
	if *retryBackoff <= 0 || *leaseDuration <= 0 {
		return errors.New("--retry-backoff and --shard-lease-duration must be greater than zero")
	}
	if (*simulate || *simulatePoisoned || *simulateForceFailure) && (*dependency == "" || *fixedVersion == "") {
		return errors.New("simulation requires --dependency and --fixed-version; use an existing go.mod dependency and a higher version")
	}
	if *sandboxTimeout <= 0 {
		return errors.New("--sandbox-timeout must be greater than zero")
	}
	if *sandboxPrewarm && (*simulate || *simulatePoisoned || *simulateForceFailure || *kinesisConsume) {
		return errors.New("--sandbox-prewarm cannot be combined with simulation or Kinesis consumer flags")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	verifier := workflow.DockerSandboxVerifier{
		WorkspaceRoot: *workspace,
		Timeout:       *sandboxTimeout,
		Debug:         *sandboxDebug,
	}
	if *sandboxPrewarm {
		goMod, err := os.ReadFile(filepath.Join(*workspace, "go.mod"))
		if err != nil {
			return fmt.Errorf("read workspace go.mod for sandbox prewarm: %w", err)
		}
		if err := verifier.Verify(ctx, workflow.GeneratedPatch{RelativePath: "go.mod", Content: goMod}); err != nil {
			return fmt.Errorf("sandbox prewarm failed: %w", err)
		}
		fmt.Println("sandbox prewarm passed; Docker Go build cache is ready")
		return nil
	}
	if *truncateLedger && *ledgerPath != "" {
		if err := os.WriteFile(*ledgerPath, nil, 0o600); err != nil {
			return fmt.Errorf("truncate audit ledger: %w", err)
		}
		if err := os.WriteFile(storage.LedgerJSONPath(*ledgerPath), nil, 0o600); err != nil {
			return fmt.Errorf("truncate structured audit ledger: %w", err)
		}
	}

	ledger, err := storage.NewImmutableLedger(*ledgerPath)
	if err != nil {
		return fmt.Errorf("open audit ledger: %w", err)
	}
	defer ledger.Close()

	engine := workflow.NewRemediationEngine(controller.NewVerificationController())
	runner := &Runner{
		Engine:    engine,
		Generator: workflow.GoModPatchGenerator{WorkspaceRoot: *workspace},
		Verifier:  verifier,
		Ledger:    ledger,
	}
	if *metricsAddr != "" {
		server, err := storage.StartMetricsServer(*metricsAddr)
		if err != nil {
			return err
		}
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdownCtx)
		}()
		fmt.Printf("metrics server listening on %s (GET /metrics)\n", *metricsAddr)
	}

	if *kinesisConsume {
		if *dynamodbTable == "" {
			fmt.Fprintln(os.Stderr, "warning: local checkpoint/idempotency files support one consumer process only")
		}
		if *dlqURL == "" {
			fmt.Fprintln(os.Stderr, "warning: no DLQ configured; exhausted or malformed records stop the consumer without checkpointing")
		}
		awsConfig, err := loadAWSConfig(ctx, *awsRegion)
		if err != nil {
			return fmt.Errorf("load AWS configuration: %w", err)
		}
		var checkpoints storage.KinesisCheckpointStore
		var idempotency storage.EventIdempotencyStore
		if *dynamodbTable != "" {
			stateStore, err := storage.NewDynamoDBStateStore(dynamodb.NewFromConfig(awsConfig), *dynamodbTable)
			if err != nil {
				return err
			}
			checkpoints, idempotency = stateStore, stateStore
		} else {
			index, err := storage.NewIdempotencyIndex(*idempotencyPath)
			if err != nil {
				return fmt.Errorf("load idempotency index: %w", err)
			}
			fileCheckpoints, err := storage.NewFileKinesisCheckpointStore(*checkpointPath)
			if err != nil {
				return err
			}
			checkpoints, idempotency = fileCheckpoints, index
		}
		buffer := &storage.TelemetryBuffer{Remediator: runner, Idempotency: idempotency}
		ownerID, err := storage.NewConsumerOwnerID()
		if err != nil {
			return fmt.Errorf("create consumer owner ID: %w", err)
		}
		var failureSink storage.KinesisFailureSink
		if *dlqURL != "" {
			failureSink = storage.SQSKinesisDeadLetterSink{Client: sqs.NewFromConfig(awsConfig), QueueURL: *dlqURL}
		}
		consumer := &storage.KinesisConsumer{
			Client:           kinesis.NewFromConfig(awsConfig),
			StreamName:       *kinesisStream,
			Buffer:           buffer,
			Checkpoints:      checkpoints,
			FailureSink:      failureSink,
			OwnerID:          ownerID,
			LeaseDuration:    *leaseDuration,
			MaxAttempts:      *maxRecordAttempts,
			RetryBackoff:     *retryBackoff,
			StartingPosition: typesPosition(*startPosition),
		}
		fmt.Printf("consuming Kinesis stream %s in %s\n", *kinesisStream, awsConfig.Region)
		return consumer.Run(ctx)
	}

	if *simulate || *simulatePoisoned || *simulateForceFailure {
		index, err := storage.NewIdempotencyIndex(*idempotencyPath)
		if err != nil {
			return fmt.Errorf("load idempotency index: %w", err)
		}
		buffer := &storage.TelemetryBuffer{Remediator: runner, Idempotency: index}
		publishToKinesis := *kinesisStream != ""
		var publisher storage.KinesisPublisher
		if publishToKinesis {
			awsConfig, err := loadAWSConfig(ctx, *awsRegion)
			if err != nil {
				return fmt.Errorf("load AWS configuration: %w", err)
			}
			publisher = storage.KinesisPublisher{Client: kinesis.NewFromConfig(awsConfig), StreamName: *kinesisStream}
		}
		simulations := make([]storage.SecurityTelemetryEvent, 0, 3)
		if *simulate {
			simulations = append(simulations, simulationEvent("TX-LOCAL-0001", *dependency, *fixedVersion))
		}
		if *simulatePoisoned {
			event := simulationEvent("TX-LOCAL-POISON", *dependency, "not-a-version")
			simulations = append(simulations, event)
		}
		if *simulateForceFailure {
			event := simulationEvent("TX-LOCAL-FAIL", "example.invalid/missing-module", *fixedVersion)
			simulations = append(simulations, event)
		}
		for _, event := range simulations {
			if publishToKinesis {
				if err := publisher.Publish(ctx, event); err != nil {
					return err
				}
				fmt.Printf("published simulation to Kinesis: %s\n", event.EventID)
				continue
			}
			processed, err := buffer.ProcessEventWithResult(ctx, event)
			if err != nil {
				fmt.Fprintf(os.Stderr, "simulation %s rolled back: %v\n", event.EventID, err)
				continue
			}
			if processed {
				fmt.Println(simulationResultMessage(event.EventID, true))
			} else {
				fmt.Println(simulationResultMessage(event.EventID, false))
			}
		}
	}

	if *metricsAddr == "" {
		return nil
	}
	<-ctx.Done()
	fmt.Println("shutting down")
	return nil
}

func loadAWSConfig(ctx context.Context, region string) (aws.Config, error) {
	if region == "" {
		return config.LoadDefaultConfig(ctx)
	}
	return config.LoadDefaultConfig(ctx, config.WithRegion(region))
}

func typesPosition(value string) types.ShardIteratorType {
	return types.ShardIteratorType(value)
}

func simulationEvent(id, dependency, version string) storage.SecurityTelemetryEvent {
	return storage.SecurityTelemetryEvent{
		EventID:      id,
		AWSAccountID: "112233445566",
		Microservice: "video-ingest-api",
		Payload:      "CRITICAL_DEPENDENCY_ALERT: simulated dependency upgrade request",
		Dependency:   dependency,
		FixedVersion: version,
		Timestamp:    time.Now().UTC(),
	}
}

func simulationResultMessage(eventID string, processed bool) string {
	if !processed {
		return fmt.Sprintf("simulation skipped (duplicate event): %s", eventID)
	}
	return fmt.Sprintf("simulation processed: %s", eventID)
}
