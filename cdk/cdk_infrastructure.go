package main

import (
	"os"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awscloudwatch"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsdynamodb"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsec2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsecs"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/aws-cdk-go/awscdk/v2/awskinesis"
	"github.com/aws/aws-cdk-go/awscdk/v2/awssqs"
	"github.com/aws/constructs-go/constructs/v10"
	"github.com/aws/jsii-runtime-go"
)

type SentinelStackProps struct {
	awscdk.StackProps
}

func NewSentinelInfrastructureStack(scope constructs.Construct, id string, props *SentinelStackProps) awscdk.Stack {
	var sprops awscdk.StackProps
	if props != nil {
		sprops = props.StackProps
	}

	stack := awscdk.NewStack(scope, &id, &sprops)

	stream := awskinesis.NewStream(stack, jsii.String("TwitchSecurityTelemetryStream"), &awskinesis.StreamProps{
		StreamName:      jsii.String("sentinel-security-telemetry"),
		ShardCount:      jsii.Number(2),
		Encryption:      awskinesis.StreamEncryption_MANAGED,
		RetentionPeriod: awscdk.Duration_Days(jsii.Number(7)),
	})

	dlq := awssqs.NewQueue(stack, jsii.String("SentinelRemediationDLQ"), &awssqs.QueueProps{
		QueueName:         jsii.String("sentinel-remediation-dlq"),
		Encryption:        awssqs.QueueEncryption_SQS_MANAGED,
		EnforceSSL:        jsii.Bool(true),
		RetentionPeriod:   awscdk.Duration_Days(jsii.Number(14)),
		VisibilityTimeout: awscdk.Duration_Seconds(jsii.Number(60)),
	})

	stateTable := awsdynamodb.NewTable(stack, jsii.String("SentinelConsumerState"), &awsdynamodb.TableProps{
		TableName: jsii.String("sentinel-consumer-state"),
		PartitionKey: &awsdynamodb.Attribute{
			Name: jsii.String("record_key"),
			Type: awsdynamodb.AttributeType_STRING,
		},
		BillingMode:         awsdynamodb.BillingMode_PAY_PER_REQUEST,
		Encryption:          awsdynamodb.TableEncryption_AWS_MANAGED,
		PointInTimeRecovery: jsii.Bool(true),
		TimeToLiveAttribute: jsii.String("expires_at"),
		DeletionProtection:  jsii.Bool(true),
		RemovalPolicy:       awscdk.RemovalPolicy_RETAIN,
	})

	taskRole := awsiam.NewRole(stack, jsii.String("SentinelConsumerTaskRole"), &awsiam.RoleProps{
		AssumedBy:   awsiam.NewServicePrincipal(jsii.String("ecs-tasks.amazonaws.com"), nil),
		Description: jsii.String("Least-privilege runtime role for the Sentinel telemetry consumer."),
	})
	taskRole.AddToPolicy(awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{
		Actions:   jsii.Strings("kinesis:ListShards", "kinesis:GetShardIterator", "kinesis:GetRecords"),
		Resources: jsii.Strings(*stream.StreamArn()),
	}))

	dlqVisibleMessages := awscloudwatch.NewMetric(&awscloudwatch.MetricProps{
		Namespace:     jsii.String("AWS/SQS"),
		MetricName:    jsii.String("ApproximateNumberOfMessagesVisible"),
		DimensionsMap: &map[string]*string{"QueueName": dlq.QueueName()},
		Statistic:     jsii.String("Maximum"),
		Period:        awscdk.Duration_Minutes(jsii.Number(1)),
	})
	awscloudwatch.NewAlarm(stack, jsii.String("SentinelDLQVisibleMessagesAlarm"), &awscloudwatch.AlarmProps{
		AlarmDescription:   jsii.String("Alarm when failed telemetry is waiting in the Sentinel dead-letter queue."),
		Metric:             dlqVisibleMessages,
		Threshold:          jsii.Number(0),
		EvaluationPeriods:  jsii.Number(1),
		ComparisonOperator: awscloudwatch.ComparisonOperator_GREATER_THAN_THRESHOLD,
		TreatMissingData:   awscloudwatch.TreatMissingData_NOT_BREACHING,
	})
	iteratorAge := awscloudwatch.NewMetric(&awscloudwatch.MetricProps{
		Namespace:     jsii.String("AWS/Kinesis"),
		MetricName:    jsii.String("GetRecords.IteratorAgeMilliseconds"),
		DimensionsMap: &map[string]*string{"StreamName": stream.StreamName()},
		Statistic:     jsii.String("Maximum"),
		Period:        awscdk.Duration_Minutes(jsii.Number(1)),
	})
	awscloudwatch.NewAlarm(stack, jsii.String("SentinelKinesisIteratorAgeAlarm"), &awscloudwatch.AlarmProps{
		AlarmDescription:   jsii.String("Alarm when Sentinel is more than five minutes behind the Kinesis stream."),
		Metric:             iteratorAge,
		Threshold:          jsii.Number(300000),
		EvaluationPeriods:  jsii.Number(2),
		ComparisonOperator: awscloudwatch.ComparisonOperator_GREATER_THAN_THRESHOLD,
		TreatMissingData:   awscloudwatch.TreatMissingData_NOT_BREACHING,
	})
	taskRole.AddToPolicy(awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{
		Actions:   jsii.Strings("dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"),
		Resources: jsii.Strings(*stateTable.TableArn()),
	}))
	taskRole.AddToPolicy(awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{
		Actions:   jsii.Strings("sqs:SendMessage"),
		Resources: jsii.Strings(*dlq.QueueArn()),
	}))

	vpc := awsec2.NewVpc(stack, jsii.String("SentinelSandboxVPC"), &awsec2.VpcProps{
		MaxAzs: jsii.Number(2),
	})

	awsecs.NewCluster(stack, jsii.String("SentinelSandboxCluster"), &awsecs.ClusterProps{
		Vpc:         vpc,
		ClusterName: jsii.String("sentinel-agent-sandbox-fleet"),
	})

	awscdk.NewCfnOutput(stack, jsii.String("DLQArnOutput"), &awscdk.CfnOutputProps{
		Value: dlq.QueueArn(),
	})
	awscdk.NewCfnOutput(stack, jsii.String("DLQUrlOutput"), &awscdk.CfnOutputProps{
		Value: dlq.QueueUrl(),
	})
	awscdk.NewCfnOutput(stack, jsii.String("ConsumerStateTableNameOutput"), &awscdk.CfnOutputProps{
		Value: stateTable.TableName(),
	})
	awscdk.NewCfnOutput(stack, jsii.String("ConsumerTaskRoleArnOutput"), &awscdk.CfnOutputProps{
		Value: taskRole.RoleArn(),
	})

	return stack
}

func main() {
	defer jsii.Close()
	app := awscdk.NewApp(nil)
	stackProps := awscdk.StackProps{}
	account := os.Getenv("CDK_DEFAULT_ACCOUNT")
	region := os.Getenv("CDK_DEFAULT_REGION")
	if region == "" {
		region = os.Getenv("AWS_REGION")
	}
	if account != "" && region != "" {
		stackProps.Env = &awscdk.Environment{Account: jsii.String(account), Region: jsii.String(region)}
	}
	NewSentinelInfrastructureStack(app, "SentinelProductionDeploymentStack", &SentinelStackProps{
		StackProps: stackProps,
	})
	app.Synth(nil)
}
