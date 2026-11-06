package main

import (
	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsec2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsecs"
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

	awskinesis.NewStream(stack, jsii.String("TwitchSecurityTelemetryStream"), &awskinesis.StreamProps{
		StreamName: jsii.String("sentinel-security-telemetry"),
		ShardCount: jsii.Number(2),
	})

	dlq := awssqs.NewQueue(stack, jsii.String("SentinelRemediationDLQ"), &awssqs.QueueProps{
		QueueName: jsii.String("sentinel-remediation-dlq"),
	})

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

	return stack
}

func main() {
	defer jsii.Close()
	app := awscdk.NewApp(nil)
	NewSentinelInfrastructureStack(app, "SentinelProductionDeploymentStack", &SentinelStackProps{
		StackProps: awscdk.StackProps{
			Env: &awscdk.Environment{
				Account: jsii.String("112233445566"),
				Region:  jsii.String("us-west-2"),
			},
		},
	})
	app.Synth(nil)
}
