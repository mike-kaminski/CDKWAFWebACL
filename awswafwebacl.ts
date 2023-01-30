import { App,
  Stack,
  StackProps,
  Duration,
  Tags, RemovalPolicy } from 'aws-cdk-lib';
import { CfnWebACL, CfnWebACLProps, CfnLoggingConfiguration } from 'aws-cdk-lib/aws-wafv2';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';
import { Topic } from 'aws-cdk-lib/aws-sns';
import { LambdaSubscription } from 'aws-cdk-lib/aws-sns-subscriptions';
import { ManagedPolicy } from 'aws-cdk-lib/aws-iam';
import { LogGroup, RetentionDays } from 'aws-cdk-lib/aws-logs';
import * as path from 'path';
import { ManagedRule,
  CfnRemediationConfiguration,
  ResourceType,
  RuleScope,
  ManagedRuleIdentifiers } from 'aws-cdk-lib/aws-config'
import { awsManagedRules, rateBasedRules } from './awswafwebaclrules';

const serviceName = 'awswafwebacl';
const environment = String(process.env.ENVIRONMENT);
const accountId =  String(process.env.ACCOUNT_ID);
const region = String(process.env.REGION);

class awsWafWebAcl extends Stack {
  constructor(scope: App, id: string, props?: StackProps) {
    super(scope, id, props);

    // Create the WAF log group
    const logGroup = new LogGroup(this, 'WebAclLogGroup', {
      logGroupName: `aws-waf-logs-${serviceName}-${environment}`,
      removalPolicy: RemovalPolicy.DESTROY,
      retention: RetentionDays.ONE_MONTH
    });

    // Create the WebACL and attach the rules.
    const webaclProps: CfnWebACLProps = {
      defaultAction: {
        allow: {}
      },
      scope: 'REGIONAL',
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: `${serviceName}-${environment}`,
        sampledRequestsEnabled: true
      },
      rules: [...awsManagedRules, ...rateBasedRules].map(wafRule => wafRule.rule),
    };

    const webACL = new CfnWebACL(this, `${serviceName}-${environment}`, webaclProps)

    const webAclLogs = new CfnLoggingConfiguration(this,'WafLoggingConfig',{
      resourceArn: webACL.attrArn,
      logDestinationConfigs:[ logGroup.logGroupArn ],
    });
    webAclLogs.node.addDependency(logGroup)

    // Create sns topic
    const topic = new Topic(this, 'albWafStatus', {
      topicName: `albWafStatus-${environment}`,
      displayName: `albWafStatus-${environment}`,
    });

    // Create lambda function
    const webAclUpdater = new NodejsFunction(this, 'webAclUpdater', {
      functionName: `albWafStatus-${environment}`,
      memorySize: 256,
      timeout: Duration.seconds(5),
      runtime: Runtime.NODEJS_14_X,
      handler: 'main',
      entry: path.join(__dirname, `./src/index.ts`),
      environment: {
        WEB_ACL_ARN: webACL.attrArn
      },
      logRetention: RetentionDays.ONE_MONTH
    });

    webAclUpdater.role?.addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName('AmazonSNSReadOnlyAccess'));
    webAclUpdater.role?.addManagedPolicy(ManagedPolicy.fromAwsManagedPolicyName('AWSWAFFullAccess'));

    // Subscribe Lambda to SNS topic
    topic.addSubscription(new LambdaSubscription(webAclUpdater));

    // AWS Config remediation
    const configRule = new ManagedRule(this, 'ConfigAlbWafEnabled', {
      configRuleName: `${serviceName}-${environment}-alb-waf-enabled`,
      identifier: ManagedRuleIdentifiers.ALB_WAF_ENABLED,
      ruleScope: RuleScope.fromResources([ResourceType.ELBV2_LOAD_BALANCER]),
      inputParameters: {
        wafWebAclIds: webACL.attrArn
      }
    });

    const remediationConfiguration = new CfnRemediationConfiguration(this, 'AlbWafEnabledRemediationConfiguration', {
      configRuleName: configRule.configRuleName,
      targetId: 'AWS-PublishSNSNotification',
      targetType: 'SSM_DOCUMENT',
      automatic: false,
      parameters: {
        'Message': { ResourceValue: { Value: 'RESOURCE_ID' }},
        'TopicArn': { StaticValue: { Values: [ topic.topicArn ] }},
      },
      maximumAutomaticAttempts: 2,
      retryAttemptSeconds: 60,
    });
    remediationConfiguration.node.addDependency(configRule);
  };
};

const app = new App();

Tags.of(app).add('product', 'aws-waf-webacl');
Tags.of(app).add('owner', 'Platform Operations');
Tags.of(app).add('environment', environment);

new awsWafWebAcl(app, 'awsWafWebAcl', { stackName: `${serviceName}-${environment}`, env: { account: accountId, region: region }});

app.synth();