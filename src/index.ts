import { SNSEvent } from 'aws-lambda';
import { WAFV2Client, AssociateWebACLCommand } from '@aws-sdk/client-wafv2'

export async function main(event: SNSEvent): Promise<void> {
  const message = event.Records[0].Sns.Message;
  console.log('Adding ALB resource: ', message);

  var params = {
    ResourceArn: message,
    WebACLArn: process.env.WEB_ACL_ARN
  };

  const client = new WAFV2Client({});
  const command = new AssociateWebACLCommand(params);
  try {
    const data = await client.send(command);
    console.log(JSON.stringify(data))
  } catch (error) {
    console.log(error)
  }
}
