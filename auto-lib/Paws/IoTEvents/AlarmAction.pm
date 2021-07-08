# Generated by default/object.tt
package Paws::IoTEvents::AlarmAction;
  use Moose;
  has DynamoDB => (is => 'ro', isa => 'Paws::IoTEvents::DynamoDBAction', request_name => 'dynamoDB', traits => ['NameInRequest']);
  has DynamoDBv2 => (is => 'ro', isa => 'Paws::IoTEvents::DynamoDBv2Action', request_name => 'dynamoDBv2', traits => ['NameInRequest']);
  has Firehose => (is => 'ro', isa => 'Paws::IoTEvents::FirehoseAction', request_name => 'firehose', traits => ['NameInRequest']);
  has IotEvents => (is => 'ro', isa => 'Paws::IoTEvents::IotEventsAction', request_name => 'iotEvents', traits => ['NameInRequest']);
  has IotSiteWise => (is => 'ro', isa => 'Paws::IoTEvents::IotSiteWiseAction', request_name => 'iotSiteWise', traits => ['NameInRequest']);
  has IotTopicPublish => (is => 'ro', isa => 'Paws::IoTEvents::IotTopicPublishAction', request_name => 'iotTopicPublish', traits => ['NameInRequest']);
  has Lambda => (is => 'ro', isa => 'Paws::IoTEvents::LambdaAction', request_name => 'lambda', traits => ['NameInRequest']);
  has Sns => (is => 'ro', isa => 'Paws::IoTEvents::SNSTopicPublishAction', request_name => 'sns', traits => ['NameInRequest']);
  has Sqs => (is => 'ro', isa => 'Paws::IoTEvents::SqsAction', request_name => 'sqs', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::IoTEvents::AlarmAction

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::IoTEvents::AlarmAction object:

  $service_obj->Method(Att1 => { DynamoDB => $value, ..., Sqs => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::IoTEvents::AlarmAction object:

  $result = $service_obj->Method(...);
  $result->Att1->DynamoDB

=head1 DESCRIPTION

Specifies one of the following actions to receive notifications when
the alarm state changes.

=head1 ATTRIBUTES


=head2 DynamoDB => L<Paws::IoTEvents::DynamoDBAction>




=head2 DynamoDBv2 => L<Paws::IoTEvents::DynamoDBv2Action>




=head2 Firehose => L<Paws::IoTEvents::FirehoseAction>




=head2 IotEvents => L<Paws::IoTEvents::IotEventsAction>




=head2 IotSiteWise => L<Paws::IoTEvents::IotSiteWiseAction>




=head2 IotTopicPublish => L<Paws::IoTEvents::IotTopicPublishAction>




=head2 Lambda => L<Paws::IoTEvents::LambdaAction>




=head2 Sns => L<Paws::IoTEvents::SNSTopicPublishAction>




=head2 Sqs => L<Paws::IoTEvents::SqsAction>





=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::IoTEvents>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

