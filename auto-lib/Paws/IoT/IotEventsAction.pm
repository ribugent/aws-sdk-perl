# Generated by default/object.tt
package Paws::IoT::IotEventsAction;
  use Moose;
  has BatchMode => (is => 'ro', isa => 'Bool', request_name => 'batchMode', traits => ['NameInRequest']);
  has InputName => (is => 'ro', isa => 'Str', request_name => 'inputName', traits => ['NameInRequest'], required => 1);
  has MessageId => (is => 'ro', isa => 'Str', request_name => 'messageId', traits => ['NameInRequest']);
  has RoleArn => (is => 'ro', isa => 'Str', request_name => 'roleArn', traits => ['NameInRequest'], required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::IoT::IotEventsAction

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::IoT::IotEventsAction object:

  $service_obj->Method(Att1 => { BatchMode => $value, ..., RoleArn => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::IoT::IotEventsAction object:

  $result = $service_obj->Method(...);
  $result->Att1->BatchMode

=head1 DESCRIPTION

Sends an input to an AWS IoT Events detector.

=head1 ATTRIBUTES


=head2 BatchMode => Bool

Whether to process the event actions as a batch. The default value is
C<false>.

When C<batchMode> is C<true>, you can't specify a C<messageId>.

When C<batchMode> is C<true> and the rule SQL statement evaluates to an
Array, each Array element is treated as a separate message when it's
sent to AWS IoT Events by calling C<BatchPutMessage>
(https://docs.aws.amazon.com/iotevents/latest/apireference/API_iotevents-data_BatchPutMessage.html).
The resulting array can't have more than 10 messages.


=head2 B<REQUIRED> InputName => Str

The name of the AWS IoT Events input.


=head2 MessageId => Str

The ID of the message. The default C<messageId> is a new UUID value.

When C<batchMode> is C<true>, you can't specify a C<messageId>--a new
UUID value will be assigned.

Assign a value to this property to ensure that only one input (message)
with a given C<messageId> will be processed by an AWS IoT Events
detector.


=head2 B<REQUIRED> RoleArn => Str

The ARN of the role that grants AWS IoT permission to send an input to
an AWS IoT Events detector. ("Action":"iotevents:BatchPutMessage").



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::IoT>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

