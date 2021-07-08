# Generated by default/object.tt
package Paws::Firehose::HttpEndpointDestinationDescription;
  use Moose;
  has BufferingHints => (is => 'ro', isa => 'Paws::Firehose::HttpEndpointBufferingHints');
  has CloudWatchLoggingOptions => (is => 'ro', isa => 'Paws::Firehose::CloudWatchLoggingOptions');
  has EndpointConfiguration => (is => 'ro', isa => 'Paws::Firehose::HttpEndpointDescription');
  has ProcessingConfiguration => (is => 'ro', isa => 'Paws::Firehose::ProcessingConfiguration');
  has RequestConfiguration => (is => 'ro', isa => 'Paws::Firehose::HttpEndpointRequestConfiguration');
  has RetryOptions => (is => 'ro', isa => 'Paws::Firehose::HttpEndpointRetryOptions');
  has RoleARN => (is => 'ro', isa => 'Str');
  has S3BackupMode => (is => 'ro', isa => 'Str');
  has S3DestinationDescription => (is => 'ro', isa => 'Paws::Firehose::S3DestinationDescription');

1;

### main pod documentation begin ###

=head1 NAME

Paws::Firehose::HttpEndpointDestinationDescription

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Firehose::HttpEndpointDestinationDescription object:

  $service_obj->Method(Att1 => { BufferingHints => $value, ..., S3DestinationDescription => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Firehose::HttpEndpointDestinationDescription object:

  $result = $service_obj->Method(...);
  $result->Att1->BufferingHints

=head1 DESCRIPTION

Describes the HTTP endpoint destination.

=head1 ATTRIBUTES


=head2 BufferingHints => L<Paws::Firehose::HttpEndpointBufferingHints>

Describes buffering options that can be applied to the data before it
is delivered to the HTTPS endpoint destination. Kinesis Data Firehose
teats these options as hints, and it might choose to use more optimal
values. The C<SizeInMBs> and C<IntervalInSeconds> parameters are
optional. However, if specify a value for one of them, you must also
provide a value for the other.


=head2 CloudWatchLoggingOptions => L<Paws::Firehose::CloudWatchLoggingOptions>




=head2 EndpointConfiguration => L<Paws::Firehose::HttpEndpointDescription>

The configuration of the specified HTTP endpoint destination.


=head2 ProcessingConfiguration => L<Paws::Firehose::ProcessingConfiguration>




=head2 RequestConfiguration => L<Paws::Firehose::HttpEndpointRequestConfiguration>

The configuration of request sent to the HTTP endpoint specified as the
destination.


=head2 RetryOptions => L<Paws::Firehose::HttpEndpointRetryOptions>

Describes the retry behavior in case Kinesis Data Firehose is unable to
deliver data to the specified HTTP endpoint destination, or if it
doesn't receive a valid acknowledgment of receipt from the specified
HTTP endpoint destination.


=head2 RoleARN => Str

Kinesis Data Firehose uses this IAM role for all the permissions that
the delivery stream needs.


=head2 S3BackupMode => Str

Describes the S3 bucket backup options for the data that Kinesis
Firehose delivers to the HTTP endpoint destination. You can back up all
documents (C<AllData>) or only the documents that Kinesis Data Firehose
could not deliver to the specified HTTP endpoint destination
(C<FailedDataOnly>).


=head2 S3DestinationDescription => L<Paws::Firehose::S3DestinationDescription>





=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Firehose>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

