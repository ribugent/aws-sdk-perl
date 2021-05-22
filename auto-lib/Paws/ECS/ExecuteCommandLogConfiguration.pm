# Generated by default/object.tt
package Paws::ECS::ExecuteCommandLogConfiguration;
  use Moose;
  has CloudWatchEncryptionEnabled => (is => 'ro', isa => 'Bool', request_name => 'cloudWatchEncryptionEnabled', traits => ['NameInRequest']);
  has CloudWatchLogGroupName => (is => 'ro', isa => 'Str', request_name => 'cloudWatchLogGroupName', traits => ['NameInRequest']);
  has S3BucketName => (is => 'ro', isa => 'Str', request_name => 's3BucketName', traits => ['NameInRequest']);
  has S3EncryptionEnabled => (is => 'ro', isa => 'Bool', request_name => 's3EncryptionEnabled', traits => ['NameInRequest']);
  has S3KeyPrefix => (is => 'ro', isa => 'Str', request_name => 's3KeyPrefix', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::ECS::ExecuteCommandLogConfiguration

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::ECS::ExecuteCommandLogConfiguration object:

  $service_obj->Method(Att1 => { CloudWatchEncryptionEnabled => $value, ..., S3KeyPrefix => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::ECS::ExecuteCommandLogConfiguration object:

  $result = $service_obj->Method(...);
  $result->Att1->CloudWatchEncryptionEnabled

=head1 DESCRIPTION

The log configuration for the results of the execute command actions.
The logs can be sent to CloudWatch Logs or an Amazon S3 bucket.

=head1 ATTRIBUTES


=head2 CloudWatchEncryptionEnabled => Bool

Whether or not to enable encryption on the CloudWatch logs. If not
specified, encryption will be disabled.


=head2 CloudWatchLogGroupName => Str

The name of the CloudWatch log group to send logs to.

The CloudWatch log group must already be created.


=head2 S3BucketName => Str

The name of the S3 bucket to send logs to.

The S3 bucket must already be created.


=head2 S3EncryptionEnabled => Bool

Whether or not to enable encryption on the CloudWatch logs. If not
specified, encryption will be disabled.


=head2 S3KeyPrefix => Str

An optional folder in the S3 bucket to place logs in.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::ECS>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

