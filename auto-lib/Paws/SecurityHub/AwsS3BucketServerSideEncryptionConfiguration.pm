# Generated by default/object.tt
package Paws::SecurityHub::AwsS3BucketServerSideEncryptionConfiguration;
  use Moose;
  has Rules => (is => 'ro', isa => 'ArrayRef[Paws::SecurityHub::AwsS3BucketServerSideEncryptionRule]');

1;

### main pod documentation begin ###

=head1 NAME

Paws::SecurityHub::AwsS3BucketServerSideEncryptionConfiguration

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::SecurityHub::AwsS3BucketServerSideEncryptionConfiguration object:

  $service_obj->Method(Att1 => { Rules => $value, ..., Rules => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::SecurityHub::AwsS3BucketServerSideEncryptionConfiguration object:

  $result = $service_obj->Method(...);
  $result->Att1->Rules

=head1 DESCRIPTION

The encryption configuration for the S3 bucket.

=head1 ATTRIBUTES


=head2 Rules => ArrayRef[L<Paws::SecurityHub::AwsS3BucketServerSideEncryptionRule>]

The encryption rules that are applied to the S3 bucket.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::SecurityHub>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

