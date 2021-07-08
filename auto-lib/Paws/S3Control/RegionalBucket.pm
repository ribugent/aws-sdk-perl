# Generated by default/object.tt
package Paws::S3Control::RegionalBucket;
  use Moose;
  has Bucket => (is => 'ro', isa => 'Str', required => 1);
  has BucketArn => (is => 'ro', isa => 'Str');
  has CreationDate => (is => 'ro', isa => 'Str', required => 1);
  has OutpostId => (is => 'ro', isa => 'Str');
  has PublicAccessBlockEnabled => (is => 'ro', isa => 'Bool', required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::S3Control::RegionalBucket

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::S3Control::RegionalBucket object:

  $service_obj->Method(Att1 => { Bucket => $value, ..., PublicAccessBlockEnabled => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::S3Control::RegionalBucket object:

  $result = $service_obj->Method(...);
  $result->Att1->Bucket

=head1 DESCRIPTION

The container for the regional bucket.

=head1 ATTRIBUTES


=head2 B<REQUIRED> Bucket => Str




=head2 BucketArn => Str

The Amazon Resource Name (ARN) for the regional bucket.


=head2 B<REQUIRED> CreationDate => Str

The creation date of the regional bucket


=head2 OutpostId => Str

The AWS Outposts ID of the regional bucket.


=head2 B<REQUIRED> PublicAccessBlockEnabled => Bool





=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::S3Control>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

