# Generated by default/object.tt
package Paws::AccessAnalyzer::S3BucketConfiguration;
  use Moose;
  has AccessPoints => (is => 'ro', isa => 'Paws::AccessAnalyzer::S3AccessPointConfigurationsMap', request_name => 'accessPoints', traits => ['NameInRequest']);
  has BucketAclGrants => (is => 'ro', isa => 'ArrayRef[Paws::AccessAnalyzer::S3BucketAclGrantConfiguration]', request_name => 'bucketAclGrants', traits => ['NameInRequest']);
  has BucketPolicy => (is => 'ro', isa => 'Str', request_name => 'bucketPolicy', traits => ['NameInRequest']);
  has BucketPublicAccessBlock => (is => 'ro', isa => 'Paws::AccessAnalyzer::S3PublicAccessBlockConfiguration', request_name => 'bucketPublicAccessBlock', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::AccessAnalyzer::S3BucketConfiguration

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::AccessAnalyzer::S3BucketConfiguration object:

  $service_obj->Method(Att1 => { AccessPoints => $value, ..., BucketPublicAccessBlock => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::AccessAnalyzer::S3BucketConfiguration object:

  $result = $service_obj->Method(...);
  $result->Att1->AccessPoints

=head1 DESCRIPTION

Proposed access control configuration for an Amazon S3 bucket. You can
propose a configuration for a new Amazon S3 bucket or an existing
Amazon S3 bucket that you own by specifying the Amazon S3 bucket
policy, bucket ACLs, bucket BPA settings, and Amazon S3 access points
attached to the bucket. If the configuration is for an existing Amazon
S3 bucket and you do not specify the Amazon S3 bucket policy, the
access preview uses the existing policy attached to the bucket. If the
access preview is for a new resource and you do not specify the Amazon
S3 bucket policy, the access preview assumes a bucket without a policy.
To propose deletion of an existing bucket policy, you can specify an
empty string. For more information about bucket policy limits, see
Bucket Policy Examples
(https://docs.aws.amazon.com/AmazonS3/latest/dev/example-bucket-policies.html).

=head1 ATTRIBUTES


=head2 AccessPoints => L<Paws::AccessAnalyzer::S3AccessPointConfigurationsMap>

The configuration of Amazon S3 access points for the bucket.


=head2 BucketAclGrants => ArrayRef[L<Paws::AccessAnalyzer::S3BucketAclGrantConfiguration>]

The proposed list of ACL grants for the Amazon S3 bucket. You can
propose up to 100 ACL grants per bucket. If the proposed grant
configuration is for an existing bucket, the access preview uses the
proposed list of grant configurations in place of the existing grants.
Otherwise, the access preview uses the existing grants for the bucket.


=head2 BucketPolicy => Str

The proposed bucket policy for the Amazon S3 bucket.


=head2 BucketPublicAccessBlock => L<Paws::AccessAnalyzer::S3PublicAccessBlockConfiguration>

The proposed block public access configuration for the Amazon S3
bucket.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::AccessAnalyzer>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

