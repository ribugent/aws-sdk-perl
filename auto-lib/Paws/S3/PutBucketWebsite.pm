
package Paws::S3::PutBucketWebsite;
  use Moose;
  has Bucket => (is => 'ro', isa => 'Str', uri_name => 'Bucket', traits => ['ParamInURI'], required => 1);
  has ContentLength => (is => 'ro', isa => 'Int', header_name => 'Content-Length', traits => ['ParamInHeader']);
  has ContentMD5 => (is => 'ro', isa => 'Str', header_name => 'Content-MD5', auto => 'MD5', traits => ['AutoInHeader']);
  has ExpectedBucketOwner => (is => 'ro', isa => 'Str', header_name => 'x-amz-expected-bucket-owner', traits => ['ParamInHeader']);
  has WebsiteConfiguration => (is => 'ro', isa => 'Paws::S3::WebsiteConfiguration', traits => ['ParamInBody'], required => 1);


  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'PutBucketWebsite');
  class_has _api_uri  => (isa => 'Str', is => 'ro', default => '/{Bucket}?website');
  class_has _api_method  => (isa => 'Str', is => 'ro', default => 'PUT');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::API::Response');
  class_has _result_key => (isa => 'Str', is => 'ro');
  
    
1;

### main pod documentation begin ###

=head1 NAME

Paws::S3::PutBucketWebsite - Arguments for method PutBucketWebsite on L<Paws::S3>

=head1 DESCRIPTION

This class represents the parameters used for calling the method PutBucketWebsite on the
L<Amazon Simple Storage Service|Paws::S3> service. Use the attributes of this class
as arguments to method PutBucketWebsite.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to PutBucketWebsite.

=head1 SYNOPSIS

    my $s3 = Paws->service('S3');
    # Set website configuration on a bucket
    # The following example adds website configuration to a bucket.
    $s3->PutBucketWebsite(
      'Bucket'               => 'examplebucket',
      'ContentMD5'           => '',
      'WebsiteConfiguration' => {
        'ErrorDocument' => {
          'Key' => 'error.html'
        },
        'IndexDocument' => {
          'Suffix' => 'index.html'
        }
      }
    );


Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/s3/PutBucketWebsite>

=head1 ATTRIBUTES


=head2 B<REQUIRED> Bucket => Str

The bucket name.



=head2 ContentLength => Int

Size of the body in bytes.



=head2 ContentMD5 => Str

The base64-encoded 128-bit MD5 digest of the data. You must use this
header as a message integrity check to verify that the request body was
not corrupted in transit. For more information, see RFC 1864
(http://www.ietf.org/rfc/rfc1864.txt).

For requests made using the AWS Command Line Interface (CLI) or AWS
SDKs, this field is calculated automatically.



=head2 ExpectedBucketOwner => Str

The account ID of the expected bucket owner. If the bucket is owned by
a different account, the request will fail with an HTTP C<403 (Access
Denied)> error.



=head2 B<REQUIRED> WebsiteConfiguration => L<Paws::S3::WebsiteConfiguration>

Container for the request.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method PutBucketWebsite in L<Paws::S3>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

