# Generated by default/object.tt
package Paws::Lightsail::LightsailDistribution;
  use Moose;
  has AbleToUpdateBundle => (is => 'ro', isa => 'Bool', request_name => 'ableToUpdateBundle', traits => ['NameInRequest']);
  has AlternativeDomainNames => (is => 'ro', isa => 'ArrayRef[Str|Undef]', request_name => 'alternativeDomainNames', traits => ['NameInRequest']);
  has Arn => (is => 'ro', isa => 'Str', request_name => 'arn', traits => ['NameInRequest']);
  has BundleId => (is => 'ro', isa => 'Str', request_name => 'bundleId', traits => ['NameInRequest']);
  has CacheBehaviors => (is => 'ro', isa => 'ArrayRef[Paws::Lightsail::CacheBehaviorPerPath]', request_name => 'cacheBehaviors', traits => ['NameInRequest']);
  has CacheBehaviorSettings => (is => 'ro', isa => 'Paws::Lightsail::CacheSettings', request_name => 'cacheBehaviorSettings', traits => ['NameInRequest']);
  has CertificateName => (is => 'ro', isa => 'Str', request_name => 'certificateName', traits => ['NameInRequest']);
  has CreatedAt => (is => 'ro', isa => 'Str', request_name => 'createdAt', traits => ['NameInRequest']);
  has DefaultCacheBehavior => (is => 'ro', isa => 'Paws::Lightsail::CacheBehavior', request_name => 'defaultCacheBehavior', traits => ['NameInRequest']);
  has DomainName => (is => 'ro', isa => 'Str', request_name => 'domainName', traits => ['NameInRequest']);
  has IpAddressType => (is => 'ro', isa => 'Str', request_name => 'ipAddressType', traits => ['NameInRequest']);
  has IsEnabled => (is => 'ro', isa => 'Bool', request_name => 'isEnabled', traits => ['NameInRequest']);
  has Location => (is => 'ro', isa => 'Paws::Lightsail::ResourceLocation', request_name => 'location', traits => ['NameInRequest']);
  has Name => (is => 'ro', isa => 'Str', request_name => 'name', traits => ['NameInRequest']);
  has Origin => (is => 'ro', isa => 'Paws::Lightsail::Origin', request_name => 'origin', traits => ['NameInRequest']);
  has OriginPublicDNS => (is => 'ro', isa => 'Str', request_name => 'originPublicDNS', traits => ['NameInRequest']);
  has ResourceType => (is => 'ro', isa => 'Str', request_name => 'resourceType', traits => ['NameInRequest']);
  has Status => (is => 'ro', isa => 'Str', request_name => 'status', traits => ['NameInRequest']);
  has SupportCode => (is => 'ro', isa => 'Str', request_name => 'supportCode', traits => ['NameInRequest']);
  has Tags => (is => 'ro', isa => 'ArrayRef[Paws::Lightsail::Tag]', request_name => 'tags', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::Lightsail::LightsailDistribution

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Lightsail::LightsailDistribution object:

  $service_obj->Method(Att1 => { AbleToUpdateBundle => $value, ..., Tags => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Lightsail::LightsailDistribution object:

  $result = $service_obj->Method(...);
  $result->Att1->AbleToUpdateBundle

=head1 DESCRIPTION

Describes an Amazon Lightsail content delivery network (CDN)
distribution.

=head1 ATTRIBUTES


=head2 AbleToUpdateBundle => Bool

Indicates whether the bundle that is currently applied to your
distribution, specified using the C<distributionName> parameter, can be
changed to another bundle.

Use the C<UpdateDistributionBundle> action to change your
distribution's bundle.


=head2 AlternativeDomainNames => ArrayRef[Str|Undef]

The alternate domain names of the distribution.


=head2 Arn => Str

The Amazon Resource Name (ARN) of the distribution.


=head2 BundleId => Str

The ID of the bundle currently applied to the distribution.


=head2 CacheBehaviors => ArrayRef[L<Paws::Lightsail::CacheBehaviorPerPath>]

An array of objects that describe the per-path cache behavior of the
distribution.


=head2 CacheBehaviorSettings => L<Paws::Lightsail::CacheSettings>

An object that describes the cache behavior settings of the
distribution.


=head2 CertificateName => Str

The name of the SSL/TLS certificate attached to the distribution, if
any.


=head2 CreatedAt => Str

The timestamp when the distribution was created.


=head2 DefaultCacheBehavior => L<Paws::Lightsail::CacheBehavior>

An object that describes the default cache behavior of the
distribution.


=head2 DomainName => Str

The domain name of the distribution.


=head2 IpAddressType => Str

The IP address type of the distribution.

The possible values are C<ipv4> for IPv4 only, and C<dualstack> for
IPv4 and IPv6.


=head2 IsEnabled => Bool

Indicates whether the distribution is enabled.


=head2 Location => L<Paws::Lightsail::ResourceLocation>

An object that describes the location of the distribution, such as the
AWS Region and Availability Zone.

Lightsail distributions are global resources that can reference an
origin in any AWS Region, and distribute its content globally. However,
all distributions are located in the C<us-east-1> Region.


=head2 Name => Str

The name of the distribution.


=head2 Origin => L<Paws::Lightsail::Origin>

An object that describes the origin resource of the distribution, such
as a Lightsail instance or load balancer.

The distribution pulls, caches, and serves content from the origin.


=head2 OriginPublicDNS => Str

The public DNS of the origin.


=head2 ResourceType => Str

The Lightsail resource type (e.g., C<Distribution>).


=head2 Status => Str

The status of the distribution.


=head2 SupportCode => Str

The support code. Include this code in your email to support when you
have questions about your Lightsail distribution. This code enables our
support team to look up your Lightsail information more easily.


=head2 Tags => ArrayRef[L<Paws::Lightsail::Tag>]

The tag keys and optional values for the resource. For more information
about tags in Lightsail, see the Lightsail Dev Guide
(https://lightsail.aws.amazon.com/ls/docs/en/articles/amazon-lightsail-tags).



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Lightsail>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

