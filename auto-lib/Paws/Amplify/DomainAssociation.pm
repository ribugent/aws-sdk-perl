# Generated by default/object.tt
package Paws::Amplify::DomainAssociation;
  use Moose;
  has AutoSubDomainCreationPatterns => (is => 'ro', isa => 'ArrayRef[Str|Undef]', request_name => 'autoSubDomainCreationPatterns', traits => ['NameInRequest']);
  has AutoSubDomainIAMRole => (is => 'ro', isa => 'Str', request_name => 'autoSubDomainIAMRole', traits => ['NameInRequest']);
  has CertificateVerificationDNSRecord => (is => 'ro', isa => 'Str', request_name => 'certificateVerificationDNSRecord', traits => ['NameInRequest']);
  has DomainAssociationArn => (is => 'ro', isa => 'Str', request_name => 'domainAssociationArn', traits => ['NameInRequest'], required => 1);
  has DomainName => (is => 'ro', isa => 'Str', request_name => 'domainName', traits => ['NameInRequest'], required => 1);
  has DomainStatus => (is => 'ro', isa => 'Str', request_name => 'domainStatus', traits => ['NameInRequest'], required => 1);
  has EnableAutoSubDomain => (is => 'ro', isa => 'Bool', request_name => 'enableAutoSubDomain', traits => ['NameInRequest'], required => 1);
  has StatusReason => (is => 'ro', isa => 'Str', request_name => 'statusReason', traits => ['NameInRequest'], required => 1);
  has SubDomains => (is => 'ro', isa => 'ArrayRef[Paws::Amplify::SubDomain]', request_name => 'subDomains', traits => ['NameInRequest'], required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::Amplify::DomainAssociation

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Amplify::DomainAssociation object:

  $service_obj->Method(Att1 => { AutoSubDomainCreationPatterns => $value, ..., SubDomains => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Amplify::DomainAssociation object:

  $result = $service_obj->Method(...);
  $result->Att1->AutoSubDomainCreationPatterns

=head1 DESCRIPTION

Describes a domain association that associates a custom domain with an
Amplify app.

=head1 ATTRIBUTES


=head2 AutoSubDomainCreationPatterns => ArrayRef[Str|Undef]

Sets branch patterns for automatic subdomain creation.


=head2 AutoSubDomainIAMRole => Str

The required AWS Identity and Access Management (IAM) service role for
the Amazon Resource Name (ARN) for automatically creating subdomains.


=head2 CertificateVerificationDNSRecord => Str

The DNS record for certificate verification.


=head2 B<REQUIRED> DomainAssociationArn => Str

The Amazon Resource Name (ARN) for the domain association.


=head2 B<REQUIRED> DomainName => Str

The name of the domain.


=head2 B<REQUIRED> DomainStatus => Str

The current status of the domain association.


=head2 B<REQUIRED> EnableAutoSubDomain => Bool

Enables the automated creation of subdomains for branches.


=head2 B<REQUIRED> StatusReason => Str

The reason for the current status of the domain association.


=head2 B<REQUIRED> SubDomains => ArrayRef[L<Paws::Amplify::SubDomain>]

The subdomains for the domain association.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Amplify>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

