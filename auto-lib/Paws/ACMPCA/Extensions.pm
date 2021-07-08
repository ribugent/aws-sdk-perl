# Generated by default/object.tt
package Paws::ACMPCA::Extensions;
  use Moose;
  has CertificatePolicies => (is => 'ro', isa => 'ArrayRef[Paws::ACMPCA::PolicyInformation]');
  has ExtendedKeyUsage => (is => 'ro', isa => 'ArrayRef[Paws::ACMPCA::ExtendedKeyUsage]');
  has KeyUsage => (is => 'ro', isa => 'Paws::ACMPCA::KeyUsage');
  has SubjectAlternativeNames => (is => 'ro', isa => 'ArrayRef[Paws::ACMPCA::GeneralName]');

1;

### main pod documentation begin ###

=head1 NAME

Paws::ACMPCA::Extensions

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::ACMPCA::Extensions object:

  $service_obj->Method(Att1 => { CertificatePolicies => $value, ..., SubjectAlternativeNames => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::ACMPCA::Extensions object:

  $result = $service_obj->Method(...);
  $result->Att1->CertificatePolicies

=head1 DESCRIPTION

Contains X.509 extension information for a certificate.

=head1 ATTRIBUTES


=head2 CertificatePolicies => ArrayRef[L<Paws::ACMPCA::PolicyInformation>]

Contains a sequence of one or more policy information terms, each of
which consists of an object identifier (OID) and optional qualifiers.
For more information, see NIST's definition of Object Identifier (OID)
(https://csrc.nist.gov/glossary/term/Object_Identifier).

In an end-entity certificate, these terms indicate the policy under
which the certificate was issued and the purposes for which it may be
used. In a CA certificate, these terms limit the set of policies for
certification paths that include this certificate.


=head2 ExtendedKeyUsage => ArrayRef[L<Paws::ACMPCA::ExtendedKeyUsage>]

Specifies additional purposes for which the certified public key may be
used other than basic purposes indicated in the C<KeyUsage> extension.


=head2 KeyUsage => L<Paws::ACMPCA::KeyUsage>




=head2 SubjectAlternativeNames => ArrayRef[L<Paws::ACMPCA::GeneralName>]

The subject alternative name extension allows identities to be bound to
the subject of the certificate. These identities may be included in
addition to or in place of the identity in the subject field of the
certificate.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::ACMPCA>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

