# Generated by default/object.tt
package Paws::AccessAnalyzer::KmsGrantConstraints;
  use Moose;
  has EncryptionContextEquals => (is => 'ro', isa => 'Paws::AccessAnalyzer::KmsConstraintsMap', request_name => 'encryptionContextEquals', traits => ['NameInRequest']);
  has EncryptionContextSubset => (is => 'ro', isa => 'Paws::AccessAnalyzer::KmsConstraintsMap', request_name => 'encryptionContextSubset', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::AccessAnalyzer::KmsGrantConstraints

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::AccessAnalyzer::KmsGrantConstraints object:

  $service_obj->Method(Att1 => { EncryptionContextEquals => $value, ..., EncryptionContextSubset => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::AccessAnalyzer::KmsGrantConstraints object:

  $result = $service_obj->Method(...);
  $result->Att1->EncryptionContextEquals

=head1 DESCRIPTION

Use this structure to propose allowing cryptographic operations
(https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#cryptographic-operations)
in the grant only when the operation request includes the specified
encryption context
(https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context).
You can specify only one type of encryption context. An empty map is
treated as not specified. For more information, see GrantConstraints
(https://docs.aws.amazon.com/kms/latest/APIReference/API_GrantConstraints.html).

=head1 ATTRIBUTES


=head2 EncryptionContextEquals => L<Paws::AccessAnalyzer::KmsConstraintsMap>

A list of key-value pairs that must match the encryption context in the
cryptographic operation
(https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#cryptographic-operations)
request. The grant allows the operation only when the encryption
context in the request is the same as the encryption context specified
in this constraint.


=head2 EncryptionContextSubset => L<Paws::AccessAnalyzer::KmsConstraintsMap>

A list of key-value pairs that must be included in the encryption
context of the cryptographic operation
(https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#cryptographic-operations)
request. The grant allows the cryptographic operation only when the
encryption context in the request includes the key-value pairs
specified in this constraint, although it can include additional
key-value pairs.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::AccessAnalyzer>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

