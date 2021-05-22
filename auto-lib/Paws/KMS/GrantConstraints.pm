# Generated by default/object.tt
package Paws::KMS::GrantConstraints;
  use Moose;
  has EncryptionContextEquals => (is => 'ro', isa => 'Paws::KMS::EncryptionContextType');
  has EncryptionContextSubset => (is => 'ro', isa => 'Paws::KMS::EncryptionContextType');

1;

### main pod documentation begin ###

=head1 NAME

Paws::KMS::GrantConstraints

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::KMS::GrantConstraints object:

  $service_obj->Method(Att1 => { EncryptionContextEquals => $value, ..., EncryptionContextSubset => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::KMS::GrantConstraints object:

  $result = $service_obj->Method(...);
  $result->Att1->EncryptionContextEquals

=head1 DESCRIPTION

Use this structure to allow cryptographic operations
(https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#cryptographic-operations)
in the grant only when the operation request includes the specified
encryption context
(https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context).

AWS KMS applies the grant constraints only to cryptographic operations
that support an encryption context, that is, all cryptographic
operations with a symmetric CMK
(https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-concepts.html#symmetric-cmks).
Grant constraints are not applied to operations that do not support an
encryption context, such as cryptographic operations with asymmetric
CMKs and management operations, such as DescribeKey or RetireGrant.

In a cryptographic operation, the encryption context in the decryption
operation must be an exact, case-sensitive match for the keys and
values in the encryption context of the encryption operation. Only the
order of the pairs can vary.

However, in a grant constraint, the key in each key-value pair is not
case sensitive, but the value is case sensitive.

To avoid confusion, do not use multiple encryption context pairs that
differ only by case. To require a fully case-sensitive encryption
context, use the C<kms:EncryptionContext:> and
C<kms:EncryptionContextKeys> conditions in an IAM or key policy. For
details, see kms:EncryptionContext:
(https://docs.aws.amazon.com/kms/latest/developerguide/policy-conditions.html#conditions-kms-encryption-context)
in the I< I<AWS Key Management Service Developer Guide> >.

=head1 ATTRIBUTES


=head2 EncryptionContextEquals => L<Paws::KMS::EncryptionContextType>

A list of key-value pairs that must match the encryption context in the
cryptographic operation
(https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#cryptographic-operations)
request. The grant allows the operation only when the encryption
context in the request is the same as the encryption context specified
in this constraint.


=head2 EncryptionContextSubset => L<Paws::KMS::EncryptionContextType>

A list of key-value pairs that must be included in the encryption
context of the cryptographic operation
(https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#cryptographic-operations)
request. The grant allows the cryptographic operation only when the
encryption context in the request includes the key-value pairs
specified in this constraint, although it can include additional
key-value pairs.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::KMS>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

