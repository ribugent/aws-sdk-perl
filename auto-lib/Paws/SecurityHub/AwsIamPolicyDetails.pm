# Generated by default/object.tt
package Paws::SecurityHub::AwsIamPolicyDetails;
  use Moose;
  has AttachmentCount => (is => 'ro', isa => 'Int');
  has CreateDate => (is => 'ro', isa => 'Str');
  has DefaultVersionId => (is => 'ro', isa => 'Str');
  has Description => (is => 'ro', isa => 'Str');
  has IsAttachable => (is => 'ro', isa => 'Bool');
  has Path => (is => 'ro', isa => 'Str');
  has PermissionsBoundaryUsageCount => (is => 'ro', isa => 'Int');
  has PolicyId => (is => 'ro', isa => 'Str');
  has PolicyName => (is => 'ro', isa => 'Str');
  has PolicyVersionList => (is => 'ro', isa => 'ArrayRef[Paws::SecurityHub::AwsIamPolicyVersion]');
  has UpdateDate => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::SecurityHub::AwsIamPolicyDetails

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::SecurityHub::AwsIamPolicyDetails object:

  $service_obj->Method(Att1 => { AttachmentCount => $value, ..., UpdateDate => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::SecurityHub::AwsIamPolicyDetails object:

  $result = $service_obj->Method(...);
  $result->Att1->AttachmentCount

=head1 DESCRIPTION

Represents an IAM permissions policy.

=head1 ATTRIBUTES


=head2 AttachmentCount => Int

The number of users, groups, and roles that the policy is attached to.


=head2 CreateDate => Str

When the policy was created.

Uses the C<date-time> format specified in RFC 3339 section 5.6,
Internet Date/Time Format
(https://tools.ietf.org/html/rfc3339#section-5.6). The value cannot
contain spaces. For example, C<2020-03-22T13:22:13.933Z>.


=head2 DefaultVersionId => Str

The identifier of the default version of the policy.


=head2 Description => Str

A description of the policy.


=head2 IsAttachable => Bool

Whether the policy can be attached to a user, group, or role.


=head2 Path => Str

The path to the policy.


=head2 PermissionsBoundaryUsageCount => Int

The number of users and roles that use the policy to set the
permissions boundary.


=head2 PolicyId => Str

The unique identifier of the policy.


=head2 PolicyName => Str

The name of the policy.


=head2 PolicyVersionList => ArrayRef[L<Paws::SecurityHub::AwsIamPolicyVersion>]

List of versions of the policy.


=head2 UpdateDate => Str

When the policy was most recently updated.

Uses the C<date-time> format specified in RFC 3339 section 5.6,
Internet Date/Time Format
(https://tools.ietf.org/html/rfc3339#section-5.6). The value cannot
contain spaces. For example, C<2020-03-22T13:22:13.933Z>.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::SecurityHub>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

