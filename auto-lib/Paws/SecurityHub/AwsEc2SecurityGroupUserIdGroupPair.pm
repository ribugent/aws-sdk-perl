# Generated by default/object.tt
package Paws::SecurityHub::AwsEc2SecurityGroupUserIdGroupPair;
  use Moose;
  has GroupId => (is => 'ro', isa => 'Str');
  has GroupName => (is => 'ro', isa => 'Str');
  has PeeringStatus => (is => 'ro', isa => 'Str');
  has UserId => (is => 'ro', isa => 'Str');
  has VpcId => (is => 'ro', isa => 'Str');
  has VpcPeeringConnectionId => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::SecurityHub::AwsEc2SecurityGroupUserIdGroupPair

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::SecurityHub::AwsEc2SecurityGroupUserIdGroupPair object:

  $service_obj->Method(Att1 => { GroupId => $value, ..., VpcPeeringConnectionId => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::SecurityHub::AwsEc2SecurityGroupUserIdGroupPair object:

  $result = $service_obj->Method(...);
  $result->Att1->GroupId

=head1 DESCRIPTION

A relationship between a security group and a user.

=head1 ATTRIBUTES


=head2 GroupId => Str

The ID of the security group.


=head2 GroupName => Str

The name of the security group.


=head2 PeeringStatus => Str

The status of a VPC peering connection, if applicable.


=head2 UserId => Str

The ID of an AWS account.

For a referenced security group in another VPC, the account ID of the
referenced security group is returned in the response. If the
referenced security group is deleted, this value is not returned.

[EC2-Classic] Required when adding or removing rules that reference a
security group in another VPC.


=head2 VpcId => Str

The ID of the VPC for the referenced security group, if applicable.


=head2 VpcPeeringConnectionId => Str

The ID of the VPC peering connection, if applicable.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::SecurityHub>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

