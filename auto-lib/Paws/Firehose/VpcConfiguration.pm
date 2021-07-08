# Generated by default/object.tt
package Paws::Firehose::VpcConfiguration;
  use Moose;
  has RoleARN => (is => 'ro', isa => 'Str', required => 1);
  has SecurityGroupIds => (is => 'ro', isa => 'ArrayRef[Str|Undef]', required => 1);
  has SubnetIds => (is => 'ro', isa => 'ArrayRef[Str|Undef]', required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::Firehose::VpcConfiguration

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Firehose::VpcConfiguration object:

  $service_obj->Method(Att1 => { RoleARN => $value, ..., SubnetIds => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Firehose::VpcConfiguration object:

  $result = $service_obj->Method(...);
  $result->Att1->RoleARN

=head1 DESCRIPTION

The details of the VPC of the Amazon ES destination.

=head1 ATTRIBUTES


=head2 B<REQUIRED> RoleARN => Str

The ARN of the IAM role that you want the delivery stream to use to
create endpoints in the destination VPC. You can use your existing
Kinesis Data Firehose delivery role or you can specify a new role. In
either case, make sure that the role trusts the Kinesis Data Firehose
service principal and that it grants the following permissions:

=over

=item *

C<ec2:DescribeVpcs>

=item *

C<ec2:DescribeVpcAttribute>

=item *

C<ec2:DescribeSubnets>

=item *

C<ec2:DescribeSecurityGroups>

=item *

C<ec2:DescribeNetworkInterfaces>

=item *

C<ec2:CreateNetworkInterface>

=item *

C<ec2:CreateNetworkInterfacePermission>

=item *

C<ec2:DeleteNetworkInterface>

=back

If you revoke these permissions after you create the delivery stream,
Kinesis Data Firehose can't scale out by creating more ENIs when
necessary. You might therefore see a degradation in performance.


=head2 B<REQUIRED> SecurityGroupIds => ArrayRef[Str|Undef]

The IDs of the security groups that you want Kinesis Data Firehose to
use when it creates ENIs in the VPC of the Amazon ES destination. You
can use the same security group that the Amazon ES domain uses or
different ones. If you specify different security groups here, ensure
that they allow outbound HTTPS traffic to the Amazon ES domain's
security group. Also ensure that the Amazon ES domain's security group
allows HTTPS traffic from the security groups specified here. If you
use the same security group for both your delivery stream and the
Amazon ES domain, make sure the security group inbound rule allows
HTTPS traffic. For more information about security group rules, see
Security group rules
(https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#SecurityGroupRules)
in the Amazon VPC documentation.


=head2 B<REQUIRED> SubnetIds => ArrayRef[Str|Undef]

The IDs of the subnets that you want Kinesis Data Firehose to use to
create ENIs in the VPC of the Amazon ES destination. Make sure that the
routing tables and inbound and outbound rules allow traffic to flow
from the subnets whose IDs are specified here to the subnets that have
the destination Amazon ES endpoints. Kinesis Data Firehose creates at
least one ENI in each of the subnets that are specified here. Do not
delete or modify these ENIs.

The number of ENIs that Kinesis Data Firehose creates in the subnets
specified here scales up and down automatically based on throughput. To
enable Kinesis Data Firehose to scale up the number of ENIs to match
throughput, ensure that you have sufficient quota. To help you
calculate the quota you need, assume that Kinesis Data Firehose can
create up to three ENIs for this delivery stream for each of the
subnets specified here. For more information about ENI quota, see
Network Interfaces
(https://docs.aws.amazon.com/vpc/latest/userguide/amazon-vpc-limits.html#vpc-limits-enis)
in the Amazon VPC Quotas topic.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Firehose>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

