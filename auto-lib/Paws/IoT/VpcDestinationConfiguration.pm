# Generated by default/object.tt
package Paws::IoT::VpcDestinationConfiguration;
  use Moose;
  has RoleArn => (is => 'ro', isa => 'Str', request_name => 'roleArn', traits => ['NameInRequest'], required => 1);
  has SecurityGroups => (is => 'ro', isa => 'ArrayRef[Str|Undef]', request_name => 'securityGroups', traits => ['NameInRequest']);
  has SubnetIds => (is => 'ro', isa => 'ArrayRef[Str|Undef]', request_name => 'subnetIds', traits => ['NameInRequest'], required => 1);
  has VpcId => (is => 'ro', isa => 'Str', request_name => 'vpcId', traits => ['NameInRequest'], required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::IoT::VpcDestinationConfiguration

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::IoT::VpcDestinationConfiguration object:

  $service_obj->Method(Att1 => { RoleArn => $value, ..., VpcId => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::IoT::VpcDestinationConfiguration object:

  $result = $service_obj->Method(...);
  $result->Att1->RoleArn

=head1 DESCRIPTION

The configuration information for a virtual private cloud (VPC)
destination.

=head1 ATTRIBUTES


=head2 B<REQUIRED> RoleArn => Str

The ARN of a role that has permission to create and attach to elastic
network interfaces (ENIs).


=head2 SecurityGroups => ArrayRef[Str|Undef]

The security groups of the VPC destination.


=head2 B<REQUIRED> SubnetIds => ArrayRef[Str|Undef]

The subnet IDs of the VPC destination.


=head2 B<REQUIRED> VpcId => Str

The ID of the VPC.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::IoT>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

