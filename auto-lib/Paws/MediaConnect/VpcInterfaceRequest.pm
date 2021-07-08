# Generated by default/object.tt
package Paws::MediaConnect::VpcInterfaceRequest;
  use Moose;
  has Name => (is => 'ro', isa => 'Str', request_name => 'name', traits => ['NameInRequest'], required => 1);
  has NetworkInterfaceType => (is => 'ro', isa => 'Str', request_name => 'networkInterfaceType', traits => ['NameInRequest']);
  has RoleArn => (is => 'ro', isa => 'Str', request_name => 'roleArn', traits => ['NameInRequest'], required => 1);
  has SecurityGroupIds => (is => 'ro', isa => 'ArrayRef[Str|Undef]', request_name => 'securityGroupIds', traits => ['NameInRequest'], required => 1);
  has SubnetId => (is => 'ro', isa => 'Str', request_name => 'subnetId', traits => ['NameInRequest'], required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::MediaConnect::VpcInterfaceRequest

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::MediaConnect::VpcInterfaceRequest object:

  $service_obj->Method(Att1 => { Name => $value, ..., SubnetId => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::MediaConnect::VpcInterfaceRequest object:

  $result = $service_obj->Method(...);
  $result->Att1->Name

=head1 DESCRIPTION

Desired VPC Interface for a Flow

=head1 ATTRIBUTES


=head2 B<REQUIRED> Name => Str

The name of the VPC Interface. This value must be unique within the
current flow.


=head2 NetworkInterfaceType => Str

The type of network interface. If this value is not included in the
request, MediaConnect uses ENA as the networkInterfaceType.


=head2 B<REQUIRED> RoleArn => Str

Role Arn MediaConnect can assumes to create ENIs in customer's account


=head2 B<REQUIRED> SecurityGroupIds => ArrayRef[Str|Undef]

Security Group IDs to be used on ENI.


=head2 B<REQUIRED> SubnetId => Str

Subnet must be in the AZ of the Flow



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::MediaConnect>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

