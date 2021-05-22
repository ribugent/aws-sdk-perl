# Generated by default/object.tt
package Paws::NetworkManager::TransitGatewayConnectPeerAssociation;
  use Moose;
  has DeviceId => (is => 'ro', isa => 'Str');
  has GlobalNetworkId => (is => 'ro', isa => 'Str');
  has LinkId => (is => 'ro', isa => 'Str');
  has State => (is => 'ro', isa => 'Str');
  has TransitGatewayConnectPeerArn => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::NetworkManager::TransitGatewayConnectPeerAssociation

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::NetworkManager::TransitGatewayConnectPeerAssociation object:

  $service_obj->Method(Att1 => { DeviceId => $value, ..., TransitGatewayConnectPeerArn => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::NetworkManager::TransitGatewayConnectPeerAssociation object:

  $result = $service_obj->Method(...);
  $result->Att1->DeviceId

=head1 DESCRIPTION

Describes a transit gateway Connect peer association.

=head1 ATTRIBUTES


=head2 DeviceId => Str

The ID of the device.


=head2 GlobalNetworkId => Str

The ID of the global network.


=head2 LinkId => Str

The ID of the link.


=head2 State => Str

The state of the association.


=head2 TransitGatewayConnectPeerArn => Str

The Amazon Resource Name (ARN) of the transit gateway Connect peer.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::NetworkManager>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

