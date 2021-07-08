# Generated by default/object.tt
package Paws::NetworkFirewall::SyncState;
  use Moose;
  has Attachment => (is => 'ro', isa => 'Paws::NetworkFirewall::Attachment');
  has Config => (is => 'ro', isa => 'Paws::NetworkFirewall::SyncStateConfig');

1;

### main pod documentation begin ###

=head1 NAME

Paws::NetworkFirewall::SyncState

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::NetworkFirewall::SyncState object:

  $service_obj->Method(Att1 => { Attachment => $value, ..., Config => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::NetworkFirewall::SyncState object:

  $result = $service_obj->Method(...);
  $result->Att1->Attachment

=head1 DESCRIPTION

The status of the firewall endpoint and firewall policy configuration
for a single VPC subnet.

For each VPC subnet that you associate with a firewall, AWS Network
Firewall does the following:

=over

=item *

Instantiates a firewall endpoint in the subnet, ready to take traffic.

=item *

Configures the endpoint with the current firewall policy settings, to
provide the filtering behavior for the endpoint.

=back

When you update a firewall, for example to add a subnet association or
change a rule group in the firewall policy, the affected sync states
reflect out-of-sync or not ready status until the changes are complete.

=head1 ATTRIBUTES


=head2 Attachment => L<Paws::NetworkFirewall::Attachment>

The attachment status of the firewall's association with a single VPC
subnet. For each configured subnet, Network Firewall creates the
attachment by instantiating the firewall endpoint in the subnet so that
it's ready to take traffic. This is part of the FirewallStatus.


=head2 Config => L<Paws::NetworkFirewall::SyncStateConfig>

The configuration status of the firewall endpoint in a single VPC
subnet. Network Firewall provides each endpoint with the rules that are
configured in the firewall policy. Each time you add a subnet or modify
the associated firewall policy, Network Firewall synchronizes the rules
in the endpoint, so it can properly filter network traffic. This is
part of the FirewallStatus.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::NetworkFirewall>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

