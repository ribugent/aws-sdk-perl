# Generated by default/object.tt
package Paws::DirectConnect::VirtualInterfaceTestHistory;
  use Moose;
  has BgpPeers => (is => 'ro', isa => 'ArrayRef[Str|Undef]', request_name => 'bgpPeers', traits => ['NameInRequest']);
  has EndTime => (is => 'ro', isa => 'Str', request_name => 'endTime', traits => ['NameInRequest']);
  has OwnerAccount => (is => 'ro', isa => 'Str', request_name => 'ownerAccount', traits => ['NameInRequest']);
  has StartTime => (is => 'ro', isa => 'Str', request_name => 'startTime', traits => ['NameInRequest']);
  has Status => (is => 'ro', isa => 'Str', request_name => 'status', traits => ['NameInRequest']);
  has TestDurationInMinutes => (is => 'ro', isa => 'Int', request_name => 'testDurationInMinutes', traits => ['NameInRequest']);
  has TestId => (is => 'ro', isa => 'Str', request_name => 'testId', traits => ['NameInRequest']);
  has VirtualInterfaceId => (is => 'ro', isa => 'Str', request_name => 'virtualInterfaceId', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::DirectConnect::VirtualInterfaceTestHistory

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::DirectConnect::VirtualInterfaceTestHistory object:

  $service_obj->Method(Att1 => { BgpPeers => $value, ..., VirtualInterfaceId => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::DirectConnect::VirtualInterfaceTestHistory object:

  $result = $service_obj->Method(...);
  $result->Att1->BgpPeers

=head1 DESCRIPTION

Information about the virtual interface failover test.

=head1 ATTRIBUTES


=head2 BgpPeers => ArrayRef[Str|Undef]

The BGP peers that were put in the DOWN state as part of the virtual
interface failover test.


=head2 EndTime => Str

The time that the virtual interface moves out of the DOWN state.


=head2 OwnerAccount => Str

The owner ID of the tested virtual interface.


=head2 StartTime => Str

The time that the virtual interface moves to the DOWN state.


=head2 Status => Str

The status of the virtual interface failover test.


=head2 TestDurationInMinutes => Int

The time that the virtual interface failover test ran in minutes.


=head2 TestId => Str

The ID of the virtual interface failover test.


=head2 VirtualInterfaceId => Str

The ID of the tested virtual interface.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::DirectConnect>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

