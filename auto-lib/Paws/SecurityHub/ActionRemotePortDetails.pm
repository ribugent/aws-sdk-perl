# Generated by default/object.tt
package Paws::SecurityHub::ActionRemotePortDetails;
  use Moose;
  has Port => (is => 'ro', isa => 'Int');
  has PortName => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::SecurityHub::ActionRemotePortDetails

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::SecurityHub::ActionRemotePortDetails object:

  $service_obj->Method(Att1 => { Port => $value, ..., PortName => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::SecurityHub::ActionRemotePortDetails object:

  $result = $service_obj->Method(...);
  $result->Att1->Port

=head1 DESCRIPTION

Provides information about the remote port that was involved in an
attempted network connection.

=head1 ATTRIBUTES


=head2 Port => Int

The number of the port.


=head2 PortName => Str

The port name of the remote connection.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::SecurityHub>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

