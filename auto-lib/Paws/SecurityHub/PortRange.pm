# Generated by default/object.tt
package Paws::SecurityHub::PortRange;
  use Moose;
  has Begin => (is => 'ro', isa => 'Int');
  has End => (is => 'ro', isa => 'Int');

1;

### main pod documentation begin ###

=head1 NAME

Paws::SecurityHub::PortRange

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::SecurityHub::PortRange object:

  $service_obj->Method(Att1 => { Begin => $value, ..., End => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::SecurityHub::PortRange object:

  $result = $service_obj->Method(...);
  $result->Att1->Begin

=head1 DESCRIPTION

A range of ports.

=head1 ATTRIBUTES


=head2 Begin => Int

The first port in the port range.


=head2 End => Int

The last port in the port range.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::SecurityHub>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

