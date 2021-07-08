# Generated by default/object.tt
package Paws::ELB::AdditionalAttribute;
  use Moose;
  has Key => (is => 'ro', isa => 'Str');
  has Value => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::ELB::AdditionalAttribute

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::ELB::AdditionalAttribute object:

  $service_obj->Method(Att1 => { Key => $value, ..., Value => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::ELB::AdditionalAttribute object:

  $result = $service_obj->Method(...);
  $result->Att1->Key

=head1 DESCRIPTION

Information about additional load balancer attributes.

=head1 ATTRIBUTES


=head2 Key => Str

The name of the attribute.

The following attribute is supported.

=over

=item *

C<elb.http.desyncmitigationmode> - Determines how the load balancer
handles requests that might pose a security risk to your application.
The possible values are C<monitor>, C<defensive>, and C<strictest>. The
default is C<defensive>.

=back



=head2 Value => Str

This value of the attribute.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::ELB>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

