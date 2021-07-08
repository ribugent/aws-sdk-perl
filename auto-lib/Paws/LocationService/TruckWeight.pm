# Generated by default/object.tt
package Paws::LocationService::TruckWeight;
  use Moose;
  has Total => (is => 'ro', isa => 'Num');
  has Unit => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::LocationService::TruckWeight

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::LocationService::TruckWeight object:

  $service_obj->Method(Att1 => { Total => $value, ..., Unit => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::LocationService::TruckWeight object:

  $result = $service_obj->Method(...);
  $result->Att1->Total

=head1 DESCRIPTION

Contains details about the truck's weight specifications. Used to avoid
roads that can't support or allow the total weight for requests that
specify C<TravelMode> as C<Truck>.

=head1 ATTRIBUTES


=head2 Total => Num

The total weight of the truck.

=over

=item *

For example, C<3500>.

=back



=head2 Unit => Str

The unit of measurement to use for the truck weight.

Default Value: C<Kilograms>



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::LocationService>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

