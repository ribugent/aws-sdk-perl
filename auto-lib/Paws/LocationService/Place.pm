# Generated by default/object.tt
package Paws::LocationService::Place;
  use Moose;
  has AddressNumber => (is => 'ro', isa => 'Str');
  has Country => (is => 'ro', isa => 'Str');
  has Geometry => (is => 'ro', isa => 'Paws::LocationService::PlaceGeometry', required => 1);
  has Label => (is => 'ro', isa => 'Str');
  has Municipality => (is => 'ro', isa => 'Str');
  has Neighborhood => (is => 'ro', isa => 'Str');
  has PostalCode => (is => 'ro', isa => 'Str');
  has Region => (is => 'ro', isa => 'Str');
  has Street => (is => 'ro', isa => 'Str');
  has SubRegion => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::LocationService::Place

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::LocationService::Place object:

  $service_obj->Method(Att1 => { AddressNumber => $value, ..., SubRegion => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::LocationService::Place object:

  $result = $service_obj->Method(...);
  $result->Att1->AddressNumber

=head1 DESCRIPTION

Contains details about addresses or points of interest that match the
search criteria.

=head1 ATTRIBUTES


=head2 AddressNumber => Str

The numerical portion of an address, such as a building number.


=head2 Country => Str

A country/region specified using ISO 3166
(https://www.iso.org/iso-3166-country-codes.html) 3-digit
country/region code. For example, C<CAN>.


=head2 B<REQUIRED> Geometry => L<Paws::LocationService::PlaceGeometry>




=head2 Label => Str

The full name and address of the point of interest such as a city,
region, or country. For example, C<123 Any Street, Any Town, USA>.


=head2 Municipality => Str

A name for a local area, such as a city or town name. For example,
C<Toronto>.


=head2 Neighborhood => Str

The name of a community district. For example, C<Downtown>.


=head2 PostalCode => Str

A group of numbers and letters in a country-specific format, which
accompanies the address for the purpose of identifying a location.


=head2 Region => Str

A name for an area or geographical division, such as a province or
state name. For example, C<British Columbia>.


=head2 Street => Str

The name for a street or a road to identify a location. For example,
C<Main Street>.


=head2 SubRegion => Str

A country, or an area that's part of a larger region . For example,
C<Metro Vancouver>.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::LocationService>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

