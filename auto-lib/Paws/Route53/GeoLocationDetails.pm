# Generated by default/object.tt
package Paws::Route53::GeoLocationDetails;
  use Moose;
  has ContinentCode => (is => 'ro', isa => 'Str');
  has ContinentName => (is => 'ro', isa => 'Str');
  has CountryCode => (is => 'ro', isa => 'Str');
  has CountryName => (is => 'ro', isa => 'Str');
  has SubdivisionCode => (is => 'ro', isa => 'Str');
  has SubdivisionName => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::Route53::GeoLocationDetails

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Route53::GeoLocationDetails object:

  $service_obj->Method(Att1 => { ContinentCode => $value, ..., SubdivisionName => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Route53::GeoLocationDetails object:

  $result = $service_obj->Method(...);
  $result->Att1->ContinentCode

=head1 DESCRIPTION

A complex type that contains the codes and full continent, country, and
subdivision names for the specified C<geolocation> code.

=head1 ATTRIBUTES


=head2 ContinentCode => Str

The two-letter code for the continent.


=head2 ContinentName => Str

The full name of the continent.


=head2 CountryCode => Str

The two-letter code for the country.


=head2 CountryName => Str

The name of the country.


=head2 SubdivisionCode => Str

The code for the subdivision, such as a particular state within the
United States. For a list of US state abbreviations, see Appendix B:
TwoE<ndash>Letter State and Possession Abbreviations
(https://pe.usps.com/text/pub28/28apb.htm) on the United States Postal
Service website. For a list of all supported subdivision codes, use the
ListGeoLocations
(https://docs.aws.amazon.com/Route53/latest/APIReference/API_ListGeoLocations.html)
API.


=head2 SubdivisionName => Str

The full name of the subdivision. Route 53 currently supports only
states in the United States.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Route53>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

