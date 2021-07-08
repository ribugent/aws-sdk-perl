# Generated by default/object.tt
package Paws::SNS::PhoneNumberInformation;
  use Moose;
  has CreatedAt => (is => 'ro', isa => 'Str');
  has Iso2CountryCode => (is => 'ro', isa => 'Str');
  has NumberCapabilities => (is => 'ro', isa => 'ArrayRef[Str|Undef]');
  has PhoneNumber => (is => 'ro', isa => 'Str');
  has RouteType => (is => 'ro', isa => 'Str');
  has Status => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::SNS::PhoneNumberInformation

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::SNS::PhoneNumberInformation object:

  $service_obj->Method(Att1 => { CreatedAt => $value, ..., Status => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::SNS::PhoneNumberInformation object:

  $result = $service_obj->Method(...);
  $result->Att1->CreatedAt

=head1 DESCRIPTION

A list of phone numbers and their metadata.

=head1 ATTRIBUTES


=head2 CreatedAt => Str

The date and time when the phone number was created.


=head2 Iso2CountryCode => Str

The two-character code for the country or region, in ISO 3166-1 alpha-2
format.


=head2 NumberCapabilities => ArrayRef[Str|Undef]

The capabilities of each phone number.


=head2 PhoneNumber => Str

The phone number.


=head2 RouteType => Str

The list of supported routes.


=head2 Status => Str

The status of the phone number.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::SNS>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

