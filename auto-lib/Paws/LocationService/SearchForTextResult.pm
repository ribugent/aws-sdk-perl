# Generated by default/object.tt
package Paws::LocationService::SearchForTextResult;
  use Moose;
  has Place => (is => 'ro', isa => 'Paws::LocationService::Place', required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::LocationService::SearchForTextResult

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::LocationService::SearchForTextResult object:

  $service_obj->Method(Att1 => { Place => $value, ..., Place => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::LocationService::SearchForTextResult object:

  $result = $service_obj->Method(...);
  $result->Att1->Place

=head1 DESCRIPTION

Contains relevant Places returned by calling
C<SearchPlaceIndexForText>.

=head1 ATTRIBUTES


=head2 B<REQUIRED> Place => L<Paws::LocationService::Place>

Contains details about the relevant point of interest.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::LocationService>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

