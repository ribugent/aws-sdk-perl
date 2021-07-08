# Generated by default/object.tt
package Paws::GameLift::FilterConfiguration;
  use Moose;
  has AllowedLocations => (is => 'ro', isa => 'ArrayRef[Str|Undef]');

1;

### main pod documentation begin ###

=head1 NAME

Paws::GameLift::FilterConfiguration

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::GameLift::FilterConfiguration object:

  $service_obj->Method(Att1 => { AllowedLocations => $value, ..., AllowedLocations => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::GameLift::FilterConfiguration object:

  $result = $service_obj->Method(...);
  $result->Att1->AllowedLocations

=head1 DESCRIPTION

A list of fleet locations where a game session queue can place new game
sessions. You can use a filter to temporarily turn off placements for
specific locations. For queues that have multi-location fleets, you can
use a filter configuration allow placement with some, but not all of
these locations.

Filter configurations are part of a GameSessionQueue.

=head1 ATTRIBUTES


=head2 AllowedLocations => ArrayRef[Str|Undef]

A list of locations to allow game session placement in, in the form of
AWS Region codes such as C<us-west-2>.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::GameLift>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

