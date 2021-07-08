# Generated by default/object.tt
package Paws::Schemas::GetDiscoveredSchemaInput;
  use Moose;
  has Events => (is => 'ro', isa => 'ArrayRef[Str|Undef]', required => 1);
  has Type => (is => 'ro', isa => 'Str', required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::Schemas::GetDiscoveredSchemaInput

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Schemas::GetDiscoveredSchemaInput object:

  $service_obj->Method(Att1 => { Events => $value, ..., Type => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Schemas::GetDiscoveredSchemaInput object:

  $result = $service_obj->Method(...);
  $result->Att1->Events

=head1 DESCRIPTION

This class has no description

=head1 ATTRIBUTES


=head2 B<REQUIRED> Events => ArrayRef[Str|Undef]

An array of strings where each string is a JSON event. These are the
events that were used to generate the schema. The array includes a
single type of event and has a maximum size of 10 events.


=head2 B<REQUIRED> Type => Str

The type of event.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Schemas>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

