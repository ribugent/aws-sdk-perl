# Generated by default/object.tt
package Paws::Honeycode::CellInput;
  use Moose;
  has Fact => (is => 'ro', isa => 'Str', request_name => 'fact', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::Honeycode::CellInput

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Honeycode::CellInput object:

  $service_obj->Method(Att1 => { Fact => $value, ..., Fact => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Honeycode::CellInput object:

  $result = $service_obj->Method(...);
  $result->Att1->Fact

=head1 DESCRIPTION

CellInput object contains the data needed to create or update cells in
a table.

=head1 ATTRIBUTES


=head2 Fact => Str

Fact represents the data that is entered into a cell. This data can be
free text or a formula. Formulas need to start with the equals (=)
sign.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Honeycode>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

