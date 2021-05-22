# Generated by default/object.tt
package Paws::LexModelsV2::Button;
  use Moose;
  has Text => (is => 'ro', isa => 'Str', request_name => 'text', traits => ['NameInRequest'], required => 1);
  has Value => (is => 'ro', isa => 'Str', request_name => 'value', traits => ['NameInRequest'], required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::LexModelsV2::Button

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::LexModelsV2::Button object:

  $service_obj->Method(Att1 => { Text => $value, ..., Value => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::LexModelsV2::Button object:

  $result = $service_obj->Method(...);
  $result->Att1->Text

=head1 DESCRIPTION

Describes a button to use on a response card used to gather slot values
from a user.

=head1 ATTRIBUTES


=head2 B<REQUIRED> Text => Str

The text that appears on the button. Use this to tell the user what
value is returned when they choose this button.


=head2 B<REQUIRED> Value => Str

The value returned to Amazon Lex when the user chooses this button.
This must be one of the slot values configured for the slot.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::LexModelsV2>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

