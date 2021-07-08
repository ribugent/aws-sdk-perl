# Generated by default/object.tt
package Paws::Quicksight::ThemeAlias;
  use Moose;
  has AliasName => (is => 'ro', isa => 'Str');
  has Arn => (is => 'ro', isa => 'Str');
  has ThemeVersionNumber => (is => 'ro', isa => 'Int');

1;

### main pod documentation begin ###

=head1 NAME

Paws::Quicksight::ThemeAlias

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Quicksight::ThemeAlias object:

  $service_obj->Method(Att1 => { AliasName => $value, ..., ThemeVersionNumber => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Quicksight::ThemeAlias object:

  $result = $service_obj->Method(...);
  $result->Att1->AliasName

=head1 DESCRIPTION

An alias for a theme.

=head1 ATTRIBUTES


=head2 AliasName => Str

The display name of the theme alias.


=head2 Arn => Str

The Amazon Resource Name (ARN) of the theme alias.


=head2 ThemeVersionNumber => Int

The version number of the theme alias.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Quicksight>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

