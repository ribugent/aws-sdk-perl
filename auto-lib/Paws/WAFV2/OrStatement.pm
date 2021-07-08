# Generated by default/object.tt
package Paws::WAFV2::OrStatement;
  use Moose;
  has Statements => (is => 'ro', isa => 'ArrayRef[Paws::WAFV2::Statement]', required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::WAFV2::OrStatement

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::WAFV2::OrStatement object:

  $service_obj->Method(Att1 => { Statements => $value, ..., Statements => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::WAFV2::OrStatement object:

  $result = $service_obj->Method(...);
  $result->Att1->Statements

=head1 DESCRIPTION

A logical rule statement used to combine other rule statements with OR
logic. You provide more than one Statement within the C<OrStatement>.

=head1 ATTRIBUTES


=head2 B<REQUIRED> Statements => ArrayRef[L<Paws::WAFV2::Statement>]

The statements to combine with OR logic. You can use any statements
that can be nested.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::WAFV2>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

