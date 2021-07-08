# Generated by default/object.tt
package Paws::Budgets::ScpActionDefinition;
  use Moose;
  has PolicyId => (is => 'ro', isa => 'Str', required => 1);
  has TargetIds => (is => 'ro', isa => 'ArrayRef[Str|Undef]', required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::Budgets::ScpActionDefinition

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Budgets::ScpActionDefinition object:

  $service_obj->Method(Att1 => { PolicyId => $value, ..., TargetIds => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Budgets::ScpActionDefinition object:

  $result = $service_obj->Method(...);
  $result->Att1->PolicyId

=head1 DESCRIPTION

The service control policies (SCP) action definition details.

=head1 ATTRIBUTES


=head2 B<REQUIRED> PolicyId => Str

The policy ID attached.


=head2 B<REQUIRED> TargetIds => ArrayRef[Str|Undef]

A list of target IDs.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Budgets>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

