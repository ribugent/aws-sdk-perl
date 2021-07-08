# Generated by default/object.tt
package Paws::CostExplorer::CostCategoryValues;
  use Moose;
  has Key => (is => 'ro', isa => 'Str');
  has MatchOptions => (is => 'ro', isa => 'ArrayRef[Str|Undef]');
  has Values => (is => 'ro', isa => 'ArrayRef[Str|Undef]');

1;

### main pod documentation begin ###

=head1 NAME

Paws::CostExplorer::CostCategoryValues

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::CostExplorer::CostCategoryValues object:

  $service_obj->Method(Att1 => { Key => $value, ..., Values => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::CostExplorer::CostCategoryValues object:

  $result = $service_obj->Method(...);
  $result->Att1->Key

=head1 DESCRIPTION

The Cost Categories values used for filtering the costs.

If C<Values> and C<Key> are not specified, the C<ABSENT> C<MatchOption>
is applied to all Cost Categories. That is, filtering on resources that
are not mapped to any Cost Categories.

If C<Values> is provided and C<Key> is not specified, the C<ABSENT>
C<MatchOption> is applied to the Cost Categories C<Key> only. That is,
filtering on resources without the given Cost Categories key.

=head1 ATTRIBUTES


=head2 Key => Str




=head2 MatchOptions => ArrayRef[Str|Undef]

The match options that you can use to filter your results. MatchOptions
is only applicable for actions related to cost category. The default
values for C<MatchOptions> is C<EQUALS> and C<CASE_SENSITIVE>.


=head2 Values => ArrayRef[Str|Undef]

The specific value of the Cost Category.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::CostExplorer>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

