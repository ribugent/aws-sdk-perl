# Generated by default/object.tt
package Paws::WellArchitected::PillarReviewSummary;
  use Moose;
  has Notes => (is => 'ro', isa => 'Str');
  has PillarId => (is => 'ro', isa => 'Str');
  has PillarName => (is => 'ro', isa => 'Str');
  has RiskCounts => (is => 'ro', isa => 'Paws::WellArchitected::RiskCounts');

1;

### main pod documentation begin ###

=head1 NAME

Paws::WellArchitected::PillarReviewSummary

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::WellArchitected::PillarReviewSummary object:

  $service_obj->Method(Att1 => { Notes => $value, ..., RiskCounts => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::WellArchitected::PillarReviewSummary object:

  $result = $service_obj->Method(...);
  $result->Att1->Notes

=head1 DESCRIPTION

A pillar review summary of a lens review.

=head1 ATTRIBUTES


=head2 Notes => Str




=head2 PillarId => Str




=head2 PillarName => Str




=head2 RiskCounts => L<Paws::WellArchitected::RiskCounts>





=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::WellArchitected>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

