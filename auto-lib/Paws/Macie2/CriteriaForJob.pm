# Generated by default/object.tt
package Paws::Macie2::CriteriaForJob;
  use Moose;
  has SimpleCriterion => (is => 'ro', isa => 'Paws::Macie2::SimpleCriterionForJob', request_name => 'simpleCriterion', traits => ['NameInRequest']);
  has TagCriterion => (is => 'ro', isa => 'Paws::Macie2::TagCriterionForJob', request_name => 'tagCriterion', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::Macie2::CriteriaForJob

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Macie2::CriteriaForJob object:

  $service_obj->Method(Att1 => { SimpleCriterion => $value, ..., TagCriterion => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Macie2::CriteriaForJob object:

  $result = $service_obj->Method(...);
  $result->Att1->SimpleCriterion

=head1 DESCRIPTION

Specifies a property- or tag-based condition that defines criteria for
including or excluding S3 buckets from a classification job.

=head1 ATTRIBUTES


=head2 SimpleCriterion => L<Paws::Macie2::SimpleCriterionForJob>

A property-based condition that defines a property, operator, and one
or more values for including or excluding buckets from the job.


=head2 TagCriterion => L<Paws::Macie2::TagCriterionForJob>

A tag-based condition that defines an operator and tag keys, tag
values, or tag key and value pairs for including or excluding buckets
from the job.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Macie2>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

