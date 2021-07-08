# Generated by default/object.tt
package Paws::CodeGuruProfiler::Pattern;
  use Moose;
  has CountersToAggregate => (is => 'ro', isa => 'ArrayRef[Str|Undef]', request_name => 'countersToAggregate', traits => ['NameInRequest']);
  has Description => (is => 'ro', isa => 'Str', request_name => 'description', traits => ['NameInRequest']);
  has Id => (is => 'ro', isa => 'Str', request_name => 'id', traits => ['NameInRequest']);
  has Name => (is => 'ro', isa => 'Str', request_name => 'name', traits => ['NameInRequest']);
  has ResolutionSteps => (is => 'ro', isa => 'Str', request_name => 'resolutionSteps', traits => ['NameInRequest']);
  has TargetFrames => (is => 'ro', isa => 'ArrayRef[ArrayRef[Str|Undef]]', request_name => 'targetFrames', traits => ['NameInRequest']);
  has ThresholdPercent => (is => 'ro', isa => 'Num', request_name => 'thresholdPercent', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::CodeGuruProfiler::Pattern

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::CodeGuruProfiler::Pattern object:

  $service_obj->Method(Att1 => { CountersToAggregate => $value, ..., ThresholdPercent => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::CodeGuruProfiler::Pattern object:

  $result = $service_obj->Method(...);
  $result->Att1->CountersToAggregate

=head1 DESCRIPTION

A set of rules used to make a recommendation during an analysis.

=head1 ATTRIBUTES


=head2 CountersToAggregate => ArrayRef[Str|Undef]

A list of the different counters used to determine if there is a match.


=head2 Description => Str

The description of the recommendation. This explains a potential
inefficiency in a profiled application.


=head2 Id => Str

The universally unique identifier (UUID) of this pattern.


=head2 Name => Str

The name for this pattern.


=head2 ResolutionSteps => Str

A string that contains the steps recommended to address the potential
inefficiency.


=head2 TargetFrames => ArrayRef[ArrayRef[Str|Undef]]

A list of frame names that were searched during the analysis that
generated a recommendation.


=head2 ThresholdPercent => Num

The percentage of time an application spends in one method that
triggers a recommendation. The percentage of time is the same as the
percentage of the total gathered sample counts during analysis.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::CodeGuruProfiler>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

