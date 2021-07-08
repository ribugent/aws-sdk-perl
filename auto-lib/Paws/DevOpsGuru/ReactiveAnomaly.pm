# Generated by default/object.tt
package Paws::DevOpsGuru::ReactiveAnomaly;
  use Moose;
  has AnomalyTimeRange => (is => 'ro', isa => 'Paws::DevOpsGuru::AnomalyTimeRange');
  has AssociatedInsightId => (is => 'ro', isa => 'Str');
  has Id => (is => 'ro', isa => 'Str');
  has ResourceCollection => (is => 'ro', isa => 'Paws::DevOpsGuru::ResourceCollection');
  has Severity => (is => 'ro', isa => 'Str');
  has SourceDetails => (is => 'ro', isa => 'Paws::DevOpsGuru::AnomalySourceDetails');
  has Status => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::DevOpsGuru::ReactiveAnomaly

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::DevOpsGuru::ReactiveAnomaly object:

  $service_obj->Method(Att1 => { AnomalyTimeRange => $value, ..., Status => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::DevOpsGuru::ReactiveAnomaly object:

  $result = $service_obj->Method(...);
  $result->Att1->AnomalyTimeRange

=head1 DESCRIPTION

Details about a reactive anomaly. This object is returned by
C<ListAnomalies>.

=head1 ATTRIBUTES


=head2 AnomalyTimeRange => L<Paws::DevOpsGuru::AnomalyTimeRange>




=head2 AssociatedInsightId => Str

The ID of the insight that contains this anomaly. An insight is
composed of related anomalies.


=head2 Id => Str

The ID of the reactive anomaly.


=head2 ResourceCollection => L<Paws::DevOpsGuru::ResourceCollection>




=head2 Severity => Str

The severity of the anomaly.


=head2 SourceDetails => L<Paws::DevOpsGuru::AnomalySourceDetails>

Details about the source of the analyzed operational data that
triggered the anomaly. The one supported source is Amazon CloudWatch
metrics.


=head2 Status => Str

The status of the anomaly.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::DevOpsGuru>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

