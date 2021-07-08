# Generated by default/object.tt
package Paws::XRay::InsightSummary;
  use Moose;
  has Categories => (is => 'ro', isa => 'ArrayRef[Str|Undef]');
  has ClientRequestImpactStatistics => (is => 'ro', isa => 'Paws::XRay::RequestImpactStatistics');
  has EndTime => (is => 'ro', isa => 'Str');
  has GroupARN => (is => 'ro', isa => 'Str');
  has GroupName => (is => 'ro', isa => 'Str');
  has InsightId => (is => 'ro', isa => 'Str');
  has LastUpdateTime => (is => 'ro', isa => 'Str');
  has RootCauseServiceId => (is => 'ro', isa => 'Paws::XRay::ServiceId');
  has RootCauseServiceRequestImpactStatistics => (is => 'ro', isa => 'Paws::XRay::RequestImpactStatistics');
  has StartTime => (is => 'ro', isa => 'Str');
  has State => (is => 'ro', isa => 'Str');
  has Summary => (is => 'ro', isa => 'Str');
  has TopAnomalousServices => (is => 'ro', isa => 'ArrayRef[Paws::XRay::AnomalousService]');

1;

### main pod documentation begin ###

=head1 NAME

Paws::XRay::InsightSummary

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::XRay::InsightSummary object:

  $service_obj->Method(Att1 => { Categories => $value, ..., TopAnomalousServices => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::XRay::InsightSummary object:

  $result = $service_obj->Method(...);
  $result->Att1->Categories

=head1 DESCRIPTION

Information that describes an insight.

=head1 ATTRIBUTES


=head2 Categories => ArrayRef[Str|Undef]

Categories The categories that label and describe the type of insight.


=head2 ClientRequestImpactStatistics => L<Paws::XRay::RequestImpactStatistics>

The impact statistics of the client side service. This includes the
number of requests to the client service and whether the requests were
faults or okay.


=head2 EndTime => Str

The time, in Unix seconds, at which the insight ended.


=head2 GroupARN => Str

The Amazon Resource Name (ARN) of the group that the insight belongs
to.


=head2 GroupName => Str

The name of the group that the insight belongs to.


=head2 InsightId => Str

The insights unique identifier.


=head2 LastUpdateTime => Str

The time, in Unix seconds, that the insight was last updated.


=head2 RootCauseServiceId => L<Paws::XRay::ServiceId>




=head2 RootCauseServiceRequestImpactStatistics => L<Paws::XRay::RequestImpactStatistics>

The impact statistics of the root cause service. This includes the
number of requests to the client service and whether the requests were
faults or okay.


=head2 StartTime => Str

The time, in Unix seconds, at which the insight began.


=head2 State => Str

The current state of the insight.


=head2 Summary => Str

A brief description of the insight.


=head2 TopAnomalousServices => ArrayRef[L<Paws::XRay::AnomalousService>]

The service within the insight that is most impacted by the incident.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::XRay>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

