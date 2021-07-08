# Generated by default/object.tt
package Paws::XRay::InsightEvent;
  use Moose;
  has ClientRequestImpactStatistics => (is => 'ro', isa => 'Paws::XRay::RequestImpactStatistics');
  has EventTime => (is => 'ro', isa => 'Str');
  has RootCauseServiceRequestImpactStatistics => (is => 'ro', isa => 'Paws::XRay::RequestImpactStatistics');
  has Summary => (is => 'ro', isa => 'Str');
  has TopAnomalousServices => (is => 'ro', isa => 'ArrayRef[Paws::XRay::AnomalousService]');

1;

### main pod documentation begin ###

=head1 NAME

Paws::XRay::InsightEvent

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::XRay::InsightEvent object:

  $service_obj->Method(Att1 => { ClientRequestImpactStatistics => $value, ..., TopAnomalousServices => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::XRay::InsightEvent object:

  $result = $service_obj->Method(...);
  $result->Att1->ClientRequestImpactStatistics

=head1 DESCRIPTION

X-Ray reevaluates insights periodically until they are resolved, and
records each intermediate state in an event. You can review incident
events in the Impact Timeline on the Inspect page in the X-Ray console.

=head1 ATTRIBUTES


=head2 ClientRequestImpactStatistics => L<Paws::XRay::RequestImpactStatistics>

The impact statistics of the client side service. This includes the
number of requests to the client service and whether the requests were
faults or okay.


=head2 EventTime => Str

The time, in Unix seconds, at which the event was recorded.


=head2 RootCauseServiceRequestImpactStatistics => L<Paws::XRay::RequestImpactStatistics>

The impact statistics of the root cause service. This includes the
number of requests to the client service and whether the requests were
faults or okay.


=head2 Summary => Str

A brief description of the event.


=head2 TopAnomalousServices => ArrayRef[L<Paws::XRay::AnomalousService>]

The service during the event that is most impacted by the incident.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::XRay>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

