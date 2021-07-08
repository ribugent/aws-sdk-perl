# Generated by default/object.tt
package Paws::SSMIncidents::IncidentRecord;
  use Moose;
  has Arn => (is => 'ro', isa => 'Str', request_name => 'arn', traits => ['NameInRequest'], required => 1);
  has AutomationExecutions => (is => 'ro', isa => 'ArrayRef[Paws::SSMIncidents::AutomationExecution]', request_name => 'automationExecutions', traits => ['NameInRequest']);
  has ChatChannel => (is => 'ro', isa => 'Paws::SSMIncidents::ChatChannel', request_name => 'chatChannel', traits => ['NameInRequest']);
  has CreationTime => (is => 'ro', isa => 'Str', request_name => 'creationTime', traits => ['NameInRequest'], required => 1);
  has DedupeString => (is => 'ro', isa => 'Str', request_name => 'dedupeString', traits => ['NameInRequest'], required => 1);
  has Impact => (is => 'ro', isa => 'Int', request_name => 'impact', traits => ['NameInRequest'], required => 1);
  has IncidentRecordSource => (is => 'ro', isa => 'Paws::SSMIncidents::IncidentRecordSource', request_name => 'incidentRecordSource', traits => ['NameInRequest'], required => 1);
  has LastModifiedBy => (is => 'ro', isa => 'Str', request_name => 'lastModifiedBy', traits => ['NameInRequest'], required => 1);
  has LastModifiedTime => (is => 'ro', isa => 'Str', request_name => 'lastModifiedTime', traits => ['NameInRequest'], required => 1);
  has NotificationTargets => (is => 'ro', isa => 'ArrayRef[Paws::SSMIncidents::NotificationTargetItem]', request_name => 'notificationTargets', traits => ['NameInRequest']);
  has ResolvedTime => (is => 'ro', isa => 'Str', request_name => 'resolvedTime', traits => ['NameInRequest']);
  has Status => (is => 'ro', isa => 'Str', request_name => 'status', traits => ['NameInRequest'], required => 1);
  has Summary => (is => 'ro', isa => 'Str', request_name => 'summary', traits => ['NameInRequest']);
  has Title => (is => 'ro', isa => 'Str', request_name => 'title', traits => ['NameInRequest'], required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::SSMIncidents::IncidentRecord

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::SSMIncidents::IncidentRecord object:

  $service_obj->Method(Att1 => { Arn => $value, ..., Title => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::SSMIncidents::IncidentRecord object:

  $result = $service_obj->Method(...);
  $result->Att1->Arn

=head1 DESCRIPTION

The record of the incident that's created when an incident occurs.

=head1 ATTRIBUTES


=head2 B<REQUIRED> Arn => Str

The Amazon Resource Name (ARN) of the incident record.


=head2 AutomationExecutions => ArrayRef[L<Paws::SSMIncidents::AutomationExecution>]

The runbook, or automation document, that's run at the beginning of the
incident.


=head2 ChatChannel => L<Paws::SSMIncidents::ChatChannel>

The chat channel used for collaboration during an incident.


=head2 B<REQUIRED> CreationTime => Str

The time that Incident Manager created the incident record.


=head2 B<REQUIRED> DedupeString => Str

The string Incident Manager uses to prevent duplicate incidents from
being created by the same incident.


=head2 B<REQUIRED> Impact => Int

The impact of the incident on customers and applications.


=head2 B<REQUIRED> IncidentRecordSource => L<Paws::SSMIncidents::IncidentRecordSource>

Details about the action that started the incident.


=head2 B<REQUIRED> LastModifiedBy => Str

Who modified the incident most recently.


=head2 B<REQUIRED> LastModifiedTime => Str

The time at which the incident was most recently modified.


=head2 NotificationTargets => ArrayRef[L<Paws::SSMIncidents::NotificationTargetItem>]

The SNS targets that AWS Chatbot uses to notify the chat channels and
perform actions on the incident record.


=head2 ResolvedTime => Str

The time at which the incident was resolved. This appears as a timeline
event.


=head2 B<REQUIRED> Status => Str

The current status of the incident.


=head2 Summary => Str

The summary of the incident. The summary is a brief synopsis of what
occurred, what is currently happening, and context.


=head2 B<REQUIRED> Title => Str

The title of the incident.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::SSMIncidents>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

