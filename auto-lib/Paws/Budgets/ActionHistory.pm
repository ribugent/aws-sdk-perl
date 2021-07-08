# Generated by default/object.tt
package Paws::Budgets::ActionHistory;
  use Moose;
  has ActionHistoryDetails => (is => 'ro', isa => 'Paws::Budgets::ActionHistoryDetails', required => 1);
  has EventType => (is => 'ro', isa => 'Str', required => 1);
  has Status => (is => 'ro', isa => 'Str', required => 1);
  has Timestamp => (is => 'ro', isa => 'Str', required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::Budgets::ActionHistory

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Budgets::ActionHistory object:

  $service_obj->Method(Att1 => { ActionHistoryDetails => $value, ..., Timestamp => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Budgets::ActionHistory object:

  $result = $service_obj->Method(...);
  $result->Att1->ActionHistoryDetails

=head1 DESCRIPTION

The historical records for a budget action.

=head1 ATTRIBUTES


=head2 B<REQUIRED> ActionHistoryDetails => L<Paws::Budgets::ActionHistoryDetails>

The description of details of the event.


=head2 B<REQUIRED> EventType => Str

This distinguishes between whether the events are triggered by the user
or generated by the system.


=head2 B<REQUIRED> Status => Str

The status of action at the time of the event.


=head2 B<REQUIRED> Timestamp => Str





=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Budgets>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

