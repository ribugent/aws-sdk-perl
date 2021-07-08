# Generated by default/object.tt
package Paws::AutoScaling::InstanceRefresh;
  use Moose;
  has AutoScalingGroupName => (is => 'ro', isa => 'Str');
  has EndTime => (is => 'ro', isa => 'Str');
  has InstanceRefreshId => (is => 'ro', isa => 'Str');
  has InstancesToUpdate => (is => 'ro', isa => 'Int');
  has PercentageComplete => (is => 'ro', isa => 'Int');
  has ProgressDetails => (is => 'ro', isa => 'Paws::AutoScaling::InstanceRefreshProgressDetails');
  has StartTime => (is => 'ro', isa => 'Str');
  has Status => (is => 'ro', isa => 'Str');
  has StatusReason => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::AutoScaling::InstanceRefresh

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::AutoScaling::InstanceRefresh object:

  $service_obj->Method(Att1 => { AutoScalingGroupName => $value, ..., StatusReason => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::AutoScaling::InstanceRefresh object:

  $result = $service_obj->Method(...);
  $result->Att1->AutoScalingGroupName

=head1 DESCRIPTION

Describes an instance refresh for an Auto Scaling group.

=head1 ATTRIBUTES


=head2 AutoScalingGroupName => Str

The name of the Auto Scaling group.


=head2 EndTime => Str

The date and time at which the instance refresh ended.


=head2 InstanceRefreshId => Str

The instance refresh ID.


=head2 InstancesToUpdate => Int

The number of instances remaining to update before the instance refresh
is complete.


=head2 PercentageComplete => Int

The percentage of the instance refresh that is complete. For each
instance replacement, Amazon EC2 Auto Scaling tracks the instance's
health status and warm-up time. When the instance's health status
changes to healthy and the specified warm-up time passes, the instance
is considered updated and is added to the percentage complete.


=head2 ProgressDetails => L<Paws::AutoScaling::InstanceRefreshProgressDetails>

Additional progress details for an Auto Scaling group that has a warm
pool.


=head2 StartTime => Str

The date and time at which the instance refresh began.


=head2 Status => Str

The current status for the instance refresh operation:

=over

=item *

C<Pending> - The request was created, but the operation has not
started.

=item *

C<InProgress> - The operation is in progress.

=item *

C<Successful> - The operation completed successfully.

=item *

C<Failed> - The operation failed to complete. You can troubleshoot
using the status reason and the scaling activities.

=item *

C<Cancelling> - An ongoing operation is being cancelled. Cancellation
does not roll back any replacements that have already been completed,
but it prevents new replacements from being started.

=item *

C<Cancelled> - The operation is cancelled.

=back



=head2 StatusReason => Str

Provides more details about the current status of the instance refresh.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::AutoScaling>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

