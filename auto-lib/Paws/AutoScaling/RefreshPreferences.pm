# Generated by default/object.tt
package Paws::AutoScaling::RefreshPreferences;
  use Moose;
  has CheckpointDelay => (is => 'ro', isa => 'Int');
  has CheckpointPercentages => (is => 'ro', isa => 'ArrayRef[Int]');
  has InstanceWarmup => (is => 'ro', isa => 'Int');
  has MinHealthyPercentage => (is => 'ro', isa => 'Int');

1;

### main pod documentation begin ###

=head1 NAME

Paws::AutoScaling::RefreshPreferences

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::AutoScaling::RefreshPreferences object:

  $service_obj->Method(Att1 => { CheckpointDelay => $value, ..., MinHealthyPercentage => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::AutoScaling::RefreshPreferences object:

  $result = $service_obj->Method(...);
  $result->Att1->CheckpointDelay

=head1 DESCRIPTION

Describes information used to start an instance refresh.

All properties are optional. However, if you specify a value for
C<CheckpointDelay>, you must also provide a value for
C<CheckpointPercentages>.

=head1 ATTRIBUTES


=head2 CheckpointDelay => Int

The amount of time, in seconds, to wait after a checkpoint before
continuing. This property is optional, but if you specify a value for
it, you must also specify a value for C<CheckpointPercentages>. If you
specify a value for C<CheckpointPercentages> and not for
C<CheckpointDelay>, the C<CheckpointDelay> defaults to C<3600> (1
hour).


=head2 CheckpointPercentages => ArrayRef[Int]

Threshold values for each checkpoint in ascending order. Each number
must be unique. To replace all instances in the Auto Scaling group, the
last number in the array must be C<100>.

For usage examples, see Adding checkpoints to an instance refresh
(https://docs.aws.amazon.com/autoscaling/ec2/userguide/asg-adding-checkpoints-instance-refresh.html)
in the I<Amazon EC2 Auto Scaling User Guide>.


=head2 InstanceWarmup => Int

The number of seconds until a newly launched instance is configured and
ready to use. During this time, Amazon EC2 Auto Scaling does not
immediately move on to the next replacement. The default is to use the
value for the health check grace period defined for the group.


=head2 MinHealthyPercentage => Int

The amount of capacity in the Auto Scaling group that must remain
healthy during an instance refresh to allow the operation to continue,
as a percentage of the desired capacity of the Auto Scaling group
(rounded up to the nearest integer). The default is C<90>.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::AutoScaling>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

