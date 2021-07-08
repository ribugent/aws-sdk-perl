# Generated by default/object.tt
package Paws::AutoScaling::InstancesDistribution;
  use Moose;
  has OnDemandAllocationStrategy => (is => 'ro', isa => 'Str');
  has OnDemandBaseCapacity => (is => 'ro', isa => 'Int');
  has OnDemandPercentageAboveBaseCapacity => (is => 'ro', isa => 'Int');
  has SpotAllocationStrategy => (is => 'ro', isa => 'Str');
  has SpotInstancePools => (is => 'ro', isa => 'Int');
  has SpotMaxPrice => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::AutoScaling::InstancesDistribution

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::AutoScaling::InstancesDistribution object:

  $service_obj->Method(Att1 => { OnDemandAllocationStrategy => $value, ..., SpotMaxPrice => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::AutoScaling::InstancesDistribution object:

  $result = $service_obj->Method(...);
  $result->Att1->OnDemandAllocationStrategy

=head1 DESCRIPTION

Describes an instances distribution for an Auto Scaling group with a
MixedInstancesPolicy.

The instances distribution specifies the distribution of On-Demand
Instances and Spot Instances, the maximum price to pay for Spot
Instances, and how the Auto Scaling group allocates instance types to
fulfill On-Demand and Spot capacities.

When you update C<SpotAllocationStrategy>, C<SpotInstancePools>, or
C<SpotMaxPrice>, this update action does not deploy any changes across
the running Amazon EC2 instances in the group. Your existing Spot
Instances continue to run as long as the maximum price for those
instances is higher than the current Spot price. When scale out occurs,
Amazon EC2 Auto Scaling launches instances based on the new settings.
When scale in occurs, Amazon EC2 Auto Scaling terminates instances
according to the group's termination policies.

=head1 ATTRIBUTES


=head2 OnDemandAllocationStrategy => Str

Indicates how to allocate instance types to fulfill On-Demand capacity.
The only valid value is C<prioritized>, which is also the default
value. This strategy uses the order of instance types in the
C<LaunchTemplateOverrides> to define the launch priority of each
instance type. The first instance type in the array is prioritized
higher than the last. If all your On-Demand capacity cannot be
fulfilled using your highest priority instance, then the Auto Scaling
groups launches the remaining capacity using the second priority
instance type, and so on.


=head2 OnDemandBaseCapacity => Int

The minimum amount of the Auto Scaling group's capacity that must be
fulfilled by On-Demand Instances. This base portion is provisioned
first as your group scales. Defaults to 0 if not specified. If you
specify weights for the instance types in the overrides, set the value
of C<OnDemandBaseCapacity> in terms of the number of capacity units,
and not the number of instances.


=head2 OnDemandPercentageAboveBaseCapacity => Int

Controls the percentages of On-Demand Instances and Spot Instances for
your additional capacity beyond C<OnDemandBaseCapacity>. Expressed as a
number (for example, 20 specifies 20% On-Demand Instances, 80% Spot
Instances). Defaults to 100 if not specified. If set to 100, only
On-Demand Instances are provisioned.


=head2 SpotAllocationStrategy => Str

Indicates how to allocate instances across Spot Instance pools.

If the allocation strategy is C<lowest-price>, the Auto Scaling group
launches instances using the Spot pools with the lowest price, and
evenly allocates your instances across the number of Spot pools that
you specify. Defaults to C<lowest-price> if not specified.

If the allocation strategy is C<capacity-optimized> (recommended), the
Auto Scaling group launches instances using Spot pools that are
optimally chosen based on the available Spot capacity. Alternatively,
you can use C<capacity-optimized-prioritized> and set the order of
instance types in the list of launch template overrides from highest to
lowest priority (from first to last in the list). Amazon EC2 Auto
Scaling honors the instance type priorities on a best-effort basis but
optimizes for capacity first.


=head2 SpotInstancePools => Int

The number of Spot Instance pools across which to allocate your Spot
Instances. The Spot pools are determined from the different instance
types in the overrides. Valid only when the Spot allocation strategy is
C<lowest-price>. Value must be in the range of 1 to 20. Defaults to 2
if not specified.


=head2 SpotMaxPrice => Str

The maximum price per unit hour that you are willing to pay for a Spot
Instance. If you leave the value at its default (empty), Amazon EC2
Auto Scaling uses the On-Demand price as the maximum Spot price. To
remove a value that you previously set, include the property but
specify an empty string ("") for the value.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::AutoScaling>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

