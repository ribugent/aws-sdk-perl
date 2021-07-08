# Generated by default/object.tt
package Paws::SageMaker::TrafficRoutingConfig;
  use Moose;
  has CanarySize => (is => 'ro', isa => 'Paws::SageMaker::CapacitySize');
  has Type => (is => 'ro', isa => 'Str', required => 1);
  has WaitIntervalInSeconds => (is => 'ro', isa => 'Int', required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::SageMaker::TrafficRoutingConfig

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::SageMaker::TrafficRoutingConfig object:

  $service_obj->Method(Att1 => { CanarySize => $value, ..., WaitIntervalInSeconds => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::SageMaker::TrafficRoutingConfig object:

  $result = $service_obj->Method(...);
  $result->Att1->CanarySize

=head1 DESCRIPTION

Currently, the C<TrafficRoutingConfig> API is not supported.

=head1 ATTRIBUTES


=head2 CanarySize => L<Paws::SageMaker::CapacitySize>




=head2 B<REQUIRED> Type => Str




=head2 B<REQUIRED> WaitIntervalInSeconds => Int





=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::SageMaker>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

