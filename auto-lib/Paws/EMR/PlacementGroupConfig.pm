# Generated by default/object.tt
package Paws::EMR::PlacementGroupConfig;
  use Moose;
  has InstanceRole => (is => 'ro', isa => 'Str', required => 1);
  has PlacementStrategy => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::EMR::PlacementGroupConfig

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::EMR::PlacementGroupConfig object:

  $service_obj->Method(Att1 => { InstanceRole => $value, ..., PlacementStrategy => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::EMR::PlacementGroupConfig object:

  $result = $service_obj->Method(...);
  $result->Att1->InstanceRole

=head1 DESCRIPTION

Placement group configuration for an Amazon EMR cluster. The
configuration specifies the placement strategy that can be applied to
instance roles during cluster creation.

To use this configuration, consider attaching managed policy
AmazonElasticMapReducePlacementGroupPolicy to the EMR role.

=head1 ATTRIBUTES


=head2 B<REQUIRED> InstanceRole => Str

Role of the instance in the cluster.

Starting with Amazon EMR version 5.23.0, the only supported instance
role is C<MASTER>.


=head2 PlacementStrategy => Str

EC2 Placement Group strategy associated with instance role.

Starting with Amazon EMR version 5.23.0, the only supported placement
strategy is C<SPREAD> for the C<MASTER> instance role.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::EMR>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

