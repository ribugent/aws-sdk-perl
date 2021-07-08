# Generated by default/object.tt
package Paws::MarketplaceMetering::UsageAllocation;
  use Moose;
  has AllocatedUsageQuantity => (is => 'ro', isa => 'Int', required => 1);
  has Tags => (is => 'ro', isa => 'ArrayRef[Paws::MarketplaceMetering::Tag]');

1;

### main pod documentation begin ###

=head1 NAME

Paws::MarketplaceMetering::UsageAllocation

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::MarketplaceMetering::UsageAllocation object:

  $service_obj->Method(Att1 => { AllocatedUsageQuantity => $value, ..., Tags => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::MarketplaceMetering::UsageAllocation object:

  $result = $service_obj->Method(...);
  $result->Att1->AllocatedUsageQuantity

=head1 DESCRIPTION

Usage allocations allow you to split usage into buckets by tags.

Each UsageAllocation indicates the usage quantity for a specific set of
tags.

=head1 ATTRIBUTES


=head2 B<REQUIRED> AllocatedUsageQuantity => Int

The total quantity allocated to this bucket of usage.


=head2 Tags => ArrayRef[L<Paws::MarketplaceMetering::Tag>]

The set of tags that define the bucket of usage. For the bucket of
items with no tags, this parameter can be left out.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::MarketplaceMetering>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

