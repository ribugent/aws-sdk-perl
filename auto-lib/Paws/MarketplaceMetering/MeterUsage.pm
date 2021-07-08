
package Paws::MarketplaceMetering::MeterUsage;
  use Moose;
  has DryRun => (is => 'ro', isa => 'Bool');
  has ProductCode => (is => 'ro', isa => 'Str', required => 1);
  has Timestamp => (is => 'ro', isa => 'Str', required => 1);
  has UsageAllocations => (is => 'ro', isa => 'ArrayRef[Paws::MarketplaceMetering::UsageAllocation]');
  has UsageDimension => (is => 'ro', isa => 'Str', required => 1);
  has UsageQuantity => (is => 'ro', isa => 'Int');

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'MeterUsage');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::MarketplaceMetering::MeterUsageResult');
  class_has _result_key => (isa => 'Str', is => 'ro');
1;

### main pod documentation begin ###

=head1 NAME

Paws::MarketplaceMetering::MeterUsage - Arguments for method MeterUsage on L<Paws::MarketplaceMetering>

=head1 DESCRIPTION

This class represents the parameters used for calling the method MeterUsage on the
L<AWSMarketplace Metering|Paws::MarketplaceMetering> service. Use the attributes of this class
as arguments to method MeterUsage.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to MeterUsage.

=head1 SYNOPSIS

    my $metering.marketplace = Paws->service('MarketplaceMetering');
    my $MeterUsageResult = $metering . marketplace->MeterUsage(
      ProductCode      => 'MyProductCode',
      Timestamp        => '1970-01-01T01:00:00',
      UsageDimension   => 'MyUsageDimension',
      DryRun           => 1,                       # OPTIONAL
      UsageAllocations => [
        {
          AllocatedUsageQuantity => 1,             # max: 2147483647
          Tags                   => [
            {
              Key   => 'MyTagKey',      # min: 1, max: 100
              Value => 'MyTagValue',    # min: 1, max: 256

            },
            ...
          ],    # min: 1, max: 5; OPTIONAL
        },
        ...
      ],    # OPTIONAL
      UsageQuantity => 1,    # OPTIONAL
    );

    # Results:
    my $MeteringRecordId = $MeterUsageResult->MeteringRecordId;

    # Returns a L<Paws::MarketplaceMetering::MeterUsageResult> object.

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/metering.marketplace/MeterUsage>

=head1 ATTRIBUTES


=head2 DryRun => Bool

Checks whether you have the permissions required for the action, but
does not make the request. If you have the permissions, the request
returns DryRunOperation; otherwise, it returns UnauthorizedException.
Defaults to C<false> if not specified.



=head2 B<REQUIRED> ProductCode => Str

Product code is used to uniquely identify a product in AWS Marketplace.
The product code should be the same as the one used during the
publishing of a new product.



=head2 B<REQUIRED> Timestamp => Str

Timestamp, in UTC, for which the usage is being reported. Your
application can meter usage for up to one hour in the past. Make sure
the timestamp value is not before the start of the software usage.



=head2 UsageAllocations => ArrayRef[L<Paws::MarketplaceMetering::UsageAllocation>]

The set of UsageAllocations to submit.

The sum of all UsageAllocation quantities must equal the UsageQuantity
of the MeterUsage request, and each UsageAllocation must have a unique
set of tags (include no tags).



=head2 B<REQUIRED> UsageDimension => Str

It will be one of the fcp dimension name provided during the publishing
of the product.



=head2 UsageQuantity => Int

Consumption value for the hour. Defaults to C<0> if not specified.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method MeterUsage in L<Paws::MarketplaceMetering>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

