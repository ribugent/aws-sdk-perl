
package Paws::AutoScaling::DescribeWarmPool;
  use Moose;
  has AutoScalingGroupName => (is => 'ro', isa => 'Str', required => 1);
  has MaxRecords => (is => 'ro', isa => 'Int');
  has NextToken => (is => 'ro', isa => 'Str');

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'DescribeWarmPool');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::AutoScaling::DescribeWarmPoolAnswer');
  class_has _result_key => (isa => 'Str', is => 'ro', default => 'DescribeWarmPoolResult');
1;

### main pod documentation begin ###

=head1 NAME

Paws::AutoScaling::DescribeWarmPool - Arguments for method DescribeWarmPool on L<Paws::AutoScaling>

=head1 DESCRIPTION

This class represents the parameters used for calling the method DescribeWarmPool on the
L<Auto Scaling|Paws::AutoScaling> service. Use the attributes of this class
as arguments to method DescribeWarmPool.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to DescribeWarmPool.

=head1 SYNOPSIS

    my $autoscaling = Paws->service('AutoScaling');
    my $DescribeWarmPoolAnswer = $autoscaling->DescribeWarmPool(
      AutoScalingGroupName => 'MyXmlStringMaxLen255',
      MaxRecords           => 1,                        # OPTIONAL
      NextToken            => 'MyXmlString',            # OPTIONAL
    );

    # Results:
    my $Instances             = $DescribeWarmPoolAnswer->Instances;
    my $NextToken             = $DescribeWarmPoolAnswer->NextToken;
    my $WarmPoolConfiguration = $DescribeWarmPoolAnswer->WarmPoolConfiguration;

    # Returns a L<Paws::AutoScaling::DescribeWarmPoolAnswer> object.

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/autoscaling/DescribeWarmPool>

=head1 ATTRIBUTES


=head2 B<REQUIRED> AutoScalingGroupName => Str

The name of the Auto Scaling group.



=head2 MaxRecords => Int

The maximum number of instances to return with this call. The maximum
value is C<50>.



=head2 NextToken => Str

The token for the next set of instances to return. (You received this
token from a previous call.)




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method DescribeWarmPool in L<Paws::AutoScaling>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

