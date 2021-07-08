
package Paws::LookoutMetrics::ListAnomalyDetectors;
  use Moose;
  has MaxResults => (is => 'ro', isa => 'Int');
  has NextToken => (is => 'ro', isa => 'Str');

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'ListAnomalyDetectors');
  class_has _api_uri  => (isa => 'Str', is => 'ro', default => '/ListAnomalyDetectors');
  class_has _api_method  => (isa => 'Str', is => 'ro', default => 'POST');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::LookoutMetrics::ListAnomalyDetectorsResponse');
1;

### main pod documentation begin ###

=head1 NAME

Paws::LookoutMetrics::ListAnomalyDetectors - Arguments for method ListAnomalyDetectors on L<Paws::LookoutMetrics>

=head1 DESCRIPTION

This class represents the parameters used for calling the method ListAnomalyDetectors on the
L<Amazon Lookout for Metrics|Paws::LookoutMetrics> service. Use the attributes of this class
as arguments to method ListAnomalyDetectors.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to ListAnomalyDetectors.

=head1 SYNOPSIS

    my $lookoutmetrics = Paws->service('LookoutMetrics');
    my $ListAnomalyDetectorsResponse = $lookoutmetrics->ListAnomalyDetectors(
      MaxResults => 1,                # OPTIONAL
      NextToken  => 'MyNextToken',    # OPTIONAL
    );

    # Results:
    my $AnomalyDetectorSummaryList =
      $ListAnomalyDetectorsResponse->AnomalyDetectorSummaryList;
    my $NextToken = $ListAnomalyDetectorsResponse->NextToken;

    # Returns a L<Paws::LookoutMetrics::ListAnomalyDetectorsResponse> object.

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/lookoutmetrics/ListAnomalyDetectors>

=head1 ATTRIBUTES


=head2 MaxResults => Int

The maximum number of results to return.



=head2 NextToken => Str

If the result of the previous request was truncated, the response
includes a C<NextToken>. To retrieve the next set of results, use the
token in the next request. Tokens expire after 24 hours.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method ListAnomalyDetectors in L<Paws::LookoutMetrics>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

