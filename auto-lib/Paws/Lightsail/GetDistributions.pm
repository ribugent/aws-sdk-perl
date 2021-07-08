
package Paws::Lightsail::GetDistributions;
  use Moose;
  has DistributionName => (is => 'ro', isa => 'Str', traits => ['NameInRequest'], request_name => 'distributionName' );
  has PageToken => (is => 'ro', isa => 'Str', traits => ['NameInRequest'], request_name => 'pageToken' );

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'GetDistributions');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::Lightsail::GetDistributionsResult');
  class_has _result_key => (isa => 'Str', is => 'ro');
1;

### main pod documentation begin ###

=head1 NAME

Paws::Lightsail::GetDistributions - Arguments for method GetDistributions on L<Paws::Lightsail>

=head1 DESCRIPTION

This class represents the parameters used for calling the method GetDistributions on the
L<Amazon Lightsail|Paws::Lightsail> service. Use the attributes of this class
as arguments to method GetDistributions.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to GetDistributions.

=head1 SYNOPSIS

    my $lightsail = Paws->service('Lightsail');
    my $GetDistributionsResult = $lightsail->GetDistributions(
      DistributionName => 'MyResourceName',    # OPTIONAL
      PageToken        => 'Mystring',          # OPTIONAL
    );

    # Results:
    my $Distributions = $GetDistributionsResult->Distributions;
    my $NextPageToken = $GetDistributionsResult->NextPageToken;

    # Returns a L<Paws::Lightsail::GetDistributionsResult> object.

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/lightsail/GetDistributions>

=head1 ATTRIBUTES


=head2 DistributionName => Str

The name of the distribution for which to return information.

Use the C<GetDistributions> action to get a list of distribution names
that you can specify.

When omitted, the response includes all of your distributions in the
AWS Region where the request is made.



=head2 PageToken => Str

The token to advance to the next page of results from your request.

To get a page token, perform an initial C<GetDistributions> request. If
your results are paginated, the response will return a next page token
that you can specify as the page token in a subsequent request.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method GetDistributions in L<Paws::Lightsail>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

