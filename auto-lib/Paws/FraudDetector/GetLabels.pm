
package Paws::FraudDetector::GetLabels;
  use Moose;
  has MaxResults => (is => 'ro', isa => 'Int', traits => ['NameInRequest'], request_name => 'maxResults' );
  has Name => (is => 'ro', isa => 'Str', traits => ['NameInRequest'], request_name => 'name' );
  has NextToken => (is => 'ro', isa => 'Str', traits => ['NameInRequest'], request_name => 'nextToken' );

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'GetLabels');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::FraudDetector::GetLabelsResult');
  class_has _result_key => (isa => 'Str', is => 'ro');
1;

### main pod documentation begin ###

=head1 NAME

Paws::FraudDetector::GetLabels - Arguments for method GetLabels on L<Paws::FraudDetector>

=head1 DESCRIPTION

This class represents the parameters used for calling the method GetLabels on the
L<Amazon Fraud Detector|Paws::FraudDetector> service. Use the attributes of this class
as arguments to method GetLabels.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to GetLabels.

=head1 SYNOPSIS

    my $frauddetector = Paws->service('FraudDetector');
    my $GetLabelsResult = $frauddetector->GetLabels(
      MaxResults => 1,                 # OPTIONAL
      Name       => 'Myidentifier',    # OPTIONAL
      NextToken  => 'Mystring',        # OPTIONAL
    );

    # Results:
    my $Labels    = $GetLabelsResult->Labels;
    my $NextToken = $GetLabelsResult->NextToken;

    # Returns a L<Paws::FraudDetector::GetLabelsResult> object.

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/frauddetector/GetLabels>

=head1 ATTRIBUTES


=head2 MaxResults => Int

The maximum number of objects to return for the request.



=head2 Name => Str

The name of the label or labels to get.



=head2 NextToken => Str

The next token for the subsequent request.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method GetLabels in L<Paws::FraudDetector>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

