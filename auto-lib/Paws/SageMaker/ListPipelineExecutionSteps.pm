
package Paws::SageMaker::ListPipelineExecutionSteps;
  use Moose;
  has MaxResults => (is => 'ro', isa => 'Int');
  has NextToken => (is => 'ro', isa => 'Str');
  has PipelineExecutionArn => (is => 'ro', isa => 'Str');
  has SortOrder => (is => 'ro', isa => 'Str');

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'ListPipelineExecutionSteps');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::SageMaker::ListPipelineExecutionStepsResponse');
  class_has _result_key => (isa => 'Str', is => 'ro');
1;

### main pod documentation begin ###

=head1 NAME

Paws::SageMaker::ListPipelineExecutionSteps - Arguments for method ListPipelineExecutionSteps on L<Paws::SageMaker>

=head1 DESCRIPTION

This class represents the parameters used for calling the method ListPipelineExecutionSteps on the
L<Amazon SageMaker Service|Paws::SageMaker> service. Use the attributes of this class
as arguments to method ListPipelineExecutionSteps.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to ListPipelineExecutionSteps.

=head1 SYNOPSIS

    my $api.sagemaker = Paws->service('SageMaker');
    my $ListPipelineExecutionStepsResponse =
      $api . sagemaker->ListPipelineExecutionSteps(
      MaxResults           => 1,                           # OPTIONAL
      NextToken            => 'MyNextToken',               # OPTIONAL
      PipelineExecutionArn => 'MyPipelineExecutionArn',    # OPTIONAL
      SortOrder            => 'Ascending',                 # OPTIONAL
      );

    # Results:
    my $NextToken = $ListPipelineExecutionStepsResponse->NextToken;
    my $PipelineExecutionSteps =
      $ListPipelineExecutionStepsResponse->PipelineExecutionSteps;

    # Returns a L<Paws::SageMaker::ListPipelineExecutionStepsResponse> object.

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/api.sagemaker/ListPipelineExecutionSteps>

=head1 ATTRIBUTES


=head2 MaxResults => Int

The maximum number of pipeline execution steps to return in the
response.



=head2 NextToken => Str

If the result of the previous C<ListPipelineExecutionSteps> request was
truncated, the response includes a C<NextToken>. To retrieve the next
set of pipeline execution steps, use the token in the next request.



=head2 PipelineExecutionArn => Str

The Amazon Resource Name (ARN) of the pipeline execution.



=head2 SortOrder => Str

The field by which to sort results. The default is C<CreatedTime>.

Valid values are: C<"Ascending">, C<"Descending">


=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method ListPipelineExecutionSteps in L<Paws::SageMaker>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

