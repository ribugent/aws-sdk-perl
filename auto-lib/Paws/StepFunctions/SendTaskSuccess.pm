
package Paws::StepFunctions::SendTaskSuccess;
  use Moose;
  has Output => (is => 'ro', isa => 'Str', traits => ['NameInRequest'], request_name => 'output' , required => 1);
  has TaskToken => (is => 'ro', isa => 'Str', traits => ['NameInRequest'], request_name => 'taskToken' , required => 1);

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'SendTaskSuccess');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::StepFunctions::SendTaskSuccessOutput');
  class_has _result_key => (isa => 'Str', is => 'ro');
1;

### main pod documentation begin ###

=head1 NAME

Paws::StepFunctions::SendTaskSuccess - Arguments for method SendTaskSuccess on L<Paws::StepFunctions>

=head1 DESCRIPTION

This class represents the parameters used for calling the method SendTaskSuccess on the
L<AWS Step Functions|Paws::StepFunctions> service. Use the attributes of this class
as arguments to method SendTaskSuccess.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to SendTaskSuccess.

=head1 SYNOPSIS

    my $states = Paws->service('StepFunctions');
    my $SendTaskSuccessOutput = $states->SendTaskSuccess(
      Output    => 'MySensitiveData',
      TaskToken => 'MyTaskToken',

    );

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/states/SendTaskSuccess>

=head1 ATTRIBUTES


=head2 B<REQUIRED> Output => Str

The JSON output of the task. Length constraints apply to the payload
size, and are expressed as bytes in UTF-8 encoding.



=head2 B<REQUIRED> TaskToken => Str

The token that represents this task. Task tokens are generated by Step
Functions when tasks are assigned to a worker, or in the context object
(https://docs.aws.amazon.com/step-functions/latest/dg/input-output-contextobject.html)
when a workflow enters a task state. See
GetActivityTaskOutput$taskToken.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method SendTaskSuccess in L<Paws::StepFunctions>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

