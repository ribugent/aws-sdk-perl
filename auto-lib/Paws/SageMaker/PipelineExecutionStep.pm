# Generated by default/object.tt
package Paws::SageMaker::PipelineExecutionStep;
  use Moose;
  has CacheHitResult => (is => 'ro', isa => 'Paws::SageMaker::CacheHitResult');
  has EndTime => (is => 'ro', isa => 'Str');
  has FailureReason => (is => 'ro', isa => 'Str');
  has Metadata => (is => 'ro', isa => 'Paws::SageMaker::PipelineExecutionStepMetadata');
  has StartTime => (is => 'ro', isa => 'Str');
  has StepName => (is => 'ro', isa => 'Str');
  has StepStatus => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::SageMaker::PipelineExecutionStep

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::SageMaker::PipelineExecutionStep object:

  $service_obj->Method(Att1 => { CacheHitResult => $value, ..., StepStatus => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::SageMaker::PipelineExecutionStep object:

  $result = $service_obj->Method(...);
  $result->Att1->CacheHitResult

=head1 DESCRIPTION

An execution of a step in a pipeline.

=head1 ATTRIBUTES


=head2 CacheHitResult => L<Paws::SageMaker::CacheHitResult>

If this pipeline execution step was cached, details on the cache hit.


=head2 EndTime => Str

The time that the step stopped executing.


=head2 FailureReason => Str

The reason why the step failed execution. This is only returned if the
step failed its execution.


=head2 Metadata => L<Paws::SageMaker::PipelineExecutionStepMetadata>

Metadata for the step execution.


=head2 StartTime => Str

The time that the step started executing.


=head2 StepName => Str

The name of the step that is executed.


=head2 StepStatus => Str

The status of the step execution.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::SageMaker>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

