# Generated by default/object.tt
package Paws::SageMaker::Pipeline;
  use Moose;
  has CreatedBy => (is => 'ro', isa => 'Paws::SageMaker::UserContext');
  has CreationTime => (is => 'ro', isa => 'Str');
  has LastModifiedBy => (is => 'ro', isa => 'Paws::SageMaker::UserContext');
  has LastModifiedTime => (is => 'ro', isa => 'Str');
  has LastRunTime => (is => 'ro', isa => 'Str');
  has PipelineArn => (is => 'ro', isa => 'Str');
  has PipelineDescription => (is => 'ro', isa => 'Str');
  has PipelineDisplayName => (is => 'ro', isa => 'Str');
  has PipelineName => (is => 'ro', isa => 'Str');
  has PipelineStatus => (is => 'ro', isa => 'Str');
  has RoleArn => (is => 'ro', isa => 'Str');
  has Tags => (is => 'ro', isa => 'ArrayRef[Paws::SageMaker::Tag]');

1;

### main pod documentation begin ###

=head1 NAME

Paws::SageMaker::Pipeline

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::SageMaker::Pipeline object:

  $service_obj->Method(Att1 => { CreatedBy => $value, ..., Tags => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::SageMaker::Pipeline object:

  $result = $service_obj->Method(...);
  $result->Att1->CreatedBy

=head1 DESCRIPTION

A SageMaker Model Building Pipeline instance.

=head1 ATTRIBUTES


=head2 CreatedBy => L<Paws::SageMaker::UserContext>




=head2 CreationTime => Str

The creation time of the pipeline.


=head2 LastModifiedBy => L<Paws::SageMaker::UserContext>




=head2 LastModifiedTime => Str

The time that the pipeline was last modified.


=head2 LastRunTime => Str

The time when the pipeline was last run.


=head2 PipelineArn => Str

The Amazon Resource Name (ARN) of the pipeline.


=head2 PipelineDescription => Str

The description of the pipeline.


=head2 PipelineDisplayName => Str

The display name of the pipeline.


=head2 PipelineName => Str

The name of the pipeline.


=head2 PipelineStatus => Str

The status of the pipeline.


=head2 RoleArn => Str

The Amazon Resource Name (ARN) of the role that created the pipeline.


=head2 Tags => ArrayRef[L<Paws::SageMaker::Tag>]

A list of tags that apply to the pipeline.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::SageMaker>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

