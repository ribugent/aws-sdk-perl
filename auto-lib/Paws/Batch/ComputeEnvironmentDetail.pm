package Paws::Batch::ComputeEnvironmentDetail;
  use Moose;
  has ComputeEnvironmentArn => (is => 'ro', isa => 'Str', xmlname => 'computeEnvironmentArn', request_name => 'computeEnvironmentArn', traits => ['Unwrapped','NameInRequest'], required => 1);
  has ComputeEnvironmentName => (is => 'ro', isa => 'Str', xmlname => 'computeEnvironmentName', request_name => 'computeEnvironmentName', traits => ['Unwrapped','NameInRequest'], required => 1);
  has ComputeResources => (is => 'ro', isa => 'Paws::Batch::ComputeResource', xmlname => 'computeResources', request_name => 'computeResources', traits => ['Unwrapped','NameInRequest']);
  has EcsClusterArn => (is => 'ro', isa => 'Str', xmlname => 'ecsClusterArn', request_name => 'ecsClusterArn', traits => ['Unwrapped','NameInRequest'], required => 1);
  has ServiceRole => (is => 'ro', isa => 'Str', xmlname => 'serviceRole', request_name => 'serviceRole', traits => ['Unwrapped','NameInRequest']);
  has State => (is => 'ro', isa => 'Str', xmlname => 'state', request_name => 'state', traits => ['Unwrapped','NameInRequest']);
  has Status => (is => 'ro', isa => 'Str', xmlname => 'status', request_name => 'status', traits => ['Unwrapped','NameInRequest']);
  has StatusReason => (is => 'ro', isa => 'Str', xmlname => 'statusReason', request_name => 'statusReason', traits => ['Unwrapped','NameInRequest']);
  has Type => (is => 'ro', isa => 'Str', xmlname => 'type', request_name => 'type', traits => ['Unwrapped','NameInRequest']);
1;

### main pod documentation begin ###

=head1 NAME

Paws::Batch::ComputeEnvironmentDetail

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Batch::ComputeEnvironmentDetail object:

  $service_obj->Method(Att1 => { ComputeEnvironmentArn => $value, ..., Type => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Batch::ComputeEnvironmentDetail object:

  $result = $service_obj->Method(...);
  $result->Att1->ComputeEnvironmentArn

=head1 DESCRIPTION

An object representing an AWS Batch compute environment.

=head1 ATTRIBUTES


=head2 B<REQUIRED> ComputeEnvironmentArn => Str

  The Amazon Resource Name (ARN) of the compute environment.


=head2 B<REQUIRED> ComputeEnvironmentName => Str

  The name of the compute environment.


=head2 ComputeResources => L<Paws::Batch::ComputeResource>

  The compute resources defined for the compute environment.


=head2 B<REQUIRED> EcsClusterArn => Str

  The Amazon Resource Name (ARN) of the underlying Amazon ECS cluster
used by the compute environment.


=head2 ServiceRole => Str

  The service role associated with the compute environment that allows
AWS Batch to make calls to AWS API operations on your behalf.


=head2 State => Str

  The state of the compute environment. The valid values are C<ENABLED>
or C<DISABLED>. An C<ENABLED> state indicates that you can register
instances with the compute environment and that the associated
instances can accept jobs.


=head2 Status => Str

  The current status of the compute environment (for example, C<CREATING>
or C<VALID>).


=head2 StatusReason => Str

  A short, human-readable string to provide additional details about the
current status of the compute environment.


=head2 Type => Str

  The type of the compute environment.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Batch>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: https://github.com/pplu/aws-sdk-perl

Please report bugs to: https://github.com/pplu/aws-sdk-perl/issues

=cut

