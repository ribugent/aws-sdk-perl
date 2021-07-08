
package Paws::CodeGuruProfiler::CreateProfilingGroup;
  use Moose;
  has AgentOrchestrationConfig => (is => 'ro', isa => 'Paws::CodeGuruProfiler::AgentOrchestrationConfig', traits => ['NameInRequest'], request_name => 'agentOrchestrationConfig');
  has ClientToken => (is => 'ro', isa => 'Str', traits => ['ParamInQuery'], query_name => 'clientToken', required => 1);
  has ComputePlatform => (is => 'ro', isa => 'Str', traits => ['NameInRequest'], request_name => 'computePlatform');
  has ProfilingGroupName => (is => 'ro', isa => 'Str', traits => ['NameInRequest'], request_name => 'profilingGroupName', required => 1);
  has Tags => (is => 'ro', isa => 'Paws::CodeGuruProfiler::TagsMap', traits => ['NameInRequest'], request_name => 'tags');

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'CreateProfilingGroup');
  class_has _api_uri  => (isa => 'Str', is => 'ro', default => '/profilingGroups');
  class_has _api_method  => (isa => 'Str', is => 'ro', default => 'POST');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::CodeGuruProfiler::CreateProfilingGroupResponse');
1;

### main pod documentation begin ###

=head1 NAME

Paws::CodeGuruProfiler::CreateProfilingGroup - Arguments for method CreateProfilingGroup on L<Paws::CodeGuruProfiler>

=head1 DESCRIPTION

This class represents the parameters used for calling the method CreateProfilingGroup on the
L<Amazon CodeGuru Profiler|Paws::CodeGuruProfiler> service. Use the attributes of this class
as arguments to method CreateProfilingGroup.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to CreateProfilingGroup.

=head1 SYNOPSIS

    my $codeguru-profiler = Paws->service('CodeGuruProfiler');
    my $CreateProfilingGroupResponse =
      $codeguru -profiler->CreateProfilingGroup(
      ClientToken              => 'MyClientToken',
      ProfilingGroupName       => 'MyProfilingGroupName',
      AgentOrchestrationConfig => {
        ProfilingEnabled => 1,

      },    # OPTIONAL
      ComputePlatform => 'Default',                        # OPTIONAL
      Tags            => { 'MyString' => 'MyString', },    # OPTIONAL
      );

    # Results:
    my $ProfilingGroup = $CreateProfilingGroupResponse->ProfilingGroup;

    # Returns a L<Paws::CodeGuruProfiler::CreateProfilingGroupResponse> object.

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/codeguru-profiler/CreateProfilingGroup>

=head1 ATTRIBUTES


=head2 AgentOrchestrationConfig => L<Paws::CodeGuruProfiler::AgentOrchestrationConfig>

Specifies whether profiling is enabled or disabled for the created
profiling group.



=head2 B<REQUIRED> ClientToken => Str

Amazon CodeGuru Profiler uses this universally unique identifier (UUID)
to prevent the accidental creation of duplicate profiling groups if
there are failures and retries.



=head2 ComputePlatform => Str

The compute platform of the profiling group. Use C<AWSLambda> if your
application runs on AWS Lambda. Use C<Default> if your application runs
on a compute platform that is not AWS Lambda, such an Amazon EC2
instance, an on-premises server, or a different platform. If not
specified, C<Default> is used.

Valid values are: C<"Default">, C<"AWSLambda">

=head2 B<REQUIRED> ProfilingGroupName => Str

The name of the profiling group to create.



=head2 Tags => L<Paws::CodeGuruProfiler::TagsMap>

A list of tags to add to the created profiling group.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method CreateProfilingGroup in L<Paws::CodeGuruProfiler>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

