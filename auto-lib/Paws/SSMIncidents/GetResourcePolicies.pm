
package Paws::SSMIncidents::GetResourcePolicies;
  use Moose;
  has MaxResults => (is => 'ro', isa => 'Int', traits => ['NameInRequest'], request_name => 'maxResults');
  has NextToken => (is => 'ro', isa => 'Str', traits => ['NameInRequest'], request_name => 'nextToken');
  has ResourceArn => (is => 'ro', isa => 'Str', traits => ['ParamInQuery'], query_name => 'resourceArn', required => 1);

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'GetResourcePolicies');
  class_has _api_uri  => (isa => 'Str', is => 'ro', default => '/getResourcePolicies');
  class_has _api_method  => (isa => 'Str', is => 'ro', default => 'POST');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::SSMIncidents::GetResourcePoliciesOutput');
1;

### main pod documentation begin ###

=head1 NAME

Paws::SSMIncidents::GetResourcePolicies - Arguments for method GetResourcePolicies on L<Paws::SSMIncidents>

=head1 DESCRIPTION

This class represents the parameters used for calling the method GetResourcePolicies on the
L<AWS Systems Manager Incident Manager|Paws::SSMIncidents> service. Use the attributes of this class
as arguments to method GetResourcePolicies.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to GetResourcePolicies.

=head1 SYNOPSIS

    my $ssm-incidents = Paws->service('SSMIncidents');
    my $GetResourcePoliciesOutput = $ssm -incidents->GetResourcePolicies(
      ResourceArn => 'MyArn',
      MaxResults  => 1,                # OPTIONAL
      NextToken   => 'MyNextToken',    # OPTIONAL
    );

    # Results:
    my $NextToken        = $GetResourcePoliciesOutput->NextToken;
    my $ResourcePolicies = $GetResourcePoliciesOutput->ResourcePolicies;

    # Returns a L<Paws::SSMIncidents::GetResourcePoliciesOutput> object.

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/ssm-incidents/GetResourcePolicies>

=head1 ATTRIBUTES


=head2 MaxResults => Int

The maximum number of resource policies to display per page of results.



=head2 NextToken => Str

The pagination token to continue to the next page of results.



=head2 B<REQUIRED> ResourceArn => Str

The Amazon Resource Name (ARN) of the response plan with the attached
resource policy.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method GetResourcePolicies in L<Paws::SSMIncidents>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

