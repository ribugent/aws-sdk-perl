
package Paws::Robomaker::ListDeploymentJobsResponse;
  use Moose;
  has DeploymentJobs => (is => 'ro', isa => 'ArrayRef[Paws::Robomaker::DeploymentJob]', traits => ['NameInRequest'], request_name => 'deploymentJobs');
  has NextToken => (is => 'ro', isa => 'Str', traits => ['NameInRequest'], request_name => 'nextToken');

  has _request_id => (is => 'ro', isa => 'Str');
1;

### main pod documentation begin ###

=head1 NAME

Paws::Robomaker::ListDeploymentJobsResponse

=head1 ATTRIBUTES


=head2 DeploymentJobs => ArrayRef[L<Paws::Robomaker::DeploymentJob>]

A list of deployment jobs that meet the criteria of the request.


=head2 NextToken => Str

If the previous paginated request did not return all of the remaining
results, the response object's C<nextToken> parameter value is set to a
token. To retrieve the next set of results, call C<ListDeploymentJobs>
again and assign that token to the request object's C<nextToken>
parameter. If there are no remaining results, the previous response
object's NextToken parameter is set to null.


=head2 _request_id => Str


=cut

