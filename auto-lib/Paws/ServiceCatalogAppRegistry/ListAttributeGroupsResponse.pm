
package Paws::ServiceCatalogAppRegistry::ListAttributeGroupsResponse;
  use Moose;
  has AttributeGroups => (is => 'ro', isa => 'ArrayRef[Paws::ServiceCatalogAppRegistry::AttributeGroupSummary]', traits => ['NameInRequest'], request_name => 'attributeGroups');
  has NextToken => (is => 'ro', isa => 'Str', traits => ['NameInRequest'], request_name => 'nextToken');

  has _request_id => (is => 'ro', isa => 'Str');
1;

### main pod documentation begin ###

=head1 NAME

Paws::ServiceCatalogAppRegistry::ListAttributeGroupsResponse

=head1 ATTRIBUTES


=head2 AttributeGroups => ArrayRef[L<Paws::ServiceCatalogAppRegistry::AttributeGroupSummary>]

This list of attribute groups.


=head2 NextToken => Str

The token to use to get the next page of results after a previous API
call.


=head2 _request_id => Str


=cut

