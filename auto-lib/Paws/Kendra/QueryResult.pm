
package Paws::Kendra::QueryResult;
  use Moose;
  has FacetResults => (is => 'ro', isa => 'ArrayRef[Paws::Kendra::FacetResult]');
  has QueryId => (is => 'ro', isa => 'Str');
  has ResultItems => (is => 'ro', isa => 'ArrayRef[Paws::Kendra::QueryResultItem]');
  has TotalNumberOfResults => (is => 'ro', isa => 'Int');

  has _request_id => (is => 'ro', isa => 'Str');

### main pod documentation begin ###

=head1 NAME

Paws::Kendra::QueryResult

=head1 ATTRIBUTES


=head2 FacetResults => ArrayRef[L<Paws::Kendra::FacetResult>]

Contains the facet results. A C<FacetResult> contains the counts for
each attribute key that was specified in the C<Facets> input parameter.


=head2 QueryId => Str

The unique identifier for the search. You use C<QueryId> to identify
the search when using the feedback API.


=head2 ResultItems => ArrayRef[L<Paws::Kendra::QueryResultItem>]

The results of the search.


=head2 TotalNumberOfResults => Int

The total number of items found by the search; however, you can only
retrieve up to 100 items. For example, if the search found 192 items,
you can only retrieve the first 100 of the items.


=head2 _request_id => Str


=cut

1;