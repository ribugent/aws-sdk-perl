
package Paws::RDS::DescribeDBProxyEndpointsResponse;
  use Moose;
  has DBProxyEndpoints => (is => 'ro', isa => 'ArrayRef[Paws::RDS::DBProxyEndpoint]');
  has Marker => (is => 'ro', isa => 'Str');

  has _request_id => (is => 'ro', isa => 'Str');
1;

### main pod documentation begin ###

=head1 NAME

Paws::RDS::DescribeDBProxyEndpointsResponse

=head1 ATTRIBUTES


=head2 DBProxyEndpoints => ArrayRef[L<Paws::RDS::DBProxyEndpoint>]

The list of C<ProxyEndpoint> objects returned by the API operation.


=head2 Marker => Str

An optional pagination token provided by a previous request. If this
parameter is specified, the response includes only records beyond the
marker, up to the value specified by C<MaxRecords>.


=head2 _request_id => Str


=cut

