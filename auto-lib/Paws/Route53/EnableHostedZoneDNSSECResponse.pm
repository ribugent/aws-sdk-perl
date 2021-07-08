
package Paws::Route53::EnableHostedZoneDNSSECResponse;
  use Moose;
  has ChangeInfo => (is => 'ro', isa => 'Paws::Route53::ChangeInfo', required => 1);


  has _request_id => (is => 'ro', isa => 'Str');
1;

### main pod documentation begin ###

=head1 NAME

Paws::Route53::EnableHostedZoneDNSSECResponse

=head1 ATTRIBUTES


=head2 B<REQUIRED> ChangeInfo => L<Paws::Route53::ChangeInfo>






=cut

