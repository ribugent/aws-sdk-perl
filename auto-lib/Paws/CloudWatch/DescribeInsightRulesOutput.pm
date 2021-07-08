
package Paws::CloudWatch::DescribeInsightRulesOutput;
  use Moose;
  has InsightRules => (is => 'ro', isa => 'ArrayRef[Paws::CloudWatch::InsightRule]');
  has NextToken => (is => 'ro', isa => 'Str');

  has _request_id => (is => 'ro', isa => 'Str');
1;

### main pod documentation begin ###

=head1 NAME

Paws::CloudWatch::DescribeInsightRulesOutput

=head1 ATTRIBUTES


=head2 InsightRules => ArrayRef[L<Paws::CloudWatch::InsightRule>]

The rules returned by the operation.


=head2 NextToken => Str

If this parameter is present, it is a token that marks the start of the
next batch of returned results.


=head2 _request_id => Str


=cut

