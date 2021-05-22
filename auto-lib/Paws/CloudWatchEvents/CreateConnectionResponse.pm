
package Paws::CloudWatchEvents::CreateConnectionResponse;
  use Moose;
  has ConnectionArn => (is => 'ro', isa => 'Str');
  has ConnectionState => (is => 'ro', isa => 'Str');
  has CreationTime => (is => 'ro', isa => 'Str');
  has LastModifiedTime => (is => 'ro', isa => 'Str');

  has _request_id => (is => 'ro', isa => 'Str');

### main pod documentation begin ###

=head1 NAME

Paws::CloudWatchEvents::CreateConnectionResponse

=head1 ATTRIBUTES


=head2 ConnectionArn => Str

The ARN of the connection that was created by the request.


=head2 ConnectionState => Str

The state of the connection that was created by the request.

Valid values are: C<"CREATING">, C<"UPDATING">, C<"DELETING">, C<"AUTHORIZED">, C<"DEAUTHORIZED">, C<"AUTHORIZING">, C<"DEAUTHORIZING">
=head2 CreationTime => Str

A time stamp for the time that the connection was created.


=head2 LastModifiedTime => Str

A time stamp for the time that the connection was last updated.


=head2 _request_id => Str


=cut

1;