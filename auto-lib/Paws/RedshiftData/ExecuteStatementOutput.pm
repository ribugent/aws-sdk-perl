
package Paws::RedshiftData::ExecuteStatementOutput;
  use Moose;
  has ClusterIdentifier => (is => 'ro', isa => 'Str');
  has CreatedAt => (is => 'ro', isa => 'Str');
  has Database => (is => 'ro', isa => 'Str');
  has DbUser => (is => 'ro', isa => 'Str');
  has Id => (is => 'ro', isa => 'Str');
  has SecretArn => (is => 'ro', isa => 'Str');

  has _request_id => (is => 'ro', isa => 'Str');

### main pod documentation begin ###

=head1 NAME

Paws::RedshiftData::ExecuteStatementOutput

=head1 ATTRIBUTES


=head2 ClusterIdentifier => Str

The cluster identifier.


=head2 CreatedAt => Str

The date and time (UTC) the statement was created.


=head2 Database => Str

The name of the database.


=head2 DbUser => Str

The database user name.


=head2 Id => Str

The identifier of the statement to be run. This value is a universally
unique identifier (UUID) generated by Amazon Redshift Data API.


=head2 SecretArn => Str

The name or ARN of the secret that enables access to the database.


=head2 _request_id => Str


=cut

1;