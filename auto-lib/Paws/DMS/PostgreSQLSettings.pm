# Generated by default/object.tt
package Paws::DMS::PostgreSQLSettings;
  use Moose;
  has AfterConnectScript => (is => 'ro', isa => 'Str');
  has CaptureDdls => (is => 'ro', isa => 'Bool');
  has DatabaseName => (is => 'ro', isa => 'Str');
  has DdlArtifactsSchema => (is => 'ro', isa => 'Str');
  has ExecuteTimeout => (is => 'ro', isa => 'Int');
  has FailTasksOnLobTruncation => (is => 'ro', isa => 'Bool');
  has MaxFileSize => (is => 'ro', isa => 'Int');
  has Password => (is => 'ro', isa => 'Str');
  has Port => (is => 'ro', isa => 'Int');
  has SecretsManagerAccessRoleArn => (is => 'ro', isa => 'Str');
  has SecretsManagerSecretId => (is => 'ro', isa => 'Str');
  has ServerName => (is => 'ro', isa => 'Str');
  has SlotName => (is => 'ro', isa => 'Str');
  has Username => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::DMS::PostgreSQLSettings

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::DMS::PostgreSQLSettings object:

  $service_obj->Method(Att1 => { AfterConnectScript => $value, ..., Username => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::DMS::PostgreSQLSettings object:

  $result = $service_obj->Method(...);
  $result->Att1->AfterConnectScript

=head1 DESCRIPTION

Provides information that defines a PostgreSQL endpoint.

=head1 ATTRIBUTES


=head2 AfterConnectScript => Str

For use with change data capture (CDC) only, this attribute has AWS DMS
bypass foreign keys and user triggers to reduce the time it takes to
bulk load data.

Example: C<afterConnectScript=SET session_replication_role='replica'>


=head2 CaptureDdls => Bool

To capture DDL events, AWS DMS creates various artifacts in the
PostgreSQL database when the task starts. You can later remove these
artifacts.

If this value is set to C<N>, you don't have to create tables or
triggers on the source database.


=head2 DatabaseName => Str

Database name for the endpoint.


=head2 DdlArtifactsSchema => Str

The schema in which the operational DDL database artifacts are created.

Example: C<ddlArtifactsSchema=xyzddlschema;>


=head2 ExecuteTimeout => Int

Sets the client statement timeout for the PostgreSQL instance, in
seconds. The default value is 60 seconds.

Example: C<executeTimeout=100;>


=head2 FailTasksOnLobTruncation => Bool

When set to C<true>, this value causes a task to fail if the actual
size of a LOB column is greater than the specified C<LobMaxSize>.

If task is set to Limited LOB mode and this option is set to true, the
task fails instead of truncating the LOB data.


=head2 MaxFileSize => Int

Specifies the maximum size (in KB) of any .csv file used to transfer
data to PostgreSQL.

Example: C<maxFileSize=512>


=head2 Password => Str

Endpoint connection password.


=head2 Port => Int

Endpoint TCP port.


=head2 SecretsManagerAccessRoleArn => Str

The full Amazon Resource Name (ARN) of the IAM role that specifies AWS
DMS as the trusted entity and grants the required permissions to access
the value in C<SecretsManagerSecret>. C<SecretsManagerSecret> has the
value of the AWS Secrets Manager secret that allows access to the
PostgreSQL endpoint.

You can specify one of two sets of values for these permissions. You
can specify the values for this setting and C<SecretsManagerSecretId>.
Or you can specify clear-text values for C<UserName>, C<Password>,
C<ServerName>, and C<Port>. You can't specify both. For more
information on creating this C<SecretsManagerSecret> and the
C<SecretsManagerAccessRoleArn> and C<SecretsManagerSecretId> required
to access it, see Using secrets to access AWS Database Migration
Service resources
(https://docs.aws.amazon.com/https:/docs.aws.amazon.com/dms/latest/userguide/CHAP_Security.html#security-iam-secretsmanager)
in the I<AWS Database Migration Service User Guide>.


=head2 SecretsManagerSecretId => Str

The full ARN, partial ARN, or friendly name of the
C<SecretsManagerSecret> that contains the PostgreSQL endpoint
connection details.


=head2 ServerName => Str

Fully qualified domain name of the endpoint.


=head2 SlotName => Str

Sets the name of a previously created logical replication slot for a
CDC load of the PostgreSQL source instance.

When used with the AWS DMS API C<CdcStartPosition> request parameter,
this attribute also enables using native CDC start points.


=head2 Username => Str

Endpoint connection user name.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::DMS>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

