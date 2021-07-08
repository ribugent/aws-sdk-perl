# Generated by default/object.tt
package Paws::RDS::ClusterPendingModifiedValues;
  use Moose;
  has DBClusterIdentifier => (is => 'ro', isa => 'Str');
  has EngineVersion => (is => 'ro', isa => 'Str');
  has IAMDatabaseAuthenticationEnabled => (is => 'ro', isa => 'Bool');
  has MasterUserPassword => (is => 'ro', isa => 'Str');
  has PendingCloudwatchLogsExports => (is => 'ro', isa => 'Paws::RDS::PendingCloudwatchLogsExports');

1;

### main pod documentation begin ###

=head1 NAME

Paws::RDS::ClusterPendingModifiedValues

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::RDS::ClusterPendingModifiedValues object:

  $service_obj->Method(Att1 => { DBClusterIdentifier => $value, ..., PendingCloudwatchLogsExports => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::RDS::ClusterPendingModifiedValues object:

  $result = $service_obj->Method(...);
  $result->Att1->DBClusterIdentifier

=head1 DESCRIPTION

This data type is used as a response element in the C<ModifyDBCluster>
operation and contains changes that will be applied during the next
maintenance window.

=head1 ATTRIBUTES


=head2 DBClusterIdentifier => Str

The DBClusterIdentifier value for the DB cluster.


=head2 EngineVersion => Str

The database engine version.


=head2 IAMDatabaseAuthenticationEnabled => Bool

A value that indicates whether mapping of Amazon Web Services Identity
and Access Management (IAM) accounts to database accounts is enabled.


=head2 MasterUserPassword => Str

The master credentials for the DB cluster.


=head2 PendingCloudwatchLogsExports => L<Paws::RDS::PendingCloudwatchLogsExports>





=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::RDS>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

