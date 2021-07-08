# Generated by default/object.tt
package Paws::SecurityHub::AwsRedshiftClusterDetails;
  use Moose;
  has AllowVersionUpgrade => (is => 'ro', isa => 'Bool');
  has AutomatedSnapshotRetentionPeriod => (is => 'ro', isa => 'Int');
  has AvailabilityZone => (is => 'ro', isa => 'Str');
  has ClusterAvailabilityStatus => (is => 'ro', isa => 'Str');
  has ClusterCreateTime => (is => 'ro', isa => 'Str');
  has ClusterIdentifier => (is => 'ro', isa => 'Str');
  has ClusterNodes => (is => 'ro', isa => 'ArrayRef[Paws::SecurityHub::AwsRedshiftClusterClusterNode]');
  has ClusterParameterGroups => (is => 'ro', isa => 'ArrayRef[Paws::SecurityHub::AwsRedshiftClusterClusterParameterGroup]');
  has ClusterPublicKey => (is => 'ro', isa => 'Str');
  has ClusterRevisionNumber => (is => 'ro', isa => 'Str');
  has ClusterSecurityGroups => (is => 'ro', isa => 'ArrayRef[Paws::SecurityHub::AwsRedshiftClusterClusterSecurityGroup]');
  has ClusterSnapshotCopyStatus => (is => 'ro', isa => 'Paws::SecurityHub::AwsRedshiftClusterClusterSnapshotCopyStatus');
  has ClusterStatus => (is => 'ro', isa => 'Str');
  has ClusterSubnetGroupName => (is => 'ro', isa => 'Str');
  has ClusterVersion => (is => 'ro', isa => 'Str');
  has DBName => (is => 'ro', isa => 'Str');
  has DeferredMaintenanceWindows => (is => 'ro', isa => 'ArrayRef[Paws::SecurityHub::AwsRedshiftClusterDeferredMaintenanceWindow]');
  has ElasticIpStatus => (is => 'ro', isa => 'Paws::SecurityHub::AwsRedshiftClusterElasticIpStatus');
  has ElasticResizeNumberOfNodeOptions => (is => 'ro', isa => 'Str');
  has Encrypted => (is => 'ro', isa => 'Bool');
  has Endpoint => (is => 'ro', isa => 'Paws::SecurityHub::AwsRedshiftClusterEndpoint');
  has EnhancedVpcRouting => (is => 'ro', isa => 'Bool');
  has ExpectedNextSnapshotScheduleTime => (is => 'ro', isa => 'Str');
  has ExpectedNextSnapshotScheduleTimeStatus => (is => 'ro', isa => 'Str');
  has HsmStatus => (is => 'ro', isa => 'Paws::SecurityHub::AwsRedshiftClusterHsmStatus');
  has IamRoles => (is => 'ro', isa => 'ArrayRef[Paws::SecurityHub::AwsRedshiftClusterIamRole]');
  has KmsKeyId => (is => 'ro', isa => 'Str');
  has MaintenanceTrackName => (is => 'ro', isa => 'Str');
  has ManualSnapshotRetentionPeriod => (is => 'ro', isa => 'Int');
  has MasterUsername => (is => 'ro', isa => 'Str');
  has NextMaintenanceWindowStartTime => (is => 'ro', isa => 'Str');
  has NodeType => (is => 'ro', isa => 'Str');
  has NumberOfNodes => (is => 'ro', isa => 'Int');
  has PendingActions => (is => 'ro', isa => 'ArrayRef[Str|Undef]');
  has PendingModifiedValues => (is => 'ro', isa => 'Paws::SecurityHub::AwsRedshiftClusterPendingModifiedValues');
  has PreferredMaintenanceWindow => (is => 'ro', isa => 'Str');
  has PubliclyAccessible => (is => 'ro', isa => 'Bool');
  has ResizeInfo => (is => 'ro', isa => 'Paws::SecurityHub::AwsRedshiftClusterResizeInfo');
  has RestoreStatus => (is => 'ro', isa => 'Paws::SecurityHub::AwsRedshiftClusterRestoreStatus');
  has SnapshotScheduleIdentifier => (is => 'ro', isa => 'Str');
  has SnapshotScheduleState => (is => 'ro', isa => 'Str');
  has VpcId => (is => 'ro', isa => 'Str');
  has VpcSecurityGroups => (is => 'ro', isa => 'ArrayRef[Paws::SecurityHub::AwsRedshiftClusterVpcSecurityGroup]');

1;

### main pod documentation begin ###

=head1 NAME

Paws::SecurityHub::AwsRedshiftClusterDetails

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::SecurityHub::AwsRedshiftClusterDetails object:

  $service_obj->Method(Att1 => { AllowVersionUpgrade => $value, ..., VpcSecurityGroups => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::SecurityHub::AwsRedshiftClusterDetails object:

  $result = $service_obj->Method(...);
  $result->Att1->AllowVersionUpgrade

=head1 DESCRIPTION

Details about an Amazon Redshift cluster.

=head1 ATTRIBUTES


=head2 AllowVersionUpgrade => Bool

Indicates whether major version upgrades are applied automatically to
the cluster during the maintenance window.


=head2 AutomatedSnapshotRetentionPeriod => Int

The number of days that automatic cluster snapshots are retained.


=head2 AvailabilityZone => Str

The name of the Availability Zone in which the cluster is located.


=head2 ClusterAvailabilityStatus => Str

The availability status of the cluster for queries. Possible values are
the following:

=over

=item *

C<Available> - The cluster is available for queries.

=item *

C<Unavailable> - The cluster is not available for queries.

=item *

C<Maintenance> - The cluster is intermittently available for queries
due to maintenance activities.

=item *

C<Modifying> -The cluster is intermittently available for queries due
to changes that modify the cluster.

=item *

C<Failed> - The cluster failed and is not available for queries.

=back



=head2 ClusterCreateTime => Str

Indicates when the cluster was created.

Uses the C<date-time> format specified in RFC 3339 section 5.6,
Internet Date/Time Format
(https://tools.ietf.org/html/rfc3339#section-5.6). The value cannot
contain spaces. For example, C<2020-03-22T13:22:13.933Z>.


=head2 ClusterIdentifier => Str

The unique identifier of the cluster.


=head2 ClusterNodes => ArrayRef[L<Paws::SecurityHub::AwsRedshiftClusterClusterNode>]

The nodes in the cluster.


=head2 ClusterParameterGroups => ArrayRef[L<Paws::SecurityHub::AwsRedshiftClusterClusterParameterGroup>]

The list of cluster parameter groups that are associated with this
cluster.


=head2 ClusterPublicKey => Str

The public key for the cluster.


=head2 ClusterRevisionNumber => Str

The specific revision number of the database in the cluster.


=head2 ClusterSecurityGroups => ArrayRef[L<Paws::SecurityHub::AwsRedshiftClusterClusterSecurityGroup>]

A list of cluster security groups that are associated with the cluster.


=head2 ClusterSnapshotCopyStatus => L<Paws::SecurityHub::AwsRedshiftClusterClusterSnapshotCopyStatus>

Information about the destination Region and retention period for the
cross-Region snapshot copy.


=head2 ClusterStatus => Str

The current status of the cluster.

Valid values: C<available> | C<available, prep-for-resize> |
C<available, resize-cleanup> |C< cancelling-resize> | C<creating> |
C<deleting> | C<final-snapshot> | C<hardware-failure> |
C<incompatible-hsm> |C< incompatible-network> |
C<incompatible-parameters> | C<incompatible-restore> | C<modifying> |
C<paused> | C<rebooting> | C<renaming> | C<resizing> | C<rotating-keys>
| C<storage-full> | C<updating-hsm>


=head2 ClusterSubnetGroupName => Str

The name of the subnet group that is associated with the cluster. This
parameter is valid only when the cluster is in a VPC.


=head2 ClusterVersion => Str

The version ID of the Amazon Redshift engine that runs on the cluster.


=head2 DBName => Str

The name of the initial database that was created when the cluster was
created.

The same name is returned for the life of the cluster.

If an initial database is not specified, a database named C<devdev> is
created by default.


=head2 DeferredMaintenanceWindows => ArrayRef[L<Paws::SecurityHub::AwsRedshiftClusterDeferredMaintenanceWindow>]

List of time windows during which maintenance was deferred.


=head2 ElasticIpStatus => L<Paws::SecurityHub::AwsRedshiftClusterElasticIpStatus>

Information about the status of the Elastic IP (EIP) address.


=head2 ElasticResizeNumberOfNodeOptions => Str

The number of nodes that you can use the elastic resize method to
resize the cluster to.


=head2 Encrypted => Bool

Indicates whether the data in the cluster is encrypted at rest.


=head2 Endpoint => L<Paws::SecurityHub::AwsRedshiftClusterEndpoint>

The connection endpoint.


=head2 EnhancedVpcRouting => Bool

Indicates whether to create the cluster with enhanced VPC routing
enabled.


=head2 ExpectedNextSnapshotScheduleTime => Str

Indicates when the next snapshot is expected to be taken. The cluster
must have a valid snapshot schedule and have backups enabled.

Uses the C<date-time> format specified in RFC 3339 section 5.6,
Internet Date/Time Format
(https://tools.ietf.org/html/rfc3339#section-5.6). The value cannot
contain spaces. For example, C<2020-03-22T13:22:13.933Z>.


=head2 ExpectedNextSnapshotScheduleTimeStatus => Str

The status of the next expected snapshot.

Valid values: C<OnTrack> | C<Pending>


=head2 HsmStatus => L<Paws::SecurityHub::AwsRedshiftClusterHsmStatus>

Information about whether the Amazon Redshift cluster finished applying
any changes to hardware security module (HSM) settings that were
specified in a modify cluster command.


=head2 IamRoles => ArrayRef[L<Paws::SecurityHub::AwsRedshiftClusterIamRole>]

A list of IAM roles that the cluster can use to access other AWS
services.


=head2 KmsKeyId => Str

The identifier of the AWS KMS encryption key that is used to encrypt
data in the cluster.


=head2 MaintenanceTrackName => Str

The name of the maintenance track for the cluster.


=head2 ManualSnapshotRetentionPeriod => Int

The default number of days to retain a manual snapshot.

If the value is -1, the snapshot is retained indefinitely.

This setting doesn't change the retention period of existing snapshots.

Valid values: Either -1 or an integer between 1 and 3,653


=head2 MasterUsername => Str

The master user name for the cluster. This name is used to connect to
the database that is specified in as the value of C<DBName>.


=head2 NextMaintenanceWindowStartTime => Str

Indicates the start of the next maintenance window.

Uses the C<date-time> format specified in RFC 3339 section 5.6,
Internet Date/Time Format
(https://tools.ietf.org/html/rfc3339#section-5.6). The value cannot
contain spaces. For example, C<2020-03-22T13:22:13.933Z>.


=head2 NodeType => Str

The node type for the nodes in the cluster.


=head2 NumberOfNodes => Int

The number of compute nodes in the cluster.


=head2 PendingActions => ArrayRef[Str|Undef]

A list of cluster operations that are waiting to start.


=head2 PendingModifiedValues => L<Paws::SecurityHub::AwsRedshiftClusterPendingModifiedValues>

A list of changes to the cluster that are currently pending.


=head2 PreferredMaintenanceWindow => Str

The weekly time range, in Universal Coordinated Time (UTC), during
which system maintenance can occur.

Format: C< I<E<lt>dayE<gt>>:HH:MM-I<E<lt>dayE<gt>>:HH:MM>

For the day values, use C<mon> | C<tue> | C<wed> | C<thu> | C<fri> |
C<sat> | C<sun>

For example, C<sun:09:32-sun:10:02>


=head2 PubliclyAccessible => Bool

Whether the cluster can be accessed from a public network.


=head2 ResizeInfo => L<Paws::SecurityHub::AwsRedshiftClusterResizeInfo>

Information about the resize operation for the cluster.


=head2 RestoreStatus => L<Paws::SecurityHub::AwsRedshiftClusterRestoreStatus>

Information about the status of a cluster restore action. Only applies
to a cluster that was created by restoring a snapshot.


=head2 SnapshotScheduleIdentifier => Str

A unique identifier for the cluster snapshot schedule.


=head2 SnapshotScheduleState => Str

The current state of the cluster snapshot schedule.

Valid values: C<MODIFYING> | C<ACTIVE> | C<FAILED>


=head2 VpcId => Str

The identifier of the VPC that the cluster is in, if the cluster is in
a VPC.


=head2 VpcSecurityGroups => ArrayRef[L<Paws::SecurityHub::AwsRedshiftClusterVpcSecurityGroup>]

The list of VPC security groups that the cluster belongs to, if the
cluster is in a VPC.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::SecurityHub>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

