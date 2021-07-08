# Generated by default/object.tt
package Paws::DocDB::GlobalCluster;
  use Moose;
  has DatabaseName => (is => 'ro', isa => 'Str');
  has DeletionProtection => (is => 'ro', isa => 'Bool');
  has Engine => (is => 'ro', isa => 'Str');
  has EngineVersion => (is => 'ro', isa => 'Str');
  has GlobalClusterArn => (is => 'ro', isa => 'Str');
  has GlobalClusterIdentifier => (is => 'ro', isa => 'Str');
  has GlobalClusterMembers => (is => 'ro', isa => 'ArrayRef[Paws::DocDB::GlobalClusterMember]', request_name => 'GlobalClusterMember', traits => ['NameInRequest']);
  has GlobalClusterResourceId => (is => 'ro', isa => 'Str');
  has Status => (is => 'ro', isa => 'Str');
  has StorageEncrypted => (is => 'ro', isa => 'Bool');

1;

### main pod documentation begin ###

=head1 NAME

Paws::DocDB::GlobalCluster

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::DocDB::GlobalCluster object:

  $service_obj->Method(Att1 => { DatabaseName => $value, ..., StorageEncrypted => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::DocDB::GlobalCluster object:

  $result = $service_obj->Method(...);
  $result->Att1->DatabaseName

=head1 DESCRIPTION

A data type representing an Amazon DocumentDB global cluster.

=head1 ATTRIBUTES


=head2 DatabaseName => Str

The default database name within the new global cluster.


=head2 DeletionProtection => Bool

The deletion protection setting for the new global cluster.


=head2 Engine => Str

The Amazon DocumentDB database engine used by the global cluster.


=head2 EngineVersion => Str

Indicates the database engine version.


=head2 GlobalClusterArn => Str

The Amazon Resource Name (ARN) for the global cluster.


=head2 GlobalClusterIdentifier => Str

Contains a user-supplied global cluster identifier. This identifier is
the unique key that identifies a global cluster.


=head2 GlobalClusterMembers => ArrayRef[L<Paws::DocDB::GlobalClusterMember>]

The list of cluster IDs for secondary clusters within the global
cluster. Currently limited to one item.


=head2 GlobalClusterResourceId => Str

The Region-unique, immutable identifier for the global database
cluster. This identifier is found in AWS CloudTrail log entries
whenever the AWS KMS customer master key (CMK) for the cluster is
accessed.


=head2 Status => Str

Specifies the current state of this global cluster.


=head2 StorageEncrypted => Bool

The storage encryption setting for the global cluster.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::DocDB>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

