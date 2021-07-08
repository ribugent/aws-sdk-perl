# Generated by default/object.tt
package Paws::FSX::CreateFileSystemWindowsConfiguration;
  use Moose;
  has ActiveDirectoryId => (is => 'ro', isa => 'Str');
  has Aliases => (is => 'ro', isa => 'ArrayRef[Str|Undef]');
  has AuditLogConfiguration => (is => 'ro', isa => 'Paws::FSX::WindowsAuditLogCreateConfiguration');
  has AutomaticBackupRetentionDays => (is => 'ro', isa => 'Int');
  has CopyTagsToBackups => (is => 'ro', isa => 'Bool');
  has DailyAutomaticBackupStartTime => (is => 'ro', isa => 'Str');
  has DeploymentType => (is => 'ro', isa => 'Str');
  has PreferredSubnetId => (is => 'ro', isa => 'Str');
  has SelfManagedActiveDirectoryConfiguration => (is => 'ro', isa => 'Paws::FSX::SelfManagedActiveDirectoryConfiguration');
  has ThroughputCapacity => (is => 'ro', isa => 'Int', required => 1);
  has WeeklyMaintenanceStartTime => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::FSX::CreateFileSystemWindowsConfiguration

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::FSX::CreateFileSystemWindowsConfiguration object:

  $service_obj->Method(Att1 => { ActiveDirectoryId => $value, ..., WeeklyMaintenanceStartTime => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::FSX::CreateFileSystemWindowsConfiguration object:

  $result = $service_obj->Method(...);
  $result->Att1->ActiveDirectoryId

=head1 DESCRIPTION

The configuration object for the Microsoft Windows file system used in
C<CreateFileSystem> and C<CreateFileSystemFromBackup> operations.

=head1 ATTRIBUTES


=head2 ActiveDirectoryId => Str

The ID for an existing AWS Managed Microsoft Active Directory (AD)
instance that the file system should join when it's created.


=head2 Aliases => ArrayRef[Str|Undef]

An array of one or more DNS alias names that you want to associate with
the Amazon FSx file system. Aliases allow you to use existing DNS names
to access the data in your Amazon FSx file system. You can associate up
to 50 aliases with a file system at any time. You can associate
additional DNS aliases after you create the file system using the
AssociateFileSystemAliases operation. You can remove DNS aliases from
the file system after it is created using the
DisassociateFileSystemAliases operation. You only need to specify the
alias name in the request payload.

For more information, see Working with DNS Aliases
(https://docs.aws.amazon.com/fsx/latest/WindowsGuide/managing-dns-aliases.html)
and Walkthrough 5: Using DNS aliases to access your file system
(https://docs.aws.amazon.com/fsx/latest/WindowsGuide/walkthrough05-file-system-custom-CNAME.html),
including additional steps you must take to be able to access your file
system using a DNS alias.

An alias name has to meet the following requirements:

=over

=item *

Formatted as a fully-qualified domain name (FQDN), C<hostname.domain>,
for example, C<accounting.example.com>.

=item *

Can contain alphanumeric characters, the underscore (_), and the hyphen
(-).

=item *

Cannot start or end with a hyphen.

=item *

Can start with a numeric.

=back

For DNS alias names, Amazon FSx stores alphabetic characters as
lowercase letters (a-z), regardless of how you specify them: as
uppercase letters, lowercase letters, or the corresponding letters in
escape codes.


=head2 AuditLogConfiguration => L<Paws::FSX::WindowsAuditLogCreateConfiguration>

The configuration that Amazon FSx for Windows File Server uses to audit
and log user accesses of files, folders, and file shares on the Amazon
FSx for Windows File Server file system.


=head2 AutomaticBackupRetentionDays => Int

The number of days to retain automatic backups. The default is to
retain backups for 7 days. Setting this value to 0 disables the
creation of automatic backups. The maximum retention period for backups
is 90 days.


=head2 CopyTagsToBackups => Bool

A boolean flag indicating whether tags for the file system should be
copied to backups. This value defaults to false. If it's set to true,
all tags for the file system are copied to all automatic and
user-initiated backups where the user doesn't specify tags. If this
value is true, and you specify one or more tags, only the specified
tags are copied to backups. If you specify one or more tags when
creating a user-initiated backup, no tags are copied from the file
system, regardless of this value.


=head2 DailyAutomaticBackupStartTime => Str

The preferred time to take daily automatic backups, formatted HH:MM in
the UTC time zone.


=head2 DeploymentType => Str

Specifies the file system deployment type, valid values are the
following:

=over

=item *

C<MULTI_AZ_1> - Deploys a high availability file system that is
configured for Multi-AZ redundancy to tolerate temporary Availability
Zone (AZ) unavailability. You can only deploy a Multi-AZ file system in
AWS Regions that have a minimum of three Availability Zones. Also
supports HDD storage type

=item *

C<SINGLE_AZ_1> - (Default) Choose to deploy a file system that is
configured for single AZ redundancy.

=item *

C<SINGLE_AZ_2> - The latest generation Single AZ file system. Specifies
a file system that is configured for single AZ redundancy and supports
HDD storage type.

=back

For more information, see Availability and Durability: Single-AZ and
Multi-AZ File Systems
(https://docs.aws.amazon.com/fsx/latest/WindowsGuide/high-availability-multiAZ.html).


=head2 PreferredSubnetId => Str

Required when C<DeploymentType> is set to C<MULTI_AZ_1>. This specifies
the subnet in which you want the preferred file server to be located.
For in-AWS applications, we recommend that you launch your clients in
the same Availability Zone (AZ) as your preferred file server to reduce
cross-AZ data transfer costs and minimize latency.


=head2 SelfManagedActiveDirectoryConfiguration => L<Paws::FSX::SelfManagedActiveDirectoryConfiguration>




=head2 B<REQUIRED> ThroughputCapacity => Int

The throughput of an Amazon FSx file system, measured in megabytes per
second, in 2 to the I<n>th increments, between 2^3 (8) and 2^11 (2048).


=head2 WeeklyMaintenanceStartTime => Str

The preferred start time to perform weekly maintenance, formatted
d:HH:MM in the UTC time zone, where d is the weekday number, from 1
through 7, beginning with Monday and ending with Sunday.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::FSX>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

