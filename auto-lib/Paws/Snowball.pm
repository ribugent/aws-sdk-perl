package Paws::Snowball;
  use Moose;
  sub service { 'snowball' }
  sub signing_name { 'snowball' }
  sub version { '2016-06-30' }
  sub target_prefix { 'AWSIESnowballJobManagementService' }
  sub json_version { "1.1" }
  has max_attempts => (is => 'ro', isa => 'Int', default => 5);
  has retry => (is => 'ro', isa => 'HashRef', default => sub {
    { base => 'rand', type => 'exponential', growth_factor => 2 }
  });
  has retriables => (is => 'ro', isa => 'ArrayRef', default => sub { [
  ] });

  with 'Paws::API::Caller', 'Paws::API::EndpointResolver', 'Paws::Net::V4Signature', 'Paws::Net::JsonCaller';

  
  sub CancelCluster {
    my $self = shift;
    my $call_object = $self->new_with_coercions('Paws::Snowball::CancelCluster', @_);
    return $self->caller->do_call($self, $call_object);
  }
  sub CancelJob {
    my $self = shift;
    my $call_object = $self->new_with_coercions('Paws::Snowball::CancelJob', @_);
    return $self->caller->do_call($self, $call_object);
  }
  sub CreateAddress {
    my $self = shift;
    my $call_object = $self->new_with_coercions('Paws::Snowball::CreateAddress', @_);
    return $self->caller->do_call($self, $call_object);
  }
  sub CreateCluster {
    my $self = shift;
    my $call_object = $self->new_with_coercions('Paws::Snowball::CreateCluster', @_);
    return $self->caller->do_call($self, $call_object);
  }
  sub CreateJob {
    my $self = shift;
    my $call_object = $self->new_with_coercions('Paws::Snowball::CreateJob', @_);
    return $self->caller->do_call($self, $call_object);
  }
  sub CreateLongTermPricing {
    my $self = shift;
    my $call_object = $self->new_with_coercions('Paws::Snowball::CreateLongTermPricing', @_);
    return $self->caller->do_call($self, $call_object);
  }
  sub CreateReturnShippingLabel {
    my $self = shift;
    my $call_object = $self->new_with_coercions('Paws::Snowball::CreateReturnShippingLabel', @_);
    return $self->caller->do_call($self, $call_object);
  }
  sub DescribeAddress {
    my $self = shift;
    my $call_object = $self->new_with_coercions('Paws::Snowball::DescribeAddress', @_);
    return $self->caller->do_call($self, $call_object);
  }
  sub DescribeAddresses {
    my $self = shift;
    my $call_object = $self->new_with_coercions('Paws::Snowball::DescribeAddresses', @_);
    return $self->caller->do_call($self, $call_object);
  }
  sub DescribeCluster {
    my $self = shift;
    my $call_object = $self->new_with_coercions('Paws::Snowball::DescribeCluster', @_);
    return $self->caller->do_call($self, $call_object);
  }
  sub DescribeJob {
    my $self = shift;
    my $call_object = $self->new_with_coercions('Paws::Snowball::DescribeJob', @_);
    return $self->caller->do_call($self, $call_object);
  }
  sub DescribeReturnShippingLabel {
    my $self = shift;
    my $call_object = $self->new_with_coercions('Paws::Snowball::DescribeReturnShippingLabel', @_);
    return $self->caller->do_call($self, $call_object);
  }
  sub GetJobManifest {
    my $self = shift;
    my $call_object = $self->new_with_coercions('Paws::Snowball::GetJobManifest', @_);
    return $self->caller->do_call($self, $call_object);
  }
  sub GetJobUnlockCode {
    my $self = shift;
    my $call_object = $self->new_with_coercions('Paws::Snowball::GetJobUnlockCode', @_);
    return $self->caller->do_call($self, $call_object);
  }
  sub GetSnowballUsage {
    my $self = shift;
    my $call_object = $self->new_with_coercions('Paws::Snowball::GetSnowballUsage', @_);
    return $self->caller->do_call($self, $call_object);
  }
  sub GetSoftwareUpdates {
    my $self = shift;
    my $call_object = $self->new_with_coercions('Paws::Snowball::GetSoftwareUpdates', @_);
    return $self->caller->do_call($self, $call_object);
  }
  sub ListClusterJobs {
    my $self = shift;
    my $call_object = $self->new_with_coercions('Paws::Snowball::ListClusterJobs', @_);
    return $self->caller->do_call($self, $call_object);
  }
  sub ListClusters {
    my $self = shift;
    my $call_object = $self->new_with_coercions('Paws::Snowball::ListClusters', @_);
    return $self->caller->do_call($self, $call_object);
  }
  sub ListCompatibleImages {
    my $self = shift;
    my $call_object = $self->new_with_coercions('Paws::Snowball::ListCompatibleImages', @_);
    return $self->caller->do_call($self, $call_object);
  }
  sub ListJobs {
    my $self = shift;
    my $call_object = $self->new_with_coercions('Paws::Snowball::ListJobs', @_);
    return $self->caller->do_call($self, $call_object);
  }
  sub ListLongTermPricing {
    my $self = shift;
    my $call_object = $self->new_with_coercions('Paws::Snowball::ListLongTermPricing', @_);
    return $self->caller->do_call($self, $call_object);
  }
  sub UpdateCluster {
    my $self = shift;
    my $call_object = $self->new_with_coercions('Paws::Snowball::UpdateCluster', @_);
    return $self->caller->do_call($self, $call_object);
  }
  sub UpdateJob {
    my $self = shift;
    my $call_object = $self->new_with_coercions('Paws::Snowball::UpdateJob', @_);
    return $self->caller->do_call($self, $call_object);
  }
  sub UpdateJobShipmentState {
    my $self = shift;
    my $call_object = $self->new_with_coercions('Paws::Snowball::UpdateJobShipmentState', @_);
    return $self->caller->do_call($self, $call_object);
  }
  sub UpdateLongTermPricing {
    my $self = shift;
    my $call_object = $self->new_with_coercions('Paws::Snowball::UpdateLongTermPricing', @_);
    return $self->caller->do_call($self, $call_object);
  }
  
  sub DescribeAllAddresses {
    my $self = shift;

    my $callback = shift @_ if (ref($_[0]) eq 'CODE');
    my $result = $self->DescribeAddresses(@_);
    my $next_result = $result;

    if (not defined $callback) {
      while ($next_result->NextToken) {
        $next_result = $self->DescribeAddresses(@_, NextToken => $next_result->NextToken);
        push @{ $result->Addresses }, @{ $next_result->Addresses };
      }
      return $result;
    } else {
      while ($result->NextToken) {
        $callback->($_ => 'Addresses') foreach (@{ $result->Addresses });
        $result = $self->DescribeAddresses(@_, NextToken => $result->NextToken);
      }
      $callback->($_ => 'Addresses') foreach (@{ $result->Addresses });
    }

    return undef
  }
  sub ListAllClusterJobs {
    my $self = shift;

    my $callback = shift @_ if (ref($_[0]) eq 'CODE');
    my $result = $self->ListClusterJobs(@_);
    my $next_result = $result;

    if (not defined $callback) {
      while ($next_result->NextToken) {
        $next_result = $self->ListClusterJobs(@_, NextToken => $next_result->NextToken);
        push @{ $result->JobListEntries }, @{ $next_result->JobListEntries };
      }
      return $result;
    } else {
      while ($result->NextToken) {
        $callback->($_ => 'JobListEntries') foreach (@{ $result->JobListEntries });
        $result = $self->ListClusterJobs(@_, NextToken => $result->NextToken);
      }
      $callback->($_ => 'JobListEntries') foreach (@{ $result->JobListEntries });
    }

    return undef
  }
  sub ListAllClusters {
    my $self = shift;

    my $callback = shift @_ if (ref($_[0]) eq 'CODE');
    my $result = $self->ListClusters(@_);
    my $next_result = $result;

    if (not defined $callback) {
      while ($next_result->NextToken) {
        $next_result = $self->ListClusters(@_, NextToken => $next_result->NextToken);
        push @{ $result->ClusterListEntries }, @{ $next_result->ClusterListEntries };
      }
      return $result;
    } else {
      while ($result->NextToken) {
        $callback->($_ => 'ClusterListEntries') foreach (@{ $result->ClusterListEntries });
        $result = $self->ListClusters(@_, NextToken => $result->NextToken);
      }
      $callback->($_ => 'ClusterListEntries') foreach (@{ $result->ClusterListEntries });
    }

    return undef
  }
  sub ListAllCompatibleImages {
    my $self = shift;

    my $callback = shift @_ if (ref($_[0]) eq 'CODE');
    my $result = $self->ListCompatibleImages(@_);
    my $next_result = $result;

    if (not defined $callback) {
      while ($next_result->NextToken) {
        $next_result = $self->ListCompatibleImages(@_, NextToken => $next_result->NextToken);
        push @{ $result->CompatibleImages }, @{ $next_result->CompatibleImages };
      }
      return $result;
    } else {
      while ($result->NextToken) {
        $callback->($_ => 'CompatibleImages') foreach (@{ $result->CompatibleImages });
        $result = $self->ListCompatibleImages(@_, NextToken => $result->NextToken);
      }
      $callback->($_ => 'CompatibleImages') foreach (@{ $result->CompatibleImages });
    }

    return undef
  }
  sub ListAllJobs {
    my $self = shift;

    my $callback = shift @_ if (ref($_[0]) eq 'CODE');
    my $result = $self->ListJobs(@_);
    my $next_result = $result;

    if (not defined $callback) {
      while ($next_result->NextToken) {
        $next_result = $self->ListJobs(@_, NextToken => $next_result->NextToken);
        push @{ $result->JobListEntries }, @{ $next_result->JobListEntries };
      }
      return $result;
    } else {
      while ($result->NextToken) {
        $callback->($_ => 'JobListEntries') foreach (@{ $result->JobListEntries });
        $result = $self->ListJobs(@_, NextToken => $result->NextToken);
      }
      $callback->($_ => 'JobListEntries') foreach (@{ $result->JobListEntries });
    }

    return undef
  }


  sub operations { qw/CancelCluster CancelJob CreateAddress CreateCluster CreateJob CreateLongTermPricing CreateReturnShippingLabel DescribeAddress DescribeAddresses DescribeCluster DescribeJob DescribeReturnShippingLabel GetJobManifest GetJobUnlockCode GetSnowballUsage GetSoftwareUpdates ListClusterJobs ListClusters ListCompatibleImages ListJobs ListLongTermPricing UpdateCluster UpdateJob UpdateJobShipmentState UpdateLongTermPricing / }

1;

### main pod documentation begin ###

=head1 NAME

Paws::Snowball - Perl Interface to AWS Amazon Import/Export Snowball

=head1 SYNOPSIS

  use Paws;

  my $obj = Paws->service('Snowball');
  my $res = $obj->Method(
    Arg1 => $val1,
    Arg2 => [ 'V1', 'V2' ],
    # if Arg3 is an object, the HashRef will be used as arguments to the constructor
    # of the arguments type
    Arg3 => { Att1 => 'Val1' },
    # if Arg4 is an array of objects, the HashRefs will be passed as arguments to
    # the constructor of the arguments type
    Arg4 => [ { Att1 => 'Val1'  }, { Att1 => 'Val2' } ],
  );

=head1 DESCRIPTION

AWS Snow Family is a petabyte-scale data transport solution that uses
secure devices to transfer large amounts of data between your
on-premises data centers and Amazon Simple Storage Service (Amazon S3).
The Snow commands described here provide access to the same
functionality that is available in the AWS Snow Family Management
Console, which enables you to create and manage jobs for a Snow device.
To transfer data locally with a Snow device, you'll need to use the
Snowball Edge client or the Amazon S3 API Interface for Snowball or AWS
OpsHub for Snow Family. For more information, see the User Guide
(https://docs.aws.amazon.com/AWSImportExport/latest/ug/api-reference.html).

For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/snowball-2016-06-30>


=head1 METHODS

=head2 CancelCluster

=over

=item ClusterId => Str


=back

Each argument is described in detail in: L<Paws::Snowball::CancelCluster>

Returns: a L<Paws::Snowball::CancelClusterResult> instance

Cancels a cluster job. You can only cancel a cluster job while it's in
the C<AwaitingQuorum> status. You'll have at least an hour after
creating a cluster job to cancel it.


=head2 CancelJob

=over

=item JobId => Str


=back

Each argument is described in detail in: L<Paws::Snowball::CancelJob>

Returns: a L<Paws::Snowball::CancelJobResult> instance

Cancels the specified job. You can only cancel a job before its
C<JobState> value changes to C<PreparingAppliance>. Requesting the
C<ListJobs> or C<DescribeJob> action returns a job's C<JobState> as
part of the response element data returned.


=head2 CreateAddress

=over

=item Address => L<Paws::Snowball::Address>


=back

Each argument is described in detail in: L<Paws::Snowball::CreateAddress>

Returns: a L<Paws::Snowball::CreateAddressResult> instance

Creates an address for a Snow device to be shipped to. In most regions,
addresses are validated at the time of creation. The address you
provide must be located within the serviceable area of your region. If
the address is invalid or unsupported, then an exception is thrown.


=head2 CreateCluster

=over

=item AddressId => Str

=item JobType => Str

=item Resources => L<Paws::Snowball::JobResource>

=item RoleARN => Str

=item ShippingOption => Str

=item SnowballType => Str

=item [Description => Str]

=item [ForwardingAddressId => Str]

=item [KmsKeyARN => Str]

=item [Notification => L<Paws::Snowball::Notification>]

=item [OnDeviceServiceConfiguration => L<Paws::Snowball::OnDeviceServiceConfiguration>]

=item [RemoteManagement => Str]

=item [TaxDocuments => L<Paws::Snowball::TaxDocuments>]


=back

Each argument is described in detail in: L<Paws::Snowball::CreateCluster>

Returns: a L<Paws::Snowball::CreateClusterResult> instance

Creates an empty cluster. Each cluster supports five nodes. You use the
CreateJob action separately to create the jobs for each of these nodes.
The cluster does not ship until these five node jobs have been created.


=head2 CreateJob

=over

=item [AddressId => Str]

=item [ClusterId => Str]

=item [Description => Str]

=item [DeviceConfiguration => L<Paws::Snowball::DeviceConfiguration>]

=item [ForwardingAddressId => Str]

=item [JobType => Str]

=item [KmsKeyARN => Str]

=item [LongTermPricingId => Str]

=item [Notification => L<Paws::Snowball::Notification>]

=item [OnDeviceServiceConfiguration => L<Paws::Snowball::OnDeviceServiceConfiguration>]

=item [RemoteManagement => Str]

=item [Resources => L<Paws::Snowball::JobResource>]

=item [RoleARN => Str]

=item [ShippingOption => Str]

=item [SnowballCapacityPreference => Str]

=item [SnowballType => Str]

=item [TaxDocuments => L<Paws::Snowball::TaxDocuments>]


=back

Each argument is described in detail in: L<Paws::Snowball::CreateJob>

Returns: a L<Paws::Snowball::CreateJobResult> instance

Creates a job to import or export data between Amazon S3 and your
on-premises data center. Your AWS account must have the right trust
policies and permissions in place to create a job for a Snow device. If
you're creating a job for a node in a cluster, you only need to provide
the C<clusterId> value; the other job attributes are inherited from the
cluster.

Only the Snowball; Edge device type is supported when ordering
clustered jobs.

The device capacity is optional.

Availability of device types differ by AWS Region. For more information
about Region availability, see AWS Regional Services
(https://aws.amazon.com/about-aws/global-infrastructure/regional-product-services/?p=ngi&loc=4).

B<AWS Snow Family device types and their capacities.>

=over

=item *

Snow Family device type: B<SNC1_SSD>

=over

=item *

Capacity: T14

=item *

Description: Snowcone

=back

=item *

Snow Family device type: B<SNC1_HDD>

=over

=item *

Capacity: T8

=item *

Description: Snowcone

=back

=item *

Device type: B<EDGE_S>

=over

=item *

Capacity: T98

=item *

Description: Snowball Edge Storage Optimized for data transfer only

=back

=item *

Device type: B<EDGE_CG>

=over

=item *

Capacity: T42

=item *

Description: Snowball Edge Compute Optimized with GPU

=back

=item *

Device type: B<EDGE_C>

=over

=item *

Capacity: T42

=item *

Description: Snowball Edge Compute Optimized without GPU

=back

=item *

Device type: B<EDGE>

=over

=item *

Capacity: T100

=item *

Description: Snowball Edge Storage Optimized with EC2 Compute

=back

=item *

Device type: B<STANDARD>

=over

=item *

Capacity: T50

=item *

Description: Original Snowball device

This device is only available in the Ningxia, Beijing, and Singapore
AWS Regions.

=back

=item *

Device type: B<STANDARD>

=over

=item *

Capacity: T80

=item *

Description: Original Snowball device

This device is only available in the Ningxia, Beijing, and Singapore
AWS Regions.

=back

=back



=head2 CreateLongTermPricing

=over

=item LongTermPricingType => Str

=item [IsLongTermPricingAutoRenew => Bool]

=item [SnowballType => Str]


=back

Each argument is described in detail in: L<Paws::Snowball::CreateLongTermPricing>

Returns: a L<Paws::Snowball::CreateLongTermPricingResult> instance

Creates a job with the long-term usage option for a device. The
long-term usage is a 1-year or 3-year long-term pricing type for the
device. You are billed upfront, and AWS provides discounts for
long-term pricing.


=head2 CreateReturnShippingLabel

=over

=item JobId => Str

=item [ShippingOption => Str]


=back

Each argument is described in detail in: L<Paws::Snowball::CreateReturnShippingLabel>

Returns: a L<Paws::Snowball::CreateReturnShippingLabelResult> instance

Creates a shipping label that will be used to return the Snow device to
AWS.


=head2 DescribeAddress

=over

=item AddressId => Str


=back

Each argument is described in detail in: L<Paws::Snowball::DescribeAddress>

Returns: a L<Paws::Snowball::DescribeAddressResult> instance

Takes an C<AddressId> and returns specific details about that address
in the form of an C<Address> object.


=head2 DescribeAddresses

=over

=item [MaxResults => Int]

=item [NextToken => Str]


=back

Each argument is described in detail in: L<Paws::Snowball::DescribeAddresses>

Returns: a L<Paws::Snowball::DescribeAddressesResult> instance

Returns a specified number of C<ADDRESS> objects. Calling this API in
one of the US regions will return addresses from the list of all
addresses associated with this account in all US regions.


=head2 DescribeCluster

=over

=item ClusterId => Str


=back

Each argument is described in detail in: L<Paws::Snowball::DescribeCluster>

Returns: a L<Paws::Snowball::DescribeClusterResult> instance

Returns information about a specific cluster including shipping
information, cluster status, and other important metadata.


=head2 DescribeJob

=over

=item JobId => Str


=back

Each argument is described in detail in: L<Paws::Snowball::DescribeJob>

Returns: a L<Paws::Snowball::DescribeJobResult> instance

Returns information about a specific job including shipping
information, job status, and other important metadata.


=head2 DescribeReturnShippingLabel

=over

=item JobId => Str


=back

Each argument is described in detail in: L<Paws::Snowball::DescribeReturnShippingLabel>

Returns: a L<Paws::Snowball::DescribeReturnShippingLabelResult> instance

Information on the shipping label of a Snow device that is being
returned to AWS.


=head2 GetJobManifest

=over

=item JobId => Str


=back

Each argument is described in detail in: L<Paws::Snowball::GetJobManifest>

Returns: a L<Paws::Snowball::GetJobManifestResult> instance

Returns a link to an Amazon S3 presigned URL for the manifest file
associated with the specified C<JobId> value. You can access the
manifest file for up to 60 minutes after this request has been made. To
access the manifest file after 60 minutes have passed, you'll have to
make another call to the C<GetJobManifest> action.

The manifest is an encrypted file that you can download after your job
enters the C<WithCustomer> status. The manifest is decrypted by using
the C<UnlockCode> code value, when you pass both values to the Snow
device through the Snowball client when the client is started for the
first time.

As a best practice, we recommend that you don't save a copy of an
C<UnlockCode> value in the same location as the manifest file for that
job. Saving these separately helps prevent unauthorized parties from
gaining access to the Snow device associated with that job.

The credentials of a given job, including its manifest file and unlock
code, expire 360 days after the job is created.


=head2 GetJobUnlockCode

=over

=item JobId => Str


=back

Each argument is described in detail in: L<Paws::Snowball::GetJobUnlockCode>

Returns: a L<Paws::Snowball::GetJobUnlockCodeResult> instance

Returns the C<UnlockCode> code value for the specified job. A
particular C<UnlockCode> value can be accessed for up to 360 days after
the associated job has been created.

The C<UnlockCode> value is a 29-character code with 25 alphanumeric
characters and 4 hyphens. This code is used to decrypt the manifest
file when it is passed along with the manifest to the Snow device
through the Snowball client when the client is started for the first
time.

As a best practice, we recommend that you don't save a copy of the
C<UnlockCode> in the same location as the manifest file for that job.
Saving these separately helps prevent unauthorized parties from gaining
access to the Snow device associated with that job.


=head2 GetSnowballUsage






Each argument is described in detail in: L<Paws::Snowball::GetSnowballUsage>

Returns: a L<Paws::Snowball::GetSnowballUsageResult> instance

Returns information about the Snow Family service limit for your
account, and also the number of Snow devices your account has in use.

The default service limit for the number of Snow devices that you can
have at one time is 1. If you want to increase your service limit,
contact AWS Support.


=head2 GetSoftwareUpdates

=over

=item JobId => Str


=back

Each argument is described in detail in: L<Paws::Snowball::GetSoftwareUpdates>

Returns: a L<Paws::Snowball::GetSoftwareUpdatesResult> instance

Returns an Amazon S3 presigned URL for an update file associated with a
specified C<JobId>.


=head2 ListClusterJobs

=over

=item ClusterId => Str

=item [MaxResults => Int]

=item [NextToken => Str]


=back

Each argument is described in detail in: L<Paws::Snowball::ListClusterJobs>

Returns: a L<Paws::Snowball::ListClusterJobsResult> instance

Returns an array of C<JobListEntry> objects of the specified length.
Each C<JobListEntry> object is for a job in the specified cluster and
contains a job's state, a job's ID, and other information.


=head2 ListClusters

=over

=item [MaxResults => Int]

=item [NextToken => Str]


=back

Each argument is described in detail in: L<Paws::Snowball::ListClusters>

Returns: a L<Paws::Snowball::ListClustersResult> instance

Returns an array of C<ClusterListEntry> objects of the specified
length. Each C<ClusterListEntry> object contains a cluster's state, a
cluster's ID, and other important status information.


=head2 ListCompatibleImages

=over

=item [MaxResults => Int]

=item [NextToken => Str]


=back

Each argument is described in detail in: L<Paws::Snowball::ListCompatibleImages>

Returns: a L<Paws::Snowball::ListCompatibleImagesResult> instance

This action returns a list of the different Amazon EC2 Amazon Machine
Images (AMIs) that are owned by your AWS account that would be
supported for use on a Snow device. Currently, supported AMIs are based
on the CentOS 7 (x86_64) - with Updates HVM, Ubuntu Server 14.04 LTS
(HVM), and Ubuntu 16.04 LTS - Xenial (HVM) images, available on the AWS
Marketplace.


=head2 ListJobs

=over

=item [MaxResults => Int]

=item [NextToken => Str]


=back

Each argument is described in detail in: L<Paws::Snowball::ListJobs>

Returns: a L<Paws::Snowball::ListJobsResult> instance

Returns an array of C<JobListEntry> objects of the specified length.
Each C<JobListEntry> object contains a job's state, a job's ID, and a
value that indicates whether the job is a job part, in the case of
export jobs. Calling this API action in one of the US regions will
return jobs from the list of all jobs associated with this account in
all US regions.


=head2 ListLongTermPricing

=over

=item [MaxResults => Int]

=item [NextToken => Str]


=back

Each argument is described in detail in: L<Paws::Snowball::ListLongTermPricing>

Returns: a L<Paws::Snowball::ListLongTermPricingResult> instance

Lists all long-term pricing types.


=head2 UpdateCluster

=over

=item ClusterId => Str

=item [AddressId => Str]

=item [Description => Str]

=item [ForwardingAddressId => Str]

=item [Notification => L<Paws::Snowball::Notification>]

=item [OnDeviceServiceConfiguration => L<Paws::Snowball::OnDeviceServiceConfiguration>]

=item [Resources => L<Paws::Snowball::JobResource>]

=item [RoleARN => Str]

=item [ShippingOption => Str]


=back

Each argument is described in detail in: L<Paws::Snowball::UpdateCluster>

Returns: a L<Paws::Snowball::UpdateClusterResult> instance

While a cluster's C<ClusterState> value is in the C<AwaitingQuorum>
state, you can update some of the information associated with a
cluster. Once the cluster changes to a different job state, usually 60
minutes after the cluster being created, this action is no longer
available.


=head2 UpdateJob

=over

=item JobId => Str

=item [AddressId => Str]

=item [Description => Str]

=item [ForwardingAddressId => Str]

=item [Notification => L<Paws::Snowball::Notification>]

=item [OnDeviceServiceConfiguration => L<Paws::Snowball::OnDeviceServiceConfiguration>]

=item [Resources => L<Paws::Snowball::JobResource>]

=item [RoleARN => Str]

=item [ShippingOption => Str]

=item [SnowballCapacityPreference => Str]


=back

Each argument is described in detail in: L<Paws::Snowball::UpdateJob>

Returns: a L<Paws::Snowball::UpdateJobResult> instance

While a job's C<JobState> value is C<New>, you can update some of the
information associated with a job. Once the job changes to a different
job state, usually within 60 minutes of the job being created, this
action is no longer available.


=head2 UpdateJobShipmentState

=over

=item JobId => Str

=item ShipmentState => Str


=back

Each argument is described in detail in: L<Paws::Snowball::UpdateJobShipmentState>

Returns: a L<Paws::Snowball::UpdateJobShipmentStateResult> instance

Updates the state when a shipment state changes to a different state.


=head2 UpdateLongTermPricing

=over

=item LongTermPricingId => Str

=item [IsLongTermPricingAutoRenew => Bool]

=item [ReplacementJob => Str]


=back

Each argument is described in detail in: L<Paws::Snowball::UpdateLongTermPricing>

Returns: a L<Paws::Snowball::UpdateLongTermPricingResult> instance

Updates the long-term pricing type.




=head1 PAGINATORS

Paginator methods are helpers that repetively call methods that return partial results

=head2 DescribeAllAddresses(sub { },[MaxResults => Int, NextToken => Str])

=head2 DescribeAllAddresses([MaxResults => Int, NextToken => Str])


If passed a sub as first parameter, it will call the sub for each element found in :

 - Addresses, passing the object as the first parameter, and the string 'Addresses' as the second parameter 

If not, it will return a a L<Paws::Snowball::DescribeAddressesResult> instance with all the C<param>s;  from all the responses. Please take into account that this mode can potentially consume vasts ammounts of memory.


=head2 ListAllClusterJobs(sub { },ClusterId => Str, [MaxResults => Int, NextToken => Str])

=head2 ListAllClusterJobs(ClusterId => Str, [MaxResults => Int, NextToken => Str])


If passed a sub as first parameter, it will call the sub for each element found in :

 - JobListEntries, passing the object as the first parameter, and the string 'JobListEntries' as the second parameter 

If not, it will return a a L<Paws::Snowball::ListClusterJobsResult> instance with all the C<param>s;  from all the responses. Please take into account that this mode can potentially consume vasts ammounts of memory.


=head2 ListAllClusters(sub { },[MaxResults => Int, NextToken => Str])

=head2 ListAllClusters([MaxResults => Int, NextToken => Str])


If passed a sub as first parameter, it will call the sub for each element found in :

 - ClusterListEntries, passing the object as the first parameter, and the string 'ClusterListEntries' as the second parameter 

If not, it will return a a L<Paws::Snowball::ListClustersResult> instance with all the C<param>s;  from all the responses. Please take into account that this mode can potentially consume vasts ammounts of memory.


=head2 ListAllCompatibleImages(sub { },[MaxResults => Int, NextToken => Str])

=head2 ListAllCompatibleImages([MaxResults => Int, NextToken => Str])


If passed a sub as first parameter, it will call the sub for each element found in :

 - CompatibleImages, passing the object as the first parameter, and the string 'CompatibleImages' as the second parameter 

If not, it will return a a L<Paws::Snowball::ListCompatibleImagesResult> instance with all the C<param>s;  from all the responses. Please take into account that this mode can potentially consume vasts ammounts of memory.


=head2 ListAllJobs(sub { },[MaxResults => Int, NextToken => Str])

=head2 ListAllJobs([MaxResults => Int, NextToken => Str])


If passed a sub as first parameter, it will call the sub for each element found in :

 - JobListEntries, passing the object as the first parameter, and the string 'JobListEntries' as the second parameter 

If not, it will return a a L<Paws::Snowball::ListJobsResult> instance with all the C<param>s;  from all the responses. Please take into account that this mode can potentially consume vasts ammounts of memory.





=head1 SEE ALSO

This service class forms part of L<Paws>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

