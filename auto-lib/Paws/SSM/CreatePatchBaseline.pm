
package Paws::SSM::CreatePatchBaseline;
  use Moose;
  has ApprovalRules => (is => 'ro', isa => 'Paws::SSM::PatchRuleGroup');
  has ApprovedPatches => (is => 'ro', isa => 'ArrayRef[Str|Undef]');
  has ApprovedPatchesComplianceLevel => (is => 'ro', isa => 'Str');
  has ApprovedPatchesEnableNonSecurity => (is => 'ro', isa => 'Bool');
  has ClientToken => (is => 'ro', isa => 'Str');
  has Description => (is => 'ro', isa => 'Str');
  has GlobalFilters => (is => 'ro', isa => 'Paws::SSM::PatchFilterGroup');
  has Name => (is => 'ro', isa => 'Str', required => 1);
  has OperatingSystem => (is => 'ro', isa => 'Str');
  has RejectedPatches => (is => 'ro', isa => 'ArrayRef[Str|Undef]');
  has RejectedPatchesAction => (is => 'ro', isa => 'Str');
  has Sources => (is => 'ro', isa => 'ArrayRef[Paws::SSM::PatchSource]');
  has Tags => (is => 'ro', isa => 'ArrayRef[Paws::SSM::Tag]');

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'CreatePatchBaseline');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::SSM::CreatePatchBaselineResult');
  class_has _result_key => (isa => 'Str', is => 'ro');
1;

### main pod documentation begin ###

=head1 NAME

Paws::SSM::CreatePatchBaseline - Arguments for method CreatePatchBaseline on L<Paws::SSM>

=head1 DESCRIPTION

This class represents the parameters used for calling the method CreatePatchBaseline on the
L<Amazon Simple Systems Manager (SSM)|Paws::SSM> service. Use the attributes of this class
as arguments to method CreatePatchBaseline.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to CreatePatchBaseline.

=head1 SYNOPSIS

    my $ssm = Paws->service('SSM');
    my $CreatePatchBaselineResult = $ssm->CreatePatchBaseline(
      Name          => 'MyBaselineName',
      ApprovalRules => {
        PatchRules => [
          {
            PatchFilterGroup => {
              PatchFilters => [
                {
                  Key => 'ARCH'
                  , # values: ARCH, ADVISORY_ID, BUGZILLA_ID, PATCH_SET, PRODUCT, PRODUCT_FAMILY, CLASSIFICATION, CVE_ID, EPOCH, MSRC_SEVERITY, NAME, PATCH_ID, SECTION, PRIORITY, REPOSITORY, RELEASE, SEVERITY, SECURITY, VERSION
                  Values => [
                    'MyPatchFilterValue', ...    # min: 1, max: 64
                  ],    # min: 1, max: 20

                },
                ...
              ],    # max: 4

            },
            ApproveAfterDays => 1,        # max: 360; OPTIONAL
            ApproveUntilDate =>
              'MyPatchStringDateTime',    # min: 1, max: 10; OPTIONAL
            ComplianceLevel => 'CRITICAL'
            , # values: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL, UNSPECIFIED; OPTIONAL
            EnableNonSecurity => 1,    # OPTIONAL
          },
          ...
        ],    # max: 10

      },    # OPTIONAL
      ApprovedPatches => [
        'MyPatchId', ...    # min: 1, max: 100
      ],    # OPTIONAL
      ApprovedPatchesComplianceLevel   => 'CRITICAL',                 # OPTIONAL
      ApprovedPatchesEnableNonSecurity => 1,                          # OPTIONAL
      ClientToken                      => 'MyClientToken',            # OPTIONAL
      Description                      => 'MyBaselineDescription',    # OPTIONAL
      GlobalFilters                    => {
        PatchFilters => [
          {
            Key => 'ARCH'
            , # values: ARCH, ADVISORY_ID, BUGZILLA_ID, PATCH_SET, PRODUCT, PRODUCT_FAMILY, CLASSIFICATION, CVE_ID, EPOCH, MSRC_SEVERITY, NAME, PATCH_ID, SECTION, PRIORITY, REPOSITORY, RELEASE, SEVERITY, SECURITY, VERSION
            Values => [
              'MyPatchFilterValue', ...    # min: 1, max: 64
            ],    # min: 1, max: 20

          },
          ...
        ],    # max: 4

      },    # OPTIONAL
      OperatingSystem => 'WINDOWS',    # OPTIONAL
      RejectedPatches => [
        'MyPatchId', ...               # min: 1, max: 100
      ],    # OPTIONAL
      RejectedPatchesAction => 'ALLOW_AS_DEPENDENCY',    # OPTIONAL
      Sources               => [
        {
          Configuration => 'MyPatchSourceConfiguration',    # min: 1, max: 1024
          Name          => 'MyPatchSourceName',
          Products      => [
            'MyPatchSourceProduct', ...                     # min: 1, max: 128
          ],    # min: 1, max: 20

        },
        ...
      ],    # OPTIONAL
      Tags => [
        {
          Key   => 'MyTagKey',      # min: 1, max: 128
          Value => 'MyTagValue',    # min: 1, max: 256

        },
        ...
      ],    # OPTIONAL
    );

    # Results:
    my $BaselineId = $CreatePatchBaselineResult->BaselineId;

    # Returns a L<Paws::SSM::CreatePatchBaselineResult> object.

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/ssm/CreatePatchBaseline>

=head1 ATTRIBUTES


=head2 ApprovalRules => L<Paws::SSM::PatchRuleGroup>

A set of rules used to include patches in the baseline.



=head2 ApprovedPatches => ArrayRef[Str|Undef]

A list of explicitly approved patches for the baseline.

For information about accepted formats for lists of approved patches
and rejected patches, see About package name formats for approved and
rejected patch lists
(https://docs.aws.amazon.com/systems-manager/latest/userguide/patch-manager-approved-rejected-package-name-formats.html)
in the I<AWS Systems Manager User Guide>.



=head2 ApprovedPatchesComplianceLevel => Str

Defines the compliance level for approved patches. When an approved
patch is reported as missing, this value describes the severity of the
compliance violation. The default value is UNSPECIFIED.

Valid values are: C<"CRITICAL">, C<"HIGH">, C<"MEDIUM">, C<"LOW">, C<"INFORMATIONAL">, C<"UNSPECIFIED">

=head2 ApprovedPatchesEnableNonSecurity => Bool

Indicates whether the list of approved patches includes non-security
updates that should be applied to the instances. The default value is
'false'. Applies to Linux instances only.



=head2 ClientToken => Str

User-provided idempotency token.



=head2 Description => Str

A description of the patch baseline.



=head2 GlobalFilters => L<Paws::SSM::PatchFilterGroup>

A set of global filters used to include patches in the baseline.



=head2 B<REQUIRED> Name => Str

The name of the patch baseline.



=head2 OperatingSystem => Str

Defines the operating system the patch baseline applies to. The Default
value is WINDOWS.

Valid values are: C<"WINDOWS">, C<"AMAZON_LINUX">, C<"AMAZON_LINUX_2">, C<"UBUNTU">, C<"REDHAT_ENTERPRISE_LINUX">, C<"SUSE">, C<"CENTOS">, C<"ORACLE_LINUX">, C<"DEBIAN">, C<"MACOS">

=head2 RejectedPatches => ArrayRef[Str|Undef]

A list of explicitly rejected patches for the baseline.

For information about accepted formats for lists of approved patches
and rejected patches, see About package name formats for approved and
rejected patch lists
(https://docs.aws.amazon.com/systems-manager/latest/userguide/patch-manager-approved-rejected-package-name-formats.html)
in the I<AWS Systems Manager User Guide>.



=head2 RejectedPatchesAction => Str

The action for Patch Manager to take on patches included in the
RejectedPackages list.

=over

=item *

B<ALLOW_AS_DEPENDENCY>: A package in the Rejected patches list is
installed only if it is a dependency of another package. It is
considered compliant with the patch baseline, and its status is
reported as I<InstalledOther>. This is the default action if no option
is specified.

=item *

B<BLOCK>: Packages in the RejectedPatches list, and packages that
include them as dependencies, are not installed under any
circumstances. If a package was installed before it was added to the
Rejected patches list, it is considered non-compliant with the patch
baseline, and its status is reported as I<InstalledRejected>.

=back


Valid values are: C<"ALLOW_AS_DEPENDENCY">, C<"BLOCK">

=head2 Sources => ArrayRef[L<Paws::SSM::PatchSource>]

Information about the patches to use to update the instances, including
target operating systems and source repositories. Applies to Linux
instances only.



=head2 Tags => ArrayRef[L<Paws::SSM::Tag>]

Optional metadata that you assign to a resource. Tags enable you to
categorize a resource in different ways, such as by purpose, owner, or
environment. For example, you might want to tag a patch baseline to
identify the severity level of patches it specifies and the operating
system family it applies to. In this case, you could specify the
following key name/value pairs:

=over

=item *

C<Key=PatchSeverity,Value=Critical>

=item *

C<Key=OS,Value=Windows>

=back

To add tags to an existing patch baseline, use the AddTagsToResource
action.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method CreatePatchBaseline in L<Paws::SSM>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

