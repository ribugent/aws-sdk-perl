# Generated by default/object.tt
package Paws::DMS::RedshiftSettings;
  use Moose;
  has AcceptAnyDate => (is => 'ro', isa => 'Bool');
  has AfterConnectScript => (is => 'ro', isa => 'Str');
  has BucketFolder => (is => 'ro', isa => 'Str');
  has BucketName => (is => 'ro', isa => 'Str');
  has CaseSensitiveNames => (is => 'ro', isa => 'Bool');
  has CompUpdate => (is => 'ro', isa => 'Bool');
  has ConnectionTimeout => (is => 'ro', isa => 'Int');
  has DatabaseName => (is => 'ro', isa => 'Str');
  has DateFormat => (is => 'ro', isa => 'Str');
  has EmptyAsNull => (is => 'ro', isa => 'Bool');
  has EncryptionMode => (is => 'ro', isa => 'Str');
  has ExplicitIds => (is => 'ro', isa => 'Bool');
  has FileTransferUploadStreams => (is => 'ro', isa => 'Int');
  has LoadTimeout => (is => 'ro', isa => 'Int');
  has MaxFileSize => (is => 'ro', isa => 'Int');
  has Password => (is => 'ro', isa => 'Str');
  has Port => (is => 'ro', isa => 'Int');
  has RemoveQuotes => (is => 'ro', isa => 'Bool');
  has ReplaceChars => (is => 'ro', isa => 'Str');
  has ReplaceInvalidChars => (is => 'ro', isa => 'Str');
  has SecretsManagerAccessRoleArn => (is => 'ro', isa => 'Str');
  has SecretsManagerSecretId => (is => 'ro', isa => 'Str');
  has ServerName => (is => 'ro', isa => 'Str');
  has ServerSideEncryptionKmsKeyId => (is => 'ro', isa => 'Str');
  has ServiceAccessRoleArn => (is => 'ro', isa => 'Str');
  has TimeFormat => (is => 'ro', isa => 'Str');
  has TrimBlanks => (is => 'ro', isa => 'Bool');
  has TruncateColumns => (is => 'ro', isa => 'Bool');
  has Username => (is => 'ro', isa => 'Str');
  has WriteBufferSize => (is => 'ro', isa => 'Int');

1;

### main pod documentation begin ###

=head1 NAME

Paws::DMS::RedshiftSettings

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::DMS::RedshiftSettings object:

  $service_obj->Method(Att1 => { AcceptAnyDate => $value, ..., WriteBufferSize => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::DMS::RedshiftSettings object:

  $result = $service_obj->Method(...);
  $result->Att1->AcceptAnyDate

=head1 DESCRIPTION

Provides information that defines an Amazon Redshift endpoint.

=head1 ATTRIBUTES


=head2 AcceptAnyDate => Bool

A value that indicates to allow any date format, including invalid
formats such as 00/00/00 00:00:00, to be loaded without generating an
error. You can choose C<true> or C<false> (the default).

This parameter applies only to TIMESTAMP and DATE columns. Always use
ACCEPTANYDATE with the DATEFORMAT parameter. If the date format for the
data doesn't match the DATEFORMAT specification, Amazon Redshift
inserts a NULL value into that field.


=head2 AfterConnectScript => Str

Code to run after connecting. This parameter should contain the code
itself, not the name of a file containing the code.


=head2 BucketFolder => Str

An S3 folder where the comma-separated-value (.csv) files are stored
before being uploaded to the target Redshift cluster.

For full load mode, AWS DMS converts source records into .csv files and
loads them to the I<BucketFolder/TableID> path. AWS DMS uses the
Redshift C<COPY> command to upload the .csv files to the target table.
The files are deleted once the C<COPY> operation has finished. For more
information, see COPY
(https://docs.aws.amazon.com/redshift/latest/dg/r_COPY.html) in the
I<Amazon Redshift Database Developer Guide>.

For change-data-capture (CDC) mode, AWS DMS creates a I<NetChanges>
table, and loads the .csv files to this
I<BucketFolder/NetChangesTableID> path.


=head2 BucketName => Str

The name of the intermediate S3 bucket used to store .csv files before
uploading data to Redshift.


=head2 CaseSensitiveNames => Bool

If Amazon Redshift is configured to support case sensitive schema
names, set C<CaseSensitiveNames> to C<true>. The default is C<false>.


=head2 CompUpdate => Bool

If you set C<CompUpdate> to C<true> Amazon Redshift applies automatic
compression if the table is empty. This applies even if the table
columns already have encodings other than C<RAW>. If you set
C<CompUpdate> to C<false>, automatic compression is disabled and
existing column encodings aren't changed. The default is C<true>.


=head2 ConnectionTimeout => Int

A value that sets the amount of time to wait (in milliseconds) before
timing out, beginning from when you initially establish a connection.


=head2 DatabaseName => Str

The name of the Amazon Redshift data warehouse (service) that you are
working with.


=head2 DateFormat => Str

The date format that you are using. Valid values are C<auto>
(case-sensitive), your date format string enclosed in quotes, or NULL.
If this parameter is left unset (NULL), it defaults to a format of
'YYYY-MM-DD'. Using C<auto> recognizes most strings, even some that
aren't supported when you use a date format string.

If your date and time values use formats different from each other, set
this to C<auto>.


=head2 EmptyAsNull => Bool

A value that specifies whether AWS DMS should migrate empty CHAR and
VARCHAR fields as NULL. A value of C<true> sets empty CHAR and VARCHAR
fields to null. The default is C<false>.


=head2 EncryptionMode => Str

The type of server-side encryption that you want to use for your data.
This encryption type is part of the endpoint settings or the extra
connections attributes for Amazon S3. You can choose either C<SSE_S3>
(the default) or C<SSE_KMS>.

For the C<ModifyEndpoint> operation, you can change the existing value
of the C<EncryptionMode> parameter from C<SSE_KMS> to C<SSE_S3>. But
you canE<rsquo>t change the existing value from C<SSE_S3> to
C<SSE_KMS>.

To use C<SSE_S3>, create an AWS Identity and Access Management (IAM)
role with a policy that allows C<"arn:aws:s3:::*"> to use the following
actions: C<"s3:PutObject", "s3:ListBucket">


=head2 ExplicitIds => Bool

This setting is only valid for a full-load migration task. Set
C<ExplicitIds> to C<true> to have tables with C<IDENTITY> columns
override their auto-generated values with explicit values loaded from
the source data files used to populate the tables. The default is
C<false>.


=head2 FileTransferUploadStreams => Int

The number of threads used to upload a single file. This parameter
accepts a value from 1 through 64. It defaults to 10.

The number of parallel streams used to upload a single .csv file to an
S3 bucket using S3 Multipart Upload. For more information, see
Multipart upload overview
(https://docs.aws.amazon.com/AmazonS3/latest/dev/mpuoverview.html).

C<FileTransferUploadStreams> accepts a value from 1 through 64. It
defaults to 10.


=head2 LoadTimeout => Int

The amount of time to wait (in milliseconds) before timing out of
operations performed by AWS DMS on a Redshift cluster, such as Redshift
COPY, INSERT, DELETE, and UPDATE.


=head2 MaxFileSize => Int

The maximum size (in KB) of any .csv file used to load data on an S3
bucket and transfer data to Amazon Redshift. It defaults to 1048576KB
(1 GB).


=head2 Password => Str

The password for the user named in the C<username> property.


=head2 Port => Int

The port number for Amazon Redshift. The default value is 5439.


=head2 RemoveQuotes => Bool

A value that specifies to remove surrounding quotation marks from
strings in the incoming data. All characters within the quotation
marks, including delimiters, are retained. Choose C<true> to remove
quotation marks. The default is C<false>.


=head2 ReplaceChars => Str

A value that specifies to replaces the invalid characters specified in
C<ReplaceInvalidChars>, substituting the specified characters instead.
The default is C<"?">.


=head2 ReplaceInvalidChars => Str

A list of characters that you want to replace. Use with
C<ReplaceChars>.


=head2 SecretsManagerAccessRoleArn => Str

The full Amazon Resource Name (ARN) of the IAM role that specifies AWS
DMS as the trusted entity and grants the required permissions to access
the value in C<SecretsManagerSecret>. C<SecretsManagerSecret> has the
value of the AWS Secrets Manager secret that allows access to the
Amazon Redshift endpoint.

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
C<SecretsManagerSecret> that contains the Amazon Redshift endpoint
connection details.


=head2 ServerName => Str

The name of the Amazon Redshift cluster you are using.


=head2 ServerSideEncryptionKmsKeyId => Str

The AWS KMS key ID. If you are using C<SSE_KMS> for the
C<EncryptionMode>, provide this key ID. The key that you use needs an
attached policy that enables IAM user permissions and allows use of the
key.


=head2 ServiceAccessRoleArn => Str

The Amazon Resource Name (ARN) of the IAM role that has access to the
Amazon Redshift service.


=head2 TimeFormat => Str

The time format that you want to use. Valid values are C<auto>
(case-sensitive), C<'timeformat_string'>, C<'epochsecs'>, or
C<'epochmillisecs'>. It defaults to 10. Using C<auto> recognizes most
strings, even some that aren't supported when you use a time format
string.

If your date and time values use formats different from each other, set
this parameter to C<auto>.


=head2 TrimBlanks => Bool

A value that specifies to remove the trailing white space characters
from a VARCHAR string. This parameter applies only to columns with a
VARCHAR data type. Choose C<true> to remove unneeded white space. The
default is C<false>.


=head2 TruncateColumns => Bool

A value that specifies to truncate data in columns to the appropriate
number of characters, so that the data fits in the column. This
parameter applies only to columns with a VARCHAR or CHAR data type, and
rows with a size of 4 MB or less. Choose C<true> to truncate data. The
default is C<false>.


=head2 Username => Str

An Amazon Redshift user name for a registered user.


=head2 WriteBufferSize => Int

The size (in KB) of the in-memory file write buffer used when
generating .csv files on the local disk at the DMS replication
instance. The default value is 1000 (buffer size is 1000KB).



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::DMS>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

