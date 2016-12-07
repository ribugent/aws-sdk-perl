
package Paws::ElasticBeanstalk::CreateApplicationVersion;
  use Moose;
  has ApplicationName => (is => 'ro', isa => 'Str', required => 1);
  has AutoCreateApplication => (is => 'ro', isa => 'Bool');
  has BuildConfiguration => (is => 'ro', isa => 'Paws::ElasticBeanstalk::BuildConfiguration');
  has Description => (is => 'ro', isa => 'Str');
  has Process => (is => 'ro', isa => 'Bool');
  has SourceBuildInformation => (is => 'ro', isa => 'Paws::ElasticBeanstalk::SourceBuildInformation');
  has SourceBundle => (is => 'ro', isa => 'Paws::ElasticBeanstalk::S3Location');
  has VersionLabel => (is => 'ro', isa => 'Str', required => 1);

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'CreateApplicationVersion');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::ElasticBeanstalk::ApplicationVersionDescriptionMessage');
  class_has _result_key => (isa => 'Str', is => 'ro', default => 'CreateApplicationVersionResult');
1;

### main pod documentation begin ###

=head1 NAME

Paws::ElasticBeanstalk::CreateApplicationVersion - Arguments for method CreateApplicationVersion on Paws::ElasticBeanstalk

=head1 DESCRIPTION

This class represents the parameters used for calling the method CreateApplicationVersion on the 
AWS Elastic Beanstalk service. Use the attributes of this class
as arguments to method CreateApplicationVersion.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to CreateApplicationVersion.

As an example:

  $service_obj->CreateApplicationVersion(Att1 => $value1, Att2 => $value2, ...);

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.

=head1 ATTRIBUTES


=head2 B<REQUIRED> ApplicationName => Str

The name of the application. If no application is found with this name,
and C<AutoCreateApplication> is C<false>, returns an
C<InvalidParameterValue> error.



=head2 AutoCreateApplication => Bool

Set to C<true> to create an application with the specified name if it
doesn't already exist.



=head2 BuildConfiguration => L<Paws::ElasticBeanstalk::BuildConfiguration>





=head2 Description => Str

Describes this version.



=head2 Process => Bool

Preprocesses and validates the environment manifest and configuration
files in the source bundle. Validating configuration files can identify
issues prior to deploying the application version to an environment.



=head2 SourceBuildInformation => L<Paws::ElasticBeanstalk::SourceBuildInformation>

Specify a commit in an AWS CodeCommit Git repository to use as the
source code for the application version.

Specify a commit in an AWS CodeCommit repository or a source bundle in
S3 (with C<SourceBundle>), but not both. If neither C<SourceBundle> nor
C<SourceBuildInformation> are provided, Elastic Beanstalk uses a sample
application.



=head2 SourceBundle => L<Paws::ElasticBeanstalk::S3Location>

The Amazon S3 bucket and key that identify the location of the source
bundle for this version.

Specify a source bundle in S3 or a commit in an AWS CodeCommit
repository (with C<SourceBuildInformation>), but not both. If neither
C<SourceBundle> nor C<SourceBuildInformation> are provided, Elastic
Beanstalk uses a sample application.



=head2 B<REQUIRED> VersionLabel => Str

A label identifying this version.

Constraint: Must be unique per application. If an application version
already exists with this label for the specified application, AWS
Elastic Beanstalk returns an C<InvalidParameterValue> error.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method CreateApplicationVersion in L<Paws::ElasticBeanstalk>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: https://github.com/pplu/aws-sdk-perl

Please report bugs to: https://github.com/pplu/aws-sdk-perl/issues

=cut

