# Generated by default/object.tt
package Paws::KinesisAnalyticsV2::ZeppelinApplicationConfiguration;
  use Moose;
  has CatalogConfiguration => (is => 'ro', isa => 'Paws::KinesisAnalyticsV2::CatalogConfiguration');
  has CustomArtifactsConfiguration => (is => 'ro', isa => 'ArrayRef[Paws::KinesisAnalyticsV2::CustomArtifactConfiguration]');
  has DeployAsApplicationConfiguration => (is => 'ro', isa => 'Paws::KinesisAnalyticsV2::DeployAsApplicationConfiguration');
  has MonitoringConfiguration => (is => 'ro', isa => 'Paws::KinesisAnalyticsV2::ZeppelinMonitoringConfiguration');

1;

### main pod documentation begin ###

=head1 NAME

Paws::KinesisAnalyticsV2::ZeppelinApplicationConfiguration

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::KinesisAnalyticsV2::ZeppelinApplicationConfiguration object:

  $service_obj->Method(Att1 => { CatalogConfiguration => $value, ..., MonitoringConfiguration => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::KinesisAnalyticsV2::ZeppelinApplicationConfiguration object:

  $result = $service_obj->Method(...);
  $result->Att1->CatalogConfiguration

=head1 DESCRIPTION

The configuration of a Kinesis Data Analytics Studio notebook.

=head1 ATTRIBUTES


=head2 CatalogConfiguration => L<Paws::KinesisAnalyticsV2::CatalogConfiguration>

The AWS Glue Data Catalog that you use in queries in a Kinesis Data
Analytics Studio notebook.


=head2 CustomArtifactsConfiguration => ArrayRef[L<Paws::KinesisAnalyticsV2::CustomArtifactConfiguration>]

Custom artifacts are dependency JARs and user-defined functions (UDF).


=head2 DeployAsApplicationConfiguration => L<Paws::KinesisAnalyticsV2::DeployAsApplicationConfiguration>

The information required to deploy a Kinesis Data Analytics Studio
notebook as an application with durable state..


=head2 MonitoringConfiguration => L<Paws::KinesisAnalyticsV2::ZeppelinMonitoringConfiguration>

The monitoring configuration of a Kinesis Data Analytics Studio
notebook.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::KinesisAnalyticsV2>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

