# Generated by default/object.tt
package Paws::LookoutEquipment::IngestionS3InputConfiguration;
  use Moose;
  has Bucket => (is => 'ro', isa => 'Str', required => 1);
  has Prefix => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::LookoutEquipment::IngestionS3InputConfiguration

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::LookoutEquipment::IngestionS3InputConfiguration object:

  $service_obj->Method(Att1 => { Bucket => $value, ..., Prefix => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::LookoutEquipment::IngestionS3InputConfiguration object:

  $result = $service_obj->Method(...);
  $result->Att1->Bucket

=head1 DESCRIPTION

Specifies S3 configuration information for the input data for the data
ingestion job.

=head1 ATTRIBUTES


=head2 B<REQUIRED> Bucket => Str

The name of the S3 bucket used for the input data for the data
ingestion.


=head2 Prefix => Str

The prefix for the S3 location being used for the input data for the
data ingestion.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::LookoutEquipment>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

