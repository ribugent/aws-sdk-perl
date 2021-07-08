# Generated by default/object.tt
package Paws::IoTAnalytics::FileFormatConfiguration;
  use Moose;
  has JsonConfiguration => (is => 'ro', isa => 'Paws::IoTAnalytics::JsonConfiguration', request_name => 'jsonConfiguration', traits => ['NameInRequest']);
  has ParquetConfiguration => (is => 'ro', isa => 'Paws::IoTAnalytics::ParquetConfiguration', request_name => 'parquetConfiguration', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::IoTAnalytics::FileFormatConfiguration

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::IoTAnalytics::FileFormatConfiguration object:

  $service_obj->Method(Att1 => { JsonConfiguration => $value, ..., ParquetConfiguration => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::IoTAnalytics::FileFormatConfiguration object:

  $result = $service_obj->Method(...);
  $result->Att1->JsonConfiguration

=head1 DESCRIPTION

Contains the configuration information of file formats. AWS IoT
Analytics data stores support JSON and Parquet
(https://parquet.apache.org/).

The default file format is JSON. You can specify only one format.

You can't change the file format after you create the data store.

=head1 ATTRIBUTES


=head2 JsonConfiguration => L<Paws::IoTAnalytics::JsonConfiguration>

Contains the configuration information of the JSON format.


=head2 ParquetConfiguration => L<Paws::IoTAnalytics::ParquetConfiguration>

Contains the configuration information of the Parquet format.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::IoTAnalytics>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

