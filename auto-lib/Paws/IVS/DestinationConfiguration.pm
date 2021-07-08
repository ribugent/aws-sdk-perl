# Generated by default/object.tt
package Paws::IVS::DestinationConfiguration;
  use Moose;
  has S3 => (is => 'ro', isa => 'Paws::IVS::S3DestinationConfiguration', request_name => 's3', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::IVS::DestinationConfiguration

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::IVS::DestinationConfiguration object:

  $service_obj->Method(Att1 => { S3 => $value, ..., S3 => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::IVS::DestinationConfiguration object:

  $result = $service_obj->Method(...);
  $result->Att1->S3

=head1 DESCRIPTION

A complex type that describes a location where recorded videos will be
stored. Each member represents a type of destination configuration. For
recording, you define one and only one type of destination
configuration.

=head1 ATTRIBUTES


=head2 S3 => L<Paws::IVS::S3DestinationConfiguration>

An S3 destination configuration where recorded videos will be stored.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::IVS>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

