# Generated by default/object.tt
package Paws::Kafka::S3;
  use Moose;
  has Bucket => (is => 'ro', isa => 'Str', request_name => 'bucket', traits => ['NameInRequest']);
  has Enabled => (is => 'ro', isa => 'Bool', request_name => 'enabled', traits => ['NameInRequest'], required => 1);
  has Prefix => (is => 'ro', isa => 'Str', request_name => 'prefix', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::Kafka::S3

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Kafka::S3 object:

  $service_obj->Method(Att1 => { Bucket => $value, ..., Prefix => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Kafka::S3 object:

  $result = $service_obj->Method(...);
  $result->Att1->Bucket

=head1 DESCRIPTION

This class has no description

=head1 ATTRIBUTES


=head2 Bucket => Str




=head2 B<REQUIRED> Enabled => Bool




=head2 Prefix => Str





=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Kafka>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

