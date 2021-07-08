# Generated by default/object.tt
package Paws::Kafka::CompatibleKafkaVersion;
  use Moose;
  has SourceVersion => (is => 'ro', isa => 'Str', request_name => 'sourceVersion', traits => ['NameInRequest']);
  has TargetVersions => (is => 'ro', isa => 'ArrayRef[Str|Undef]', request_name => 'targetVersions', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::Kafka::CompatibleKafkaVersion

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Kafka::CompatibleKafkaVersion object:

  $service_obj->Method(Att1 => { SourceVersion => $value, ..., TargetVersions => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Kafka::CompatibleKafkaVersion object:

  $result = $service_obj->Method(...);
  $result->Att1->SourceVersion

=head1 DESCRIPTION

Contains source Kafka versions and compatible target Kafka versions.

=head1 ATTRIBUTES


=head2 SourceVersion => Str

A Kafka version.


=head2 TargetVersions => ArrayRef[Str|Undef]

A list of Kafka versions.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Kafka>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

