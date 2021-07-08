# Generated by default/object.tt
package Paws::IoTEventsData::EnableActionConfiguration;
  use Moose;
  has Note => (is => 'ro', isa => 'Str', request_name => 'note', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::IoTEventsData::EnableActionConfiguration

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::IoTEventsData::EnableActionConfiguration object:

  $service_obj->Method(Att1 => { Note => $value, ..., Note => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::IoTEventsData::EnableActionConfiguration object:

  $result = $service_obj->Method(...);
  $result->Att1->Note

=head1 DESCRIPTION

Contains the configuration information of an enable action.

=head1 ATTRIBUTES


=head2 Note => Str

The note that you can leave when you enable the alarm.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::IoTEventsData>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

